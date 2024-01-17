"""
References:
- Project 4: A TCP State Transition Program
  http://www.cs.uni.edu/~diesburg/courses/cs3470_fa19/projects/p4-tcp.html
  Accessed: 2023-10-25
"""
from enum import Enum
import logging
import time
from typing import List

from packets.ip import IPPacket
from packets.tcp import TCPPacket


logger = logging.getLogger(__name__)


class TCPOverUDPSocketError(Exception):
    """
    Catch all error for anything related to TCPOverUDPSocket.
    """


class TCPOverUDPSocket:
    class STATE(Enum):
        CLOSED = 1
        LISTEN = 2
        SYN_RCVD = 3
        SYN_SENT = 4
        ESTABLISHED = 5
        FIN_WAIT_1 = 6
        FIN_WAIT_2 = 7
        CLOSING = 8
        TIME_WAIT = 9
        CLOSE_WAIT = 10
        LAST_ACK = 11

    def __init__(
        self,
        nic,
        source_address: str,
        source_port: int,
        destination_address: str,
        destination_port: int,
        *_,
    ) -> None:
        self.nic = nic

        # The address from which packets will originate (ie. this socket).
        self.source_address = source_address
        self.source_port = source_port

        # The address to which packets will be sent.
        self.destination_address = destination_address
        self.destination_port = destination_port

        # TCP control fields.
        self.state = self.STATE.CLOSED
        self.sequence_number = 0
        self.acknowledgment_number = None

        # Packet queues.
        self.packet_in_queue: List[TCPPacket] = []
        self._packet_out_queue: List[tuple] = []

        # Data pulled from inbound packet queue.
        self._data_queue = bytearray()

    def start(self):
        self._handle_queue()

    def _handle_queue(self):
        while True:
            try:
                logger.debug(f'Length of in queue {len(self.packet_in_queue)}')
                packet = self.packet_in_queue.pop(0)
            except IndexError:
                # TODO: Use select instead of fast loop
                time.sleep(1)
                continue

            self._handle_packet(packet)

    def _handle_packet(self, p: TCPPacket):
        """
        Make a decision about what to do based contents of packet.
        """
        logger.info(f'Starting to handle {p}')

        # Packet should acknowledge what we have already sent.
        # TODO: Only handle if acknowledgment number is far behind. Many MTU?
        if p.acknowledgment_number < self.sequence_number:
            # TODO: Only send those that are missing.
            self._write_old_packets()
        elif p.acknowledgment_number == self.sequence_number:
            if self._packet_out_queue:
                # Remove from queue while data sent is less than p.acknowledgment_number.
                old_sequence_number, ip_packet = self._packet_out_queue[0]
                while p.acknowledgment_number >= old_sequence_number and self._packet_out_queue:
                    old_sequence_number, ip_packet = self._packet_out_queue.pop(0)

                # Put last packet back if it was popped to soon.
                if p.acknowledgment_number < old_sequence_number:
                    self._packet_out_queue.insert(0, (old_sequence_number, ip_packet))

        else:
            raise TCPOverUDPSocketError(f'Unexpected ack number {p.acknowledgment_number}')

        # Bootstrap acknowledgment number if this is the first packet handled by the socket.
        if self.acknowledgment_number is None:
            self.acknowledgment_number = p.sequence_number - 1

        # Before we can start ACKing more bytes, need to make sure that we are
        # starting from where we left off.
        if p.sequence_number != self.acknowledgment_number + 1:
            # Send an ack of our last byte.
            resp_p = self._get_tcp_packet()
            resp_p.ack = True
            self._write_packet(resp_p)
            return

        self.acknowledgment_number = p.sequence_number + len(p.bytes)

        # TODO: Write tests for packets being resent.

        resp_p = self._get_tcp_packet()

        if p.is_ack:
            self._data_queue.extend(p.data)

        if self.state == self.STATE.LISTEN:
            if not p.is_syn:
                # Not valid packet to receive while in LISTEN. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            # Send SYN/ACK
            resp_p.syn = True
            resp_p.ack = True
            self._write_packet(resp_p)
            self.state = self.STATE.SYN_RCVD
            return

        elif self.state == self.STATE.SYN_RCVD:
            if not (p.is_ack or p.is_syn_ack):
                # Not valid packet to receive while in SYN_RCVD. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            # Ignore case where we receive a SYN/ACK. That means there was a
            # concurrent attempt to start a connection.
            # We can rely on the next ACK from normal data flow to set the state.
            if p.is_syn_ack:
                # TODO: Test this.
                return

            # We've received an ACK. Connection is ESTABLISHED.
            self.state = self.STATE.ESTABLISHED
            return

        elif self.state == self.STATE.SYN_SENT:
            if not (p.is_syn_ack or p.is_syn):
                # Not valid packet to receive while in SYN_SENT. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            if p.is_syn:
                # TODO: Test this.
                # Could be that other socket sent a SYN packet just as we did
                # and their's reached this socket before their SYN/ACK could
                # reach this socket.
                resp_p.syn = True
                resp_p.ack = True
                self._write_packet(resp_p)
                self.state = self.STATE.SYN_RCVD
                return

            # Received SYN/ACK. Send ACK
            resp_p.ack = True
            self._write_packet(resp_p)
            self.state = self.STATE.ESTABLISHED
            return

        elif self.state == self.STATE.ESTABLISHED:
            if not (p.is_ack or p.fin):
                # Not valid packet to receive while in ESTABLISHED. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            if p.is_fin:
                resp_p.ack = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSE_WAIT
                return

            resp_p.ack = True
            self._write_packet(resp_p)
            return

        elif self.state == self.STATE.FIN_WAIT_1:
            if not (p.is_ack or p.fin or p.is_fin_ack):
                # Not valid packet to receive while in FIN_WAIT_1. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            if p.is_fin:
                resp_p.ack = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSING
                return

            if p.is_fin_ack:
                resp_p.ack = True
                self._write_packet(resp_p)
                self.state = self.STATE.TIME_WAIT
                return

            self.state = self.STATE.FIN_WAIT_2
            return

        elif self.state == self.STATE.FIN_WAIT_2:
            if not p.fin:
                # Not valid packet to receive while in FIN_WAIT_2. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            resp_p.ack = True
            self._write_packet(resp_p)
            self.state = self.STATE.TIME_WAIT
            return

        elif self.state == self.STATE.CLOSING:
            if not p.ack:
                # Not valid packet to receive while in CLOSING. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            self.state = self.STATE.TIME_WAIT
            return

        elif self.state == self.STATE.CLOSE_WAIT:
            # We do not expect any incoming packets while in CLOSE_WAIT. Send RST.
            resp_p.rst = True
            self._write_packet(resp_p)
            self.state = self.STATE.CLOSED
            return

        elif self.state == self.STATE.LAST_ACK:
            if not p.ack:
                # Not valid packet to receive while in LAST_ACK. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            self.state = self.STATE.CLOSED
            return

        raise TCPOverUDPSocketError(f'Unexpected packet {p} for state {self.state}')

    def read(self, size: int) -> bytes:
        data = self._data_queue[:size]
        self._data_queue = self._data_queue[size:]
        return data

    def write(self, msg: bytes):
        # Build TCP packet.
        p = self._get_tcp_packet()
        p.ack = True
        p.data = msg

        self._write_packet(p)

    def _write_old_packets(self):
        # Send any packets that we should have seen an ACK for by now.
        for _old_sequence_number, old_packet in self._packet_out_queue:
            # TODO: Only resend if packets are "old enough".
            self.nic.send_packet(old_packet)

    def _write_packet(self, p: TCPPacket):
        """
        Write TCP packet out to the network.
        """
        logger.debug(f'Will write {p}')

        p.sequence_number = self.sequence_number

        # Wrap in IP packet.
        ip_packet = self._get_ip_packet(p)

        # Send packet on its way.
        self.nic.send_packet(ip_packet)

        self.sequence_number += len(ip_packet.data)

        # Store TCP packet in case we need to send again.
        self._packet_out_queue.append((self.sequence_number, ip_packet))

        logger.debug(f'Wrote packet {ip_packet}')

    def _get_tcp_packet(self):
        p = TCPPacket()

        p.source_port = self.source_port
        p.destination_port = self.destination_port

        p.sequence_number = self.sequence_number
        p.acknowledgment_number = self.acknowledgment_number or 0

        p.window_size = 2048

        return p

    def _get_ip_packet(
        self,
        packet: TCPPacket,
    ) -> IPPacket:
        ip_packet = IPPacket()
        ip_packet.version = 4
        ip_packet.ihl = 5
        ip_packet.dscp = 0
        ip_packet.ecn = 0
        ip_packet.identification = 0
        ip_packet.flags = 2  # Do not fragment. TODO: Support fragmentation.
        ip_packet.fragment_offset = 0
        ip_packet.ttl = 64
        ip_packet.protocol = 6
        ip_packet.source_address = self.source_address
        ip_packet.destination_address = self.destination_address

        packet.ip_packet = ip_packet
        # Encapsulate into IP packet.
        ip_packet.data = packet.bytes
        # Overwrite default total_length
        ip_packet.total_length = len(ip_packet.bytes)

        return ip_packet

    def open_connection(self):
        p = self._get_tcp_packet()
        p.syn = True
        self._write_packet(p)
        self.state = self.STATE.SYN_SENT

        while self.state != self.STATE.ESTABLISHED:
            # TODO: Replace with something better than tight loop.
            time.sleep(0.1)

    def close_connection(self):
        if self.state not in (
            self.STATE.SYN_RCVD,
            self.STATE.SYN_SENT,
            self.STATE.ESTABLISHED,
            self.STATE.CLOSE_WAIT,
        ):
            raise TCPOverUDPSocketError(f'Unexpected state {self.state} for closing')

        if self.state == self.STATE.SYN_SENT:
            self.state = self.STATE.CLOSED
            return

        if self.state == self.STATE.CLOSE_WAIT:
            p = self._get_tcp_packet()
            p.fin = True
            self._write_packet(p)
            self.state = self.STATE.LAST_ACK

            while self.state != self.STATE.CLOSED:
                # TODO: Replace with something better than tight loop.
                time.sleep(0.1)

            return

        p = self._get_tcp_packet()
        p.fin = True
        self._write_packet(p)
        self.state = self.STATE.FIN_WAIT_1

        while self.state != self.STATE.TIME_WAIT:
            # TODO: Replace with something better than tight loop.
            time.sleep(0.1)
