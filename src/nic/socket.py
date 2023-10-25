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
        self.acknowledgment_number = 0

        # Inbound packet queue.
        self.packet_in_queue: List[TCPPacket] = []

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

        resp_p = self._get_tcp_packet()

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
            if not p.is_ack:
                # Not valid packet to receive while in SYN_RCVD. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            # We've received an ACK. Connection is ESTABLISHED.
            self.state = self.STATE.ESTABLISHED
            return

        elif self.state == self.STATE.SYN_SENT:
            if not p.is_syn_ack:
                # Not valid packet to receive while in SYN_SENT. Send RST.
                resp_p.rst = True
                self._write_packet(resp_p)
                self.state = self.STATE.CLOSED
                return

            # Send ACK
            resp_p.ack = True
            self._write_packet(resp_p)
            self.state = self.STATE.ESTABLISHED
            return

        elif self.state == self.STATE.ESTABLISHED:
            resp_p.ack = True
            self._write_packet(resp_p)
            return

        raise TCPOverUDPSocketError('Unexpected packet {p} for state {self.state}')

    def read(self, size: int) -> bytes:
        data = self._data_queue[:size]
        self._data_queue = self._data_queue[size:]
        return data

    def write(self, msg: bytes):
        # Build TCP packet.
        p = self._get_tcp_packet()
        p.data = msg

        self._write_packet(p)

    def _write_packet(self, p: TCPPacket):
        """
        Write TCP packet out to the network.
        """
        logger.debug(f'Will write {p}')

        # Wrap in IP packet.
        ip_packet = self._get_ip_packet(p)

        # Send packet on its way.
        self.nic.send_packet(ip_packet)

        logger.debug(f'Wrote packet {ip_packet}')

    def _get_tcp_packet(self):
        p = TCPPacket()

        p.source_port = self.source_port
        p.destination_port = self.destination_port

        p.sequence_number = self.sequence_number
        p.acknowledgment_number = self.acknowledgment_number

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
