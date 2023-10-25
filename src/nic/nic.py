import logging
import socket
import time
import threading
import sys

from nic.socket import TCPOverUDPSocket
from packets.ip import IPPacket, IPPacketError
from packets.tcp import TCPPacket, TCPPacketError


logger = logging.getLogger(__name__)


class NIC:
    def __init__(self, port=2240) -> None:
        # This mimics an ethernet layer for us (ie. layer 2).
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # We bind to an address so that real UDP packets can be received. We
        # can think of this as the NIC publishing its MAC address on a network?
        self._sock.bind(('127.0.0.1', port))

        self._in_queue = bytearray()
        self._out_queue = []

        self._socket_map = {}

        self._shutdown = False

        self._threads = []

    def run(self):
        """
        Run each loop to handle both in and outbound transit.
        """
        t = threading.Thread(target=self.read_from_layer_2)
        t.daemon = True
        t.start()
        self._threads.append(t)

        t = threading.Thread(target=self.handle_in_queue)
        t.daemon = True
        t.start()
        self._threads.append(t)

        t = threading.Thread(target=self._send_out_queue)
        t.daemon = True
        t.start()
        self._threads.append(t)

        for t in self._threads:
            try:
                t.join()
            except KeyboardInterrupt:
                sys.exit(0)

    def read_from_layer_2(self):
        logger.debug('starting layer 2 read')
        while True:
            if self._shutdown:
                break

            try:
                b = self._sock.recv(60)
            except KeyboardInterrupt:
                self._shutdown = True
                break

            self._in_queue.extend(b)

    def handle_in_queue(self):
        logger.debug('starting in queue')

        while True:
            if self._shutdown:
                break

            if len(self._in_queue) < 20:
                # Wait it out a bit.
                time.sleep(0.1)
                continue

            # Copy up to 60 bytes as that is the maximum size of an IPv4 header.
            # If those validate, then we can take the number specified by "total_length".
            ip_header = self._in_queue[:60]
            # TODO: Handle condition where there's less than 60 bytes in buffer
            # but 60 bytes are needed to correctly validate packet. Since we
            # don't plan on using options, this can be ignored for now.

            # Read IP packet and verify
            try:
                ip_packet = IPPacket.parse(ip_header)
            except IPPacketError:
                # If the packet is not valid, chop of a byte and try again.
                # This is very slow and inefficient, but we don't loose packets this way.
                self._in_queue = self._in_queue[1:]
                continue

            if len(self._in_queue) < ip_packet.total_length:
                # Wait it out a bit.
                time.sleep(0.1)
                continue

            ip_packet_bytes = self._in_queue[:ip_packet.total_length]
            self._in_queue = self._in_queue[ip_packet.total_length:]

            try:
                ip_packet = IPPacket.parse(ip_packet_bytes)
            except IPPacketError:
                continue

            if ip_packet.protocol != IPPacket.PROTOCOL.TCP:
                # We don't support anything but TCP at the moment.
                continue

            # Read TCP header and direct to correct socket thread.
            # If socket does not exist, create one and send to its own thread.
            try:
                tcp_packet = TCPPacket.parse_from_ip_packet(ip_packet)
            except TCPPacketError:
                # Throw the packet away if its not valid.
                continue

            # Route packet based on IP and Port
            tup = (
                # Note that we flip the dest/src elements when identifying and
                # instantiating a new socket. This allows us to write the
                # socket code from the perspective of a sender.
                tcp_packet.ip_packet.destination_address,
                tcp_packet.destination_port,

                tcp_packet.ip_packet.source_address,
                tcp_packet.source_port,

                tcp_packet.ip_packet.protocol,
            )

            s = self._socket_map.get(tup)
            if s is None:
                logger.debug(f'setting up new socket for {tup}')

                s = self._socket_map[tup] = TCPOverUDPSocket(self, *tup)

                t = threading.Thread(target=s.handle_queue)
                t.daemon = True
                t.start()
                self._threads.append(t)

            s.queue.append(tcp_packet)

    def send_packet(
        self,
        source_address: str,
        destination_address: str,
        packet,
    ):
        p = self._get_ip_packet(source_address, destination_address, packet)
        self._out_queue.append((p.bytes, (destination_address, packet.destination_port)))

    def _send_out_queue(self):
        logger.debug('starting out queue')

        while True:
            if self._shutdown:
                break

            try:
                p = self._out_queue.pop(0)
            except IndexError:
                time.sleep(0.1)
                continue
            except KeyboardInterrupt:
                self._shutdown = True
                break

            self._sock.sendto(*p)

    def _get_ip_packet(
        self,
        source_address,
        destination_address,
        packet,
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
        ip_packet.source_address = source_address
        ip_packet.destination_address = destination_address

        packet.ip_packet = ip_packet
        # Encapsulate into IP packet.
        ip_packet.data = packet.bytes
        # Overwrite default total_length
        ip_packet.total_length = len(ip_packet.bytes)

        return ip_packet
