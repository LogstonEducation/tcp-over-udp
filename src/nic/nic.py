import logging
import time
import threading
import sys

from nic.socket import TCPOverUDPSocket
from packets.ip import IPPacket, IPPacketError
from packets.tcp import TCPPacket, TCPPacketError


logger = logging.getLogger(__name__)


class NICError(Exception):
    """
    Catch all error for anything related to NIC.
    """


class NIC:
    def __init__(self, layer2) -> None:
        # A bool to indicate if threads should shutdown.
        # TODO: Do we need this?
        self._shutdown = False

        self._layer2 = layer2
        self._in_queue = bytearray()
        self._out_queue = bytearray()

        # A list of threads used by NIC.
        # The NIC itself needs a few threads to manage incoming and outgoing
        # traffic. And each socket uses its own thread.
        self._threads = []

        # A map from 5-tuple to socket servicing the connection represented by
        # the 5-tuple.
        self._socket_map = {}

    def run(self):
        """
        Run each loop to handle both in and outbound transit.
        """
        t = threading.Thread(target=self._read_from_layer2, daemon=True)
        t.start()
        self._threads.append(t)

        t = threading.Thread(target=self._write_to_layer2, daemon=True)
        t.start()
        self._threads.append(t)

        t = threading.Thread(target=self._handle_in_queue, daemon=True)
        t.start()
        self._threads.append(t)

        for t in self._threads:
            try:
                t.join()
            except KeyboardInterrupt:
                sys.exit(0)

    def _read_from_layer2(self):
        logger.info('starting read from layer 2 loop')

        while True:
            if self._shutdown:
                break

            try:
                b = self._layer2.read(60)
            except KeyboardInterrupt:
                self._shutdown = True
                break

            self._in_queue.extend(b)

    def _write_to_layer2(self):
        logger.info('starting write to layer 2 loop')

        while True:
            if self._shutdown:
                break

            try:
                # Send a few bytes at a time to get a feel for
                # very discrete flows.
                b = self._out_queue[:5]
                self._out_queue = self._out_queue[5:]
            except IndexError:
                time.sleep(0.1)
                continue
            except KeyboardInterrupt:
                self._shutdown = True
                break

            self._layer2.write(b)

    def _handle_in_queue(self):
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

                t = threading.Thread(target=s.handle_queue, daemon = True)
                t.start()
                self._threads.append(t)

            s.packet_in_queue.append(tcp_packet)

    def send_packet(self, packet: IPPacket):
        self._out_queue.extend(packet.bytes)

    def create_conn(self, addr_tup: tuple, timeout=1.0) -> TCPOverUDPSocket:
        logger.debug(f'Creating conn to {addr_tup}')

        # TODO: Pull source_address from NIC.
        source_address = '98.76.54.231'
        # TODO: Randomize this port based on "available" ports.
        source_port = 2245

        tup = (
            source_address,
            source_port,
            addr_tup[0],
            addr_tup[1],
            IPPacket.PROTOCOL.TCP,
        )

        if tup in self._socket_map:
            raise NICError(f'Socket {tup} already exists')

        s = self._socket_map[tup] = TCPOverUDPSocket(self, *tup)

        # Open a connection.
        t = threading.Thread(target=s.open_connection, daemon=True)
        t.start()
        self._threads.append(t)

        # Wait until socket is ready.
        t.join(timeout)

        return s
