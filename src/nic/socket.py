import socket


from packets.ip import IPPacket
from packets.tcp import TCPPacket


class TCPOverUDPSocket:
    def __init__(self, host: str, port: int) -> None:
        self.destination_address = host
        self.destination_port = port

        # TODO: Generate random unused port.
        self.source_address = self._get_socket_ip()
        self.source_port = self._get_socket_port()

        self.sequence_number = 0
        self.acknowledgment_number = 0

        # This mimics an ethernet layer for us (ie. layer 2).
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def write_to_fd(self, msg: bytes):
        # TODO: Re-read ip dest info from packet to avoid context leakage and
        # mimic a more realistic write to an file descriptor.
        self._sock.sendto(msg, (self.destination_address, self.destination_port))

    def read_from_fd(self):
        # TODO: Move this into NIC file and create separate thread for each
        # TCPOverUDPSocket socket. Route data from UDP to correct TOU Socket
        # based on address/port.
        msg, addr = self._sock.recvfrom()

    def _get_socket_ip(self):
        # TODO: Replace with real IP of host.
        return '192.168.1.1'

    def _get_socket_port(self):
        return 12345

    def _get_ip_packet(self, tcp_packet):
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

        tcp_packet.ip_packet = ip_packet
        ip_packet.data = tcp_packet.bytes
        # Overwrite default total_length
        ip_packet.total_length = len(ip_packet.bytes)

        return ip_packet

    def write(self, msg: bytes):
        p = TCPPacket()
        p.data = msg

        # Generate random unused port
        p.source_port = self.source_port
        p.destination_port = self.destination_port

        p.sequence_number = self.sequence_number
        p.acknowledgment_number = self.acknowledgment_number

        p.window_size = 2048

        # Encapsulate into IP packet.
        ip_packet = self._get_ip_packet(p)

        # Send IP packet on its way.
        self.write_to_fd(ip_packet.bytes)

    def read(self) -> bytes:
        # Read bytes and transcribe into packets.
        # Validate TCP.
        return b''
