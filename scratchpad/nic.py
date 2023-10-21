import socket


class Packet:
    pass







class SocketManager:
    pass


class BaseSocket:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    def _create_connection(self):
        raise NotImplementedError()


class UDPSocket(BaseSocket):
    def __init__(self, host: str, port: int) -> None:
        super().__init__(host, port)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def write_to_fd(self, msg: bytes):
        # Re-read ip info from packet.
        p = Packet.parse(msg)
        self._sock.sendto(msg, (p.ip.dest, p.ip.port))

    def read_from_fd(self, msg: bytes):
        self._sock.sendto(msg, (UDP_IP, UDP_PORT))

    def write(self, msg: bytes):
        # Create TCP packet
        self._sock.sendto(packet, (self.host, self.port))

    def read(self) -> bytes:
        # Read bytes and transcribe into packets.
        # Validate TCP.
        pass


s = UDPSocket('127.0.0.1', 5005)
s.write('hello')
