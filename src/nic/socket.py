from packets.tcp import TCPPacket


class TCPOverUDPSocket:
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

        self.sequence_number = 0
        self.acknowledgment_number = 0

        self.queue = []

    def _get_tcp_packet(self):
        p = TCPPacket()

        p.source_port = self.source_port
        p.destination_port = self.destination_port

        p.sequence_number = self.sequence_number
        p.acknowledgment_number = self.acknowledgment_number

        p.window_size = 2048

        return p

    def write(self, msg: bytes):
        p = self._get_tcp_packet()
        p.data = msg

        # Send packet on its way.
        self.nic.send_packet(self.source_address, self.destination_address, p)
