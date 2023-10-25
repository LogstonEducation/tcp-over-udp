import socket


class UDP:
    """
    A class that mimics Layer 2 of the OSI model with UDP.

    This project is focused on implementing the TCP protocol. Thus proper
    rendering to real TCP packets sent by a real NIC is less important. We
    gloss over the process of writing TCP/IP packets to a file descriptor that
    then packs them into layer 2 frames and sends them on their way based on
    MAC addresses. Instead, we pack the same TCP/IP packets into the body of a
    UDP packet and send that UDP packet on its way.

    Becausea we use UDP packets for layer 2 and we don't want to complicate
    logic with routing to different real UDP sockets based on the ports in
    the inner TCP packets, we do a few things:

      1. We assume that a real UDP socket created by this class represents a
         MAC address in the UDP layer 2 world we are creating.
      2. We assume that all IPs live at the remote MAC address. If we were to use
         "arp", it would report the same MAC for any IP we asked about.

    Thus, this class just shuttles packets between two peers. If we choose to
    add more peers later, we can develop a mapping between the 5-tuples in the
    TCP packets and the UDP sockets created by this class; for another day.
    Each peer is responsible for setting the correct addresses, which will be
    inverses of each other.
    """
    def __init__(
        self,
        local_addr: tuple = ('127.0.0.1', 2240),
        remote_addr: tuple = ('127.0.0.1', 2241),
    ):
        self.local_addr = local_addr
        self.remote_addr = remote_addr

        # This mimics an ethernet layer for us (ie. layer 2).
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def setup(self):
        # We bind to an address so that real UDP packets can be received. We
        # can think of this as the NIC publishing its MAC address on a network?
        self._sock.bind(self.local_addr)

    def write(self, b: bytes):
        self._sock.sendto(b, self.remote_addr)

    def read(self, count: int) -> bytes:
        return self._sock.recv(count)
