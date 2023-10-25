from nic.nic import NIC
from nic.socket import TCPOverUDPSocket


def test_socket():
    n = NIC()

    s = TCPOverUDPSocket(n, '127.0.0.1', 5004, '127.0.0.1', 5005)
    s.write(b'hello')
