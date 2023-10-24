from nic.socket import TCPOverUDPSocket


def test_socket():
    s = TCPOverUDPSocket('127.0.0.1', 5005)
    s.write(b'hello')
