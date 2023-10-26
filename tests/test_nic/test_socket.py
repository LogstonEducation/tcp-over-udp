import threading

from layer2.buffer import Buffer
from nic.nic import NIC
from nic.socket import TCPOverUDPSocket
from packets.ip import IPPacket
from packets.tcp import TCPPacket


def create_simple_ip_packet() -> IPPacket:
    p = IPPacket()

    p.version = 4
    p.ihl = 5
    p.dscp = 0
    p.ecn = 0
    p.total_length = 52
    p.identification = 0
    p.flags = 2
    p.fragment_offset = 0
    p.ttl = 64
    p.protocol = 6
    p.source_address = '127.0.0.1'
    p.destination_address = '127.0.0.1'

    return p


def create_simple_tcp_packet(data=b'') -> TCPPacket:
    p = TCPPacket()
    p.ip_packet = create_simple_ip_packet()
    p.data = data
    p.ip_packet.data = p.bytes
    return p


def setup_socket():
    """
    Create a NIC and socket used for testing.
    """
    layer2 = Buffer()
    n = NIC(layer2)
    s = TCPOverUDPSocket(
        n,
        source_address='127.0.0.1',
        source_port=0,
        destination_address='127.0.0.1',
        destination_port=0,
    )
    return n, s


# FROM LISTEN
def test_socket_listen_to_syn_rcvd():
    # Set up server socket.
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.LISTEN

    # Create SYN packet from client.
    p = create_simple_tcp_packet()
    p.syn = True

    s._handle_packet(p)

    # Server sent back a SYN/ACK
    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_syn_ack

    # Socket is in SYN_RCVD state
    assert s.state == TCPOverUDPSocket.STATE.SYN_RCVD


### FROM SYN_RCVD
def test_socket_syn_rcvd_to_established():
    # Set up server socket.
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.SYN_RCVD

    # Create SYN packet from client.
    p = create_simple_tcp_packet()
    p.ack = True

    s._handle_packet(p)

    # Server sent nothing back.
    assert len(n._out_queue) == 0

    assert s.state == TCPOverUDPSocket.STATE.ESTABLISHED


def test_socket_syn_rcvd_to_fin_wait_1():
    # Set up server socket.
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.SYN_RCVD

    t = threading.Thread(target=s.close_connection, daemon=True)
    t.start()
    t.join(0.01)

    # Server sent a FIN
    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_fin

    assert s.state == TCPOverUDPSocket.STATE.FIN_WAIT_1


def test_socket_syn_rcvd_to_closed():
    # Set up server socket.
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.SYN_RCVD

    # Create SYN packet from client.
    p = create_simple_tcp_packet()

    s._handle_packet(p)

    # Server sent back a RST
    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_rst

    # Socket is in CLOSED state
    assert s.state == TCPOverUDPSocket.STATE.CLOSED


# FROM SYN_SENT
def test_socket_syn_sent_to_established():
    # Set up client socket.
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.SYN_SENT

    # Create SYN/ACK packet from server.
    p = create_simple_tcp_packet()
    p.syn = True
    p.ack = True

    s._handle_packet(p)

    # Client sent back a ACK
    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_ack

    assert s.state == TCPOverUDPSocket.STATE.ESTABLISHED


# FROM ESTABLISHED
def test_socket_established_to_fin_wait():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.ESTABLISHED

    t = threading.Thread(target=s.close_connection, daemon=True)
    t.start()
    t.join(0.01)

    # Server sent a FIN
    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_fin

    assert s.state == TCPOverUDPSocket.STATE.FIN_WAIT_1


def test_socket_established_to_close_wait():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.ESTABLISHED

    p = create_simple_tcp_packet()
    p.fin = True

    s._handle_packet(p)

    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_ack

    assert s.state == TCPOverUDPSocket.STATE.CLOSE_WAIT


# FROM FIN_WAIT_1
def test_socket_fin_wait_1_to_fin_wait_2():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.FIN_WAIT_1

    p = create_simple_tcp_packet()
    p.ack = True

    s._handle_packet(p)

    assert len(n._out_queue) == 0

    assert s.state == TCPOverUDPSocket.STATE.FIN_WAIT_2


def test_socket_fin_wait_1_to_time_wait():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.FIN_WAIT_1

    p = create_simple_tcp_packet()
    p.fin = True
    p.ack = True

    s._handle_packet(p)

    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_ack

    assert s.state == TCPOverUDPSocket.STATE.TIME_WAIT


def test_socket_fin_wait_1_to_closing():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.FIN_WAIT_1

    p = create_simple_tcp_packet()
    p.fin = True

    s._handle_packet(p)

    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_ack

    assert s.state == TCPOverUDPSocket.STATE.CLOSING


# FROM FIN_WAIT_2
def test_socket_fin_wait_2_to_time_wait():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.FIN_WAIT_2

    p = create_simple_tcp_packet()
    p.fin = True

    s._handle_packet(p)

    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_ack

    assert s.state == TCPOverUDPSocket.STATE.TIME_WAIT


# FROM CLOSING
def test_socket_closing_to_time_wait():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.CLOSING

    p = create_simple_tcp_packet()
    p.ack = True

    s._handle_packet(p)

    assert len(n._out_queue) == 0

    assert s.state == TCPOverUDPSocket.STATE.TIME_WAIT


# FROM CLOSE_WAIT
def test_socket_close_wait_to_last_ack():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.CLOSE_WAIT

    t = threading.Thread(target=s.close_connection, daemon=True)
    t.start()
    t.join(0.01)

    # Sent a FIN
    p = TCPPacket.parse_from_ip_packet(IPPacket.parse(n._out_queue))
    assert p.is_fin

    assert s.state == TCPOverUDPSocket.STATE.LAST_ACK


# FROM LAST_ACK
def test_socket_last_ack_to_closed():
    n, s = setup_socket()
    s.state = TCPOverUDPSocket.STATE.LAST_ACK

    p = create_simple_tcp_packet()
    p.ack = True

    s._handle_packet(p)

    assert len(n._out_queue) == 0

    assert s.state == TCPOverUDPSocket.STATE.CLOSED
