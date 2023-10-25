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
