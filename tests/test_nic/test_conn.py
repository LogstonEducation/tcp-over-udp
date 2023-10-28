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


def test_sequence_number():
    client_nic, client_socket = setup_socket()
    client_socket.state = TCPOverUDPSocket.STATE.ESTABLISHED

    _, server_socket = setup_socket()
    server_socket.state = TCPOverUDPSocket.STATE.ESTABLISHED

    # Start off sockets on correct footing.
    server_socket.acknowledgment_number = client_socket.sequence_number

    # Client -> Server
    p = create_simple_tcp_packet(b'some jazz')
    p.ack = True
    client_socket._write_packet(p)
    out_queue = client_socket._packet_out_queue
    assert len(out_queue) == 1
    assert out_queue[0][0] == 29
    assert TCPPacket.parse_from_ip_packet(out_queue[0][1]).data == b'some jazz'
    # IP packet was 49 bytes.
    assert len(out_queue[0][1].bytes) == 49
    assert len(client_nic._out_queue) == 49

    # Server -> Client: Server's acknowledgment number is too low.
    p = create_simple_tcp_packet(b'yep yep, jazz')
    p.ack = True
    # Assert server is behind.
    assert p.acknowledgment_number < client_socket.sequence_number
    client_socket._handle_packet(p)

    # Client -> Sever: Client resends previous packet.
    out_queue = client_socket._packet_out_queue
    assert len(out_queue) == 2
    assert out_queue[0][0] == 29
    assert TCPPacket.parse_from_ip_packet(out_queue[0][1]).data == b'some jazz'
    # Just an ack packet sent
    assert out_queue[1][0] == 49
    assert TCPPacket.parse_from_ip_packet(out_queue[1][1]).data == b''

    # Sent on the wire thus far, 1 send, 1 resend, and 1 ack: 49 + 49 + 40
    assert len(client_nic._out_queue) == 138

    # Server -> Client: Server's acknowledgment number is correct. Client purges old packets.
    p = create_simple_tcp_packet(b'ah, gotcha')
    p.ack = True
    p.acknowledgment_number = client_socket.sequence_number
    client_socket._handle_packet(p)

    out_queue = client_socket._packet_out_queue
    assert len(out_queue) == 1
    assert out_queue[0][0] == 69
