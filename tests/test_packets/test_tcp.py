from packets.ip import IPPacket
from packets.tcp import TCPPacket
from utils import bytearray_from_hex


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
    p.source_address = '192.168.68.51'
    p.destination_address = '54.145.64.88'

    return p


def create_simple_tcp_packet() -> TCPPacket:
    p = TCPPacket()
    p.ip_packet = create_simple_ip_packet()

    p.source_port = 18739
    p.destination_port = 80

    p.sequence_number = 10
    p.acknowledgment_number = 97

    p.data_offset = 5

    p.window_size = 2048

    return p


def test_pseduo_header_sum():
    p = create_simple_tcp_packet()
    assert p._pseduo_header_sum == 97246


def test_header_before_checksum():
    p = create_simple_tcp_packet()

    assert p._header_before_checksum == bytearray_from_hex((
        '49', '33', '00', '50',
        '00', '00', '00', '0a',
        '00', '00', '00', '61',
        '50', '00', '08', '00',
        '00', '00', '00', '00',
    ))


def test_flags():
    p = TCPPacket()

    p.syn = True
    assert p.flags == 2

    p.ack = True
    assert p.flags == 18



def test_checksum_securitynik():
    """
    Based off of: https://www.securitynik.com/2015/08/calculating-udp-checksum-with-taste-of_3.html
    """
    ip_packet = IPPacket()

    ip_packet.source_address = '192.168.0.31'
    ip_packet.destination_address = '192.168.0.30'
    ip_packet.protocol = 6

    p = TCPPacket()
    p.ip_packet = ip_packet

    p.source_port = 20
    p.destination_port = 10

    p.sequence_number = 10
    p.acknowledgment_number = 0

    p.data_offset = 5
    p.syn = True
    p.window_size = 8192
    p.urgent_pointer = 0
    p.data = b'Hi'

    assert p.checksum == bytearray_from_hex(('c5', 'c1'))
