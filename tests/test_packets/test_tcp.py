import re

import pytest

from packets.ip import IPPacket
from packets.tcp import TCPPacket, TCPPacketError
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


def create_simple_tcp_packet(data=b'') -> TCPPacket:
    p = TCPPacket()
    p.ip_packet = create_simple_ip_packet()

    p.source_port = 18739
    p.destination_port = 80

    p.sequence_number = 10
    p.acknowledgment_number = 97

    p.window_size = 2048

    p.data = data

    p.ip_packet.data = p.bytes

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
        '00', '00', '08', '00',
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

    p.syn = True
    p.window_size = 8192
    p.urgent_pointer = 0
    p.data = b'Hi'

    assert p.checksum == bytearray_from_hex(('c5', 'c1'))


def test_parse_round_trip():
    p = create_simple_tcp_packet(b'hello')

    p2 = TCPPacket.parse_from_ip_packet(p.ip_packet, verify=False)

    # Check field parsing
    assert p.source_port == p2.source_port
    assert p.destination_port == p2.destination_port

    assert p.sequence_number == p2.sequence_number
    assert p.acknowledgment_number == p2.acknowledgment_number

    assert p.data_offset == p2.data_offset

    assert p.cwr == p2.cwr
    assert p.ece == p2.ece
    assert p.urg == p2.urg
    assert p.ack == p2.ack
    assert p.psh == p2.psh
    assert p.rst == p2.rst
    assert p.syn == p2.syn
    assert p.fin == p2.fin

    assert p.window_size == p2.window_size

    assert p.urgent_pointer == p2.urgent_pointer

    assert p.options == p2.options

    assert p.data == p2.data

    # Check valid checksum
    p2 = TCPPacket.parse_from_ip_packet(p.ip_packet)
    assert p.bytes == p2.bytes

    # Check invalid checksum
    b = bytearray(p.ip_packet.data)
    b[16] = 0
    b[17] = 0
    p.ip_packet.data = b

    m = re.escape(r"Invalid checksum ['0x9e', '0x5a'], expected ['0x0', '0x0']")
    with pytest.raises(TCPPacketError, match=m):
        TCPPacket.parse_from_ip_packet(p.ip_packet)
