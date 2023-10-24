from packets.ip import IPPacket
from utils import bytearray_from_hex


def create_simple_packet() -> IPPacket:
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


def test_version():
    p = IPPacket()
    p.version = 0b0100
    assert p.version == 0b0100


def test_ihl():
    p = IPPacket()
    p.ihl = 0b0101
    assert p.ihl == 0b0101


def test_dscp():
    p = IPPacket()
    p.dscp = 0b000000
    assert p.dscp == 0b000000


def test_ecn():
    p = IPPacket()
    p.ecn = 0b00
    assert p.ecn == 0b00


def test_total_length():
    p = IPPacket()
    p.total_length = 40
    assert p.total_length == 40


def test_identification():
    p = IPPacket()
    p.identification = 12167
    assert p.identification == 12167


def test_flags():
    p = IPPacket()
    p.flags = 0b000
    assert p.flags == 0b000


def test_fragment_offset():
    p = IPPacket()
    p.fragment_offset = 0b0000000000000
    assert p.fragment_offset == 0b0000000000000


def test_ttl():
    p = IPPacket()
    p.ttl = 64
    assert p.ttl == 64


def test_protocol():
    p = IPPacket()
    p.protocol = 6  # TCP
    assert p.protocol == 6


def test_header_checksum_wikipedia():
    p = IPPacket()

    p.version = 4
    p.ihl = 5
    p.dscp = 0
    p.ecn = 0

    p.total_length = 115

    p.identification = 0

    p.flags = 2
    p.fragment_offset = 0

    p.ttl = 64
    p.protocol = 17

    p.source_address = '192.168.0.1'
    p.destination_address = '192.168.0.199'

    assert p.header_checksum == bytearray_from_hex(('b8', '61'))


def test_header_checksum():
    p = create_simple_packet()
    assert p.header_checksum == bytearray_from_hex(('be', 'ff'))


def test_source_address():
    p = IPPacket()
    p.source_address = '127.0.0.1'
    assert p.source_address == bytearray((127, 0, 0, 1))


def test_destination_address():
    p = IPPacket()
    p.destination_address = '8.8.8.8'
    assert p.destination_address == bytearray((8, 8, 8, 8))


def test_options():
    p = IPPacket()
    p.options = b''
    assert p.options == b''


def test_data():
    p = IPPacket()
    p.data = b'hello'
    assert p.data == b'hello'


def test_header_before_checksum():
    p = create_simple_packet()

    assert p._header_before_checksum == bytearray_from_hex((
        '45', '00', '00', '34',
        '00', '00', '40', '00',
        '40', '06', '00', '00',
        'c0', 'a8', '44', '33',
        '36', '91', '40', '58',
    ))


def test_header():
    p = create_simple_packet()

    assert p.header == bytearray_from_hex((
        '45', '00', '00', '34',
        '00', '00', '40', '00',
        '40', '06', 'be', 'ff',
        'c0', 'a8', '44', '33',
        '36', '91', '40', '58',
    ))


def test_bytes():
    p = create_simple_packet()
    p.data = b'hello'
    assert p.bytes == p.header + b'hello'
