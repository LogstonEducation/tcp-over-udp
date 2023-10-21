from packets.ip import IPPacket


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
    assert p.flags == 12167


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


def test_header_checksum():
    raise NotImplementedError()


def test_source_address():
    p = IPPacket()
    p.source_address = ...
    assert p.source_address == ...


def test_destination_address():
    p = IPPacket()
    p.destination_address = ...
    assert p.destination_address == ...


def test_options():
    p = IPPacket()
    p.options = ...
    assert p.options == ...


def test_options():
    p = IPPacket()
    p.data = ...
    assert p.data == ...
