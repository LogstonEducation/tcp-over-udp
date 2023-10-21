
class IPPacket:
    """
    A class to represent an IP packet.

    Both its header and data (eg. TCP data) are held in the state of this packet.

    Pulled from https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
    """

    def __init__(self) -> None:
        self._version = b''
        self._ihl = b''
        self._dscp = b''
        self._ecn = b''
        self._total_length = b''
        self._identification = b''
        self._flags = b''
        self._fragment_offset = b''
        self._ttl = b''
        self._protocol = b''
        self._header_checksum = b''
        self._source_address = b''
        self._destination_address = b''
        self._options = b''
        self._data = b''

    # Version
    @property
    def version(self) -> bytes:
        """
        Return the four-bit version field.

        For IPv4, this is always equal to 4.
        """
        return self._version

    @version.setter
    def version(self, value: bytes):
        self._version = value

    # Internet Header Length
    @property
    def ihl(self) -> bytes:
        """
        Return size of IPv4 header as a count of the 32-bit words in the header.

        The IPv4 header is variable in size due to the optional 14th field
        (options). The IHL field contains the size of the IPv4 header; it has 4
        bits that specify the number of 32-bit words in the header. The minimum
        value for this field is 5,[32] which indicates a length of 5 × 32 bits
        = 160 bits = 20 bytes. As a 4-bit field, the maximum value is 15; this
        means that the maximum size of the IPv4 header is 15 × 32 bits = 480
        bits = 60 bytes.
        """
        return self._ihl

    @ihl.setter
    def ihl(self, value: bytes):
        self._ihl = value

    # Differentiated Services Code Point
    @property
    def dscp(self) -> bytes:
        """
        Return Type of Service for the packet.

        Originally defined as the type of service (ToS), this field specifies
        differentiated services (DiffServ).[33] Real-time data streaming makes
        use of the DSCP field. An example is Voice over IP (VoIP), which is
        used for interactive voice services.
        """
        return self._dscp

    @dscp.setter
    def dscp(self, value: bytes):
        self._dscp = value

    # Explicit Congestion Notification
    @property
    def ecn(self) -> bytes:
        """
        Return Type of Service for the packet.

        This field allows end-to-end notification of network congestion without
        dropping packets.[34] ECN is an optional feature available when both
        endpoints support it and effective when also supported by the
        underlying network.
        """
        return self._ecn

    @ecn.setter
    def ecn(self, value: bytes):
        self._ecn = value

    # Total Length
    @property
    def total_length(self) -> bytes:
        """
        Return size of packet in bytes.

        This 16-bit field defines the entire packet size in bytes, including
        header and data. The minimum size is 20 bytes (header without data) and
        the maximum is 65,535 bytes. All hosts are required to be able to
        reassemble datagrams of size up to 576 bytes, but most modern hosts
        handle much larger packets. Links may impose further restrictions on
        the packet size, in which case datagrams must be fragmented.
        Fragmentation in IPv4 is performed in either the sending host or in
        routers. Reassembly is performed at the receiving host.
        """
        return self._total_length

    @total_length.setter
    def total_length(self, value: bytes):
        self._total_length = value

    # Identification
    @property
    def identification(self) -> bytes:
        """
        Return identification for group of IP fragments.

        This field is an identification field and is primarily used for
        uniquely identifying the group of fragments of a single IP datagram.
        Some experimental work has suggested using the ID field for other
        purposes, such as for adding packet-tracing information to help trace
        datagrams with spoofed source addresses, but any such use is now
        prohibited.
        """
        return self._identification

    @identification.setter
    def identification(self, value: bytes):
        self._identification = value

    # Flags
    @property
    def flags(self) -> bytes:
        """
        Return fragmentation flags.

        A three-bit field follows and is used to control or identify fragments.
        They are (in order, from most significant to least significant):

            bit 0: Reserved; must be zero.
            bit 1: Don't Fragment (DF)
            bit 2: More Fragments (MF)

        If the DF flag is set, and fragmentation is required to route the
        packet, then the packet is dropped. This can be used when sending
        packets to a host that does not have resources to perform reassembly of
        fragments. It can also be used for path MTU discovery, either
        automatically by the host IP software, or manually using diagnostic
        tools such as ping or traceroute.

        For unfragmented packets, the MF flag is cleared. For fragmented
        packets, all fragments except the last have the MF flag set. The last
        fragment has a non-zero Fragment Offset field, differentiating it from
        an unfragmented packet.
        """
        return self._flags

    @flags.setter
    def flags(self, value: bytes):
        self._flags = value

    # Fragment offset
    @property
    def fragment_offset(self) -> bytes:
        """
        Return offset of fragment relative to unfragmented packet.

        This field specifies the offset of a particular fragment relative to
        the beginning of the original unfragmented IP datagram. The
        fragmentation offset value for the first fragment is always 0. The
        field is 13 bits wide, so that the offset can be from 0 to 8191 (from
        (20  – 1) to (213 – 1)). Fragments are specified in units of 8 bytes,
        which is why fragment length must be a multiple of 8.[37] Therefore,
        the 13-bit field allows a maximum offset of (213 – 1) × 8 = 65,528
        bytes, with the header length included (65,528 + 20 = 65,548 bytes),
        supporting fragmentation of packets exceeding the maximum IP length of
        65,535 bytes.
        """
        return self._fragment_offset

    @fragment_offset.setter
    def fragment_offset(self, value: bytes):
        self._fragment_offset = value

    # Time To Live
    @property
    def ttl(self) -> bytes:
        """
        Return Time To Live value.

        An eight-bit time to live field limits a datagram's lifetime to prevent
        network failure in the event of a routing loop. It is specified in
        seconds, but time intervals less than 1 second are rounded up to 1. In
        practice, the field is used as a hop count—when the datagram arrives at
        a router, the router decrements the TTL field by one. When the TTL
        field hits zero, the router discards the packet and typically sends an
        ICMP time exceeded message to the sender.
        """
        return self._ttl

    @ttl.setter
    def ttl(self, value: bytes):
        self._ttl = value

    # Protocol
    @property
    def protocol(self) -> bytes:
        """
        Return protocol number for packet.

        This field defines the protocol used in the data portion of the IP
        datagram. IANA maintains a list of IP protocol numbers.
        """
        return self._protocol

    @protocol.setter
    def protocol(self, value: bytes):
        self._protocol = value

    # Header Checksum
    @property
    def header_checksum(self) -> bytes:
        """
        Return header checksum for packet.

        The 16-bit IPv4 header checksum field is used for error-checking of
        the header. When a packet arrives at a router, the router
        calculates the checksum of the header and compares it to the
        checksum field. If the values do not match, the router discards the
        packet. Errors in the data field must be handled by the
        encapsulated protocol. Both UDP and TCP have separate checksums
        that apply to their data.

        When a packet arrives at a router, the router decreases the TTL field in
        the header. Consequently, the router must calculate a new header checksum.

        The checksum field is the 16 bit one's complement of the one's complement
        sum of all 16 bit words in the header. For purposes of computing the
        checksum, the value of the checksum field is zero.
        """
        return self._header_checksum

    @header_checksum.setter
    def header_checksum(self, value: bytes):
        self._header_checksum = value

    # Source Address
    @property
    def source_address(self) -> bytes:
        """
        Return source address of packet.

        This 32-bit field is the IPv4 address of the sender of the packet. It
        may be changed in transit by network address translation (NAT).
        """
        return self._source_address

    @source_address.setter
    def source_address(self, value: bytes):
        self._source_address = value

    # Destination Address
    @property
    def destination_address(self) -> bytes:
        """
        Return destination address of packet.

        This 32-bit field is the IPv4 address of the sender of the packet. It
        may be changed in transit by network address translation (NAT).
        """
        return self._destination_address

    @destination_address.setter
    def destination_address(self, value: bytes):
        self._destination_address = value

    # Options
    @property
    def options(self) -> bytes:
        """
        Return options for packet.

        The options field is not often used. Packets containing some options
        may be considered as dangerous by some routers and be blocked.

        For more, see wikipedia page.
        """
        return self._options

    @options.setter
    def options(self, value: bytes):
        self._options = value
        raise NotImplementedError('Not implemented in this particular project :/')

    # Data
    @property
    def data(self) -> bytes:
        """
        Return data for packet.
        """
        return self._data

    @data.setter
    def data(self, value: bytes):
        self._data = value
