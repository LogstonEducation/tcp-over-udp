from .ip import IPPacket, ones_complement


class TCPPacketError(Exception):
    """
    Catch all error for anything related to TCP packets.
    """


class TCPPacket:
    """
    A class to represent a TCP packet.

    Both its header and data are held in the state of this packet.

    Pulled from https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    """

    def __init__(self) -> None:
        self._source_port = 0
        self._destination_port = 0
        self._sequence_number = 0
        self._acknowledgment_number = 0
        self._data_offset = 0
        self._reserved = b''
        self._cwr = False
        self._ece = False
        self._urg = False
        self._ack = False
        self._psh = False
        self._rst = False
        self._syn = False
        self._fin = False
        self._window_size = 0
        # header_checksum calculated on the fly.
        self._urgent_pointer = 0
        self._options = b''
        self._data = b''

    # Source Port
    @property
    def source_port(self) -> int:
        """
        Return the sending port.
        """
        return self._source_port

    @source_port.setter
    def source_port(self, value: int):
        self._source_port = value

    # Destination Port
    @property
    def destination_port(self) -> int:
        """
        Return the receiving port.
        """
        return self._destination_port

    @destination_port.setter
    def destination_port(self, value: int):
        self._destination_port = value

    # Sequence Number
    @property
    def sequence_number(self) -> int:
        """
        Return the sequence number for packet.

        Has a dual role:
        - If the SYN flag is set (1), then this is the initial sequence number.
          The sequence number of the actual first data byte and the
          acknowledged number in the corresponding ACK are then this sequence
          number plus 1.
        - If the SYN flag is unset (0), then this is the accumulated sequence
          number of the first data byte of this segment for the current
          session.
        """
        return self._sequence_number

    @sequence_number.setter
    def sequence_number(self, value: int):
        self._sequence_number = value

    # Acknowledgment Number
    @property
    def acknowledgment_number(self) -> int:
        """
        Return the acknowledgment number for packet.

        If the ACK flag is set then the value of this field is the next
        sequence number that the sender of the ACK is expecting. This
        acknowledges receipt of all prior bytes (if any). The first ACK sent by
        each end acknowledges the other end's initial sequence number itself,
        but no data.
        """
        return self._acknowledgment_number

    @acknowledgment_number.setter
    def acknowledgment_number(self, value: int):
        self._acknowledgment_number = value

    # Data Offset
    @property
    def data_offset(self) -> int:
        """
        Return size of TCP header in terms of 32-bit words.

        Specifies the size of the TCP header in 32-bit words. The minimum size
        header is 5 words and the maximum is 15 words thus giving the minimum
        size of 20 bytes and maximum of 60 bytes, allowing for up to 40 bytes
        of options in the header. This field gets its name from the fact that
        it is also the offset from the start of the TCP segment to the actual
        data.
        """
        return int(len(self._header_before_checksum) / 4)

    # Reserved
    @property
    def reserved(self) -> bytes:
        """
        For future use and should be set to zero.
        """
        return self._reserved

    # Flag - CWR
    @property
    def cwr(self) -> bool:
        """
        Return Congestion window reduced flag.

        CWR (1 bit): Congestion window reduced (CWR) flag is set by the sending
        host to indicate that it received a TCP segment with the ECE flag set
        and had responded in congestion control mechanism.
        """
        return self._cwr

    @cwr.setter
    def cwr(self, value: bool):
        self._cwr = value

    # Flag - ECE
    @property
    def ece(self) -> bool:
        """
        Return ECN-Echo flag.

        ECE (1 bit): ECN-Echo has a dual role, depending on the value of the
        SYN flag. It indicates:

        - If the SYN flag is set (1), the TCP peer is ECN capable.
        - If the SYN flag is unset (0), a packet with the Congestion
          Experienced flag set (ECN=11) in its IP header was received during
          normal transmission.[a] This serves as an indication of network
          congestion (or impending congestion) to the TCP sender.
        """
        return self._ece

    @ece.setter
    def ece(self, value: bool):
        self._ece = value

    # Flag - URG
    @property
    def urg(self) -> bool:
        """
        Return urgent pointer flag.

        URG (1 bit): Indicates that the Urgent pointer field is significant
        """
        return self._urg

    @urg.setter
    def urg(self, value: bool):
        self._urg = value

    # Flag - ACK
    @property
    def ack(self) -> bool:
        """
        Return acknowledgment flag.

        ACK (1 bit): Indicates that the Acknowledgment field is significant.
        All packets after the initial SYN packet sent by the client should have
        this flag set.
        """
        return self._ack

    @ack.setter
    def ack(self, value: bool):
        self._ack = value

    # Flag - PSH
    @property
    def psh(self) -> bool:
        """
        Return push flag.

        PSH (1 bit): Push function. Asks to push the buffered data to the
        receiving application.
        """
        return self._psh

    @psh.setter
    def psh(self, value: bool):
        self._psh = value

    # Flag - RST
    @property
    def rst(self) -> bool:
        """
        Return reset flag.

        RST (1 bit): Reset the connection.
        """
        return self._rst

    @rst.setter
    def rst(self, value: bool):
        self._rst = value

    # Flag - SYN
    @property
    def syn(self) -> bool:
        """
        Return synchronize flag.

        SYN (1 bit): Synchronize sequence numbers. Only the first packet sent
        from each end should have this flag set. Some other flags and fields
        change meaning based on this flag, and some are only valid when it is
        set, and others when it is clear.
        """
        return self._syn

    @syn.setter
    def syn(self, value: bool):
        self._syn = value

    # Flag - FIN
    @property
    def fin(self) -> bool:
        """
        Return finish flag.

        FIN (1 bit): Last packet from sender.
        """
        return self._fin

    @fin.setter
    def fin(self, value: bool):
        self._fin = value

    # Flags
    @property
    def flags(self) -> int:
        """
        Return byte with configuration of flags.

        This is a helper function and does not represent a unique field in a TCP packet.
        """
        return (
            (self.cwr << 7) +
            (self.ece << 6) +
            (self.urg << 5) +
            (self.ack << 4) +
            (self.psh << 3) +
            (self.rst << 2) +
            (self.syn << 1) +
            (self.fin << 0)
        )

    # Window Size
    @property
    def window_size(self) -> int:
        """
        Return window size for socket.

        The size of the receive window, which specifies the number of window
        size units that the sender of this segment is currently willing to
        receive.
        """
        return self._window_size

    @window_size.setter
    def window_size(self, value: int):
        self._window_size = value

    # Checksum
    @property
    def checksum(self) -> bytes:
        """
        Return checksum of tcp header.

        The 16-bit checksum field is used for error-checking of the TCP header,
        the payload and an IP pseudo-header. The pseudo-header consists of the
        source IP address, the destination IP address, the protocol number for
        the TCP protocol (6) and the length of the TCP headers and payload (in
        bytes).
        """
        # Sum up each 16-bit chunk of IP pseudo header, TCP header, and TCP data.
        s = self._pseduo_header_sum
        h = bytearray(self._header_before_checksum)

        # Add in data offset at this point because we now know the size of the
        # headers. Add it in in _header_before_checksum would cause a
        # recursion error.
        h[12] = (self.data_offset << 4)
        # Technically should added 0 after the data offset. But leaving it out.

        for i in range(0, len(h), 2):
            s += (h[i] << 8) + h[i + 1]

        # Pad TCP data to include 16-bit chunks of data.
        d = bytearray(self.data)
        if len(d) % 2:
            d.append(0)

        for i in range(0, len(d), 2):
            s += (d[i] << 8) + d[i + 1]

        # Collapse into 16 bits
        s = (s >> 16) + (s & 0xffff)

        s = ones_complement(s)

        return bytes((s >> 8, s & 0xff))

    # Urgent Pointer
    @property
    def urgent_pointer(self) -> int:
        """
        Return urgent offset from sequence number.

        If the URG flag is set, then this 16-bit field is an offset from the
        sequence number indicating the last urgent data byte.
        """
        return self._urgent_pointer

    @urgent_pointer.setter
    def urgent_pointer(self, value: int):
        self._urgent_pointer = value

    # Options
    @property
    def options(self) -> bytes:
        """
        Return options for TCP packet.
        """
        return self._options

    @options.setter
    def options(self, value: bytes):
        self._options = value

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

    @property
    def ip_packet(self) -> IPPacket:
        if self._ip_packet is None:
            raise ValueError('IP packet not set')
        return self._ip_packet

    @ip_packet.setter
    def ip_packet(self, value: IPPacket):
        self._ip_packet = value

    @property
    def _pseduo_header_sum(self) -> int:
        """
        Header used as part of checksum calculation.
        """
        s = 0

        # Add in IP source address.
        sa = IPPacket.get_bytes_for_ip(self.ip_packet.source_address)
        s += (sa[0] << 8) + sa[1]
        s += (sa[2] << 8) + sa[3]

        # Add in IP destination address.
        da = IPPacket.get_bytes_for_ip(self.ip_packet.destination_address)
        s += (da[0] << 8) + da[1]
        s += (da[2] << 8) + da[3]

        # Add in Protocol
        # Technically, we add 0 here for the first 8 bits of a 16 bit chunk;
        # Protocol is only 8 bits wide. But zero is zero.
        s += self.ip_packet.protocol

        # Calculate TCP segment length in bytes.
        s += len(self._header_before_checksum) + len(self.data)

        return s

    @property
    def _header_before_checksum(self) -> bytes:
        b = bytearray()

        b.extend((self.source_port >> 8, self.source_port & 0xff))
        b.extend((self.destination_port >> 8, self.destination_port & 0xff))

        b.extend((
            (self.sequence_number >> 24) & 0xff,  # & is not needed but done for uniformity
            (self.sequence_number >> 16) & 0xff,
            (self.sequence_number >> 8) & 0xff,
            (self.sequence_number >> 0) & 0xff,  # >> is not needed by done for uniformity
        ))
        b.extend((
            (self.acknowledgment_number >> 24) & 0xff,  # & is not needed but done for uniformity
            (self.acknowledgment_number >> 16) & 0xff,
            (self.acknowledgment_number >> 8) & 0xff,
            (self.acknowledgment_number >> 0) & 0xff,  # >> is not needed by done for uniformity
        ))

        # Place holder for data offset. Will fill in later.
        b.append(0x00)

        b.append(self.flags)

        b.extend((self.window_size >> 8, self.window_size & 0xff))

        # Checksum
        b.append(0x00)
        b.append(0x00)

        b.extend((self.urgent_pointer >> 8, self.urgent_pointer & 0xff))

        # Add padding to 32-bit boundary
        for _ in range(len(bytes(b) + self.options) % 4):
            b.append(0)

        return bytes(b)

    @property
    def header(self) -> bytes:
        h = bytearray(self._header_before_checksum)

        h[12] = (self.data_offset << 4)

        c = self.checksum

        h[16] = c[0]
        h[17] = c[1]

        return bytes(h)

    @property
    def bytes(self):
        return self.header + self.data

    @classmethod
    def parse_from_ip_packet(cls, ip_packet: IPPacket, verify=True):
        p = cls()
        p.ip_packet = ip_packet

        b = ip_packet.data

        p.source_port = (b[0] << 8) + b[1]
        p.destination_port = (b[2] << 8) + b[3]

        p.sequence_number = (b[4] << 24) + (b[5] << 16) + (b[6] << 8) + b[7]
        p.acknowledgment_number = (b[8] << 24) + (b[9] << 16) + (b[10] << 8) + b[11]

        data_offset = b[12] >> 4

        p.cwr = bool((b[13] >> 7) & 0b1)
        p.ece = bool((b[13] >> 6) & 0b1)
        p.urg = bool((b[13] >> 5) & 0b1)
        p.ack = bool((b[13] >> 4) & 0b1)
        p.psh = bool((b[13] >> 3) & 0b1)
        p.rst = bool((b[13] >> 2) & 0b1)
        p.syn = bool((b[13] >> 1) & 0b1)
        p.fin = bool((b[13] >> 0) & 0b1)  # Not strictly need, but looks good.

        p.window_size = (b[14] << 8) + b[15]

        p.urgent_pointer = (b[18] << 8) + b[19]

        p.options = b[20:(data_offset * 4)]

        p.data = b[(data_offset * 4):]

        if verify and p.checksum != b[16:18]:
            c = list(map(hex, p.checksum))
            e = list(map(hex, b[16:18]))
            msg = f'Invalid checksum {c}, expected {e}'
            raise TCPPacketError(msg)

        return p

    @property
    def is_syn(self) -> bool:
        p = self.__class__()
        p.syn = True
        return p.flags == self.flags

    @property
    def is_syn_ack(self) -> bool:
        p = self.__class__()
        p.syn = True
        p.ack = True
        return p.flags == self.flags

    @property
    def is_ack(self) -> bool:
        p = self.__class__()
        p.ack = True
        return p.flags == self.flags

    @property
    def is_fin(self) -> bool:
        p = self.__class__()
        p.fin = True
        return p.flags == self.flags

    @property
    def is_fin_ack(self) -> bool:
        p = self.__class__()
        p.fin = True
        p.ack = True
        return p.flags == self.flags

    @property
    def is_rst(self) -> bool:
        p = self.__class__()
        p.rst = True
        return p.flags == self.flags

    @property
    def type(self) -> str:
        if self.is_syn:
            return 'SYN'
        elif self.is_syn_ack:
            return 'SYN/ACK'
        elif self.is_ack:
            return 'ACK'
        elif self.is_fin:
            return 'FIN'
        elif self.is_fin_ack:
            return 'FIN/ACK'
        elif self.is_rst:
            return 'RST'

        return 'DATA'

    def __str__(self):
        parts = [
            self.__class__.__name__,
            self.type,
            str(self.source_port),
            '->',
            str(self.destination_port),
        ]
        return f"<{' '.join(parts)}>"
