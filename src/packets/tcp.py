from .ip import IPPacket


class TCPPacket:
    """
    A class to represent a TCP packet.

    Both its header and data are held in the state of this packet.

    Pulled from https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    """

    def __init__(self, ip_packet: IPPacket) -> None:
        self._ip_packet = ip_packet
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
        return self.acknowledgment_number

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
        return self._data_offset

    @data_offset.setter
    def data_offset(self, value: int):
        self._data_offset = value

    # Reserved
    @property
    def reserved(self) -> bytes:
        """
        For future use and should be set to zero.
        """
        return self._reserved

    @reserved.setter
    def reserved(self, value: bytes):
        self._reserved = value

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
    def flags(self):
        """
        Return byte with configuration of flags.

        This is a helper function and does not represent a unique field in a TCP packet.
        """
        return b''

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
        return self._checksum

    @checksum.setter
    def checksum(self, value: bytes):
        self._checksum = value

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
    def pseduo_header(self):
        """
        Header used as part of checksum calculation.
        """
        # Calculate TCP segment length in bytes.
        tcp_length = self._ip_packet.total_length - (self._ip_packet.ihl << 2)

        s = 0

        # Add in IP source address.
        s += (self._ip_packet.source_address[0] << 8) + self._ip_packet.source_address[1]
        s += (self._ip_packet.source_address[2] << 8) + self._ip_packet.source_address[3]

        # Add in IP destination address.
        s += (self._ip_packet.destination_address[0] << 8) + self._ip_packet.destination_address[1]
        s += (self._ip_packet.destination_address[2] << 8) + self._ip_packet.destination_address[3]

        # Add in Protocol
        s += self._ip_packet.protocol
        s += tcp_length

        return s

