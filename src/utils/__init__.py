def bytearray_from_hex(h):
    return bytearray(int(x, 16) for x in h)


def ones_complement(k, width=16):
    flipped_bits = []
    for bit in reversed(str(bin(k))[2:]):
        if bit == '1':
            flipped_bits.append('0')
        else:
            flipped_bits.append('1')

    # Left pad with 1s.
    for _ in range(width - len(flipped_bits)):
        flipped_bits.append('1')

    complement_bit_string = '0b' + ''.join(reversed(flipped_bits))

    return int(complement_bit_string, 2)
