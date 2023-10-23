def bytearray_from_hex(h):
    return bytearray(int(x, 16) for x in h)
