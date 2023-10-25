class Buffer:
    """
    A class that mimics Layer 2 of the OSI model with a buffer.

    Used primarily for testing.
    """
    def __init__(self):
        self.buffer = bytearray()
        pass

    def setup(self):
        pass

    def write(self, b: bytes):
        self.buffer.extend(b)

    def read(self, count: int) -> bytes:
        b = self.buffer[:count]
        self.buffer = self.buffer[count:]
        return bytes(b)
