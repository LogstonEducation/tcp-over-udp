import logging
import threading
import sys
import time

from packets.tcp import TCPPacket

from .nic import NIC


logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    n = NIC(port=2241)
    t = threading.Thread(target=n.run)
    t.daemon = True
    t.start()

    p = TCPPacket()

    # Move this into socket. User should only know about creating conn.
    p.source_port = 2241
    p.destination_port = 2240
    p.sequence_number = 25
    p.acknowledgment_number = 81
    p.window_size = 2048

    for x in range(10):
        p.data = f'sup {x}'.encode()
        n.send_packet('127.0.0.1', '127.0.0.1', p)
        time.sleep(1)

    try:
        t.join()
    except KeyboardInterrupt:
        pass
