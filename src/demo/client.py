import logging
import threading
import sys
import time

from layer2.udp import UDP
from nic.nic import NIC


logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    layer2 = UDP(
        # Should be inverse of Server's port bindings.
        local_addr=('127.0.0.1', 2241),
        remote_addr=('127.0.0.1', 2240),
    )
    n = NIC(layer2)
    t = threading.Thread(target=n.run, daemon=True)
    t.start()

    # IP can be bogus since we are servicing all IPs on the server side.
    s = n.create_conn(('123.45.67.89', 80))

    for x in range(10):
        s.write(f'sup {x}'.encode())
        time.sleep(1)

    try:
        t.join()
    except KeyboardInterrupt:
        pass
