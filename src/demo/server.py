import logging
import sys

from nic.nic import NIC
from layer2.udp import UDP


logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    layer2 = UDP(
        local_addr=('127.0.0.1', 2240),
        remote_addr=('127.0.0.1', 2241),
    )
    n = NIC(layer2)
    n.run()
