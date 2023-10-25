import logging
import sys

from nic.nic import NIC
from layer2.udp import UDP


logger = logging.getLogger(__name__)


def main():
    import argparse

    parser = argparse.ArgumentParser('Demo TCP client')
    parser.add_argument('-l', '--log-level', default='INFO')

    args = parser.parse_args()

    log_level = getattr(logging, args.log_level)

    logging.basicConfig(stream=sys.stdout, level=log_level)

    layer2 = UDP(
        local_addr=('127.0.0.1', 2240),
        remote_addr=('127.0.0.1', 2241),
    )
    n = NIC(layer2)
    n.run()
