import logging
import sys

from .nic import NIC


logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    n = NIC()
    n.run()
