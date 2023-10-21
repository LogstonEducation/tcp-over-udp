import socket
import sys


UDP_IP = "127.0.0.1"
UDP_PORT = 5005


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(sys.argv[1].encode('utf-8'), (UDP_IP, UDP_PORT))




