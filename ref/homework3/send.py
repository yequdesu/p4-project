#!/usr/bin/env python3
import random
import socket
import sys
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_interface():
    """Get eth0 interface"""
    ifaces = [i for i in get_if_list() if "eth0" in i]
    if not ifaces:
        print("Cannot find eth0 interface")
        sys.exit(1)
    return ifaces[0]


def main():
    if len(sys.argv) < 3:
        print('Usage: <destination> "<message>"')
        sys.exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_interface()

    print(f"Sending on {iface} to {addr}")
    
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152, 65535)) / sys.argv[2]
    
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
