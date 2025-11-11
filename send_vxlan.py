#!/usr/bin/env python3
"""
VXLAN packet sender for testing
"""

import argparse
import random
import socket
import sys

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    """Get the eth0 interface"""
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        sys.exit(1)
    return iface


def main():
    parser = argparse.ArgumentParser(description='Send VXLAN packet for testing')
    parser.add_argument('--ip', required=True, help='Destination IP address')
    parser.add_argument('--message', default='Hello VXLAN', help='Message to send')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip)
    iface = get_if()

    print("Sending packet to %s via interface %s" % (str(addr), iface))
    print("P4 switch will handle VXLAN encapsulation automatically")

    # Send regular IPv4 packet - P4 switch will do VXLAN encapsulation
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152, 65535)) / args.message

    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    print("VXLAN packet sent successfully")


if __name__ == '__main__':
    main()