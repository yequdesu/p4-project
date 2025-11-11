#!/usr/bin/env python3
"""
IPv6 packet sender for testing
"""

import argparse
import random
import socket
import sys

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IPv6, UDP


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
    parser = argparse.ArgumentParser(description='Send IPv6 packet for testing')
    parser.add_argument('--ip', required=True, help='Destination IPv6 address')
    parser.add_argument('--message', default='Hello IPv6', help='Message to send')
    args = parser.parse_args()

    iface = get_if()

    print("Sending IPv6 packet on interface %s to %s" % (iface, args.ip))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IPv6(src="2001:db8:1::1", dst=args.ip) / UDP(dport=4321, sport=1234) / args.message
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    print("IPv6 packet sent successfully")


if __name__ == '__main__':
    main()