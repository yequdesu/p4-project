#!/usr/bin/env python3
"""
IPv6 encapsulated IPv4 packet sender for testing
"""

import argparse
import random
import socket
import sys

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP


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
    parser = argparse.ArgumentParser(description='Send IPv4 packet that will be encapsulated in IPv6 tunnel')
    parser.add_argument('--ip', help='Destination IPv4 address (default: 10.0.2.10 which triggers IPv6 encapsulation)')
    parser.add_argument('--message', default='Hello IPv6 tunnel', help='Message to send')
    args = parser.parse_args()

    # Default to the trigger IP address for IPv6 encapsulation
    dst_ip = args.ip if args.ip else "10.0.2.10"

    iface = get_if()

    print("Sending IPv4 packet on interface %s to %s (will be encapsulated in IPv6 tunnel by s1)" % (iface, dst_ip))
    # Create IPv4 packet - this will be encapsulated by s1 switch
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(src="10.0.1.10", dst=dst_ip, ttl=64) / UDP(dport=4321, sport=1234) / args.message
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    print("IPv4 packet sent successfully (IPv6 encapsulation will be done by s1 switch)")


if __name__ == '__main__':
    main()