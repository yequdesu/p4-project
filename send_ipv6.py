#!/usr/bin/env python3
"""
IPv6 packet sender for testing
"""

import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IPv6, UDP

def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    if len(sys.argv) < 3:
        print('Usage: python3 send_ipv6.py <dst_ipv6> <message>')
        exit(1)

    dst_ipv6 = sys.argv[1]
    message = sys.argv[2]
    iface = get_if()

    print("Sending IPv6 packet on interface %s to %s" % (iface, dst_ipv6))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') / IPv6(src="2001:db8:1::1", dst=dst_ipv6) / UDP(dport=4321, sport=1234) / message
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    print("Packet sent successfully")

if __name__ == '__main__':
    main()