#!/usr/bin/env python3
"""
VXLAN packet receiver for testing
"""

import argparse
import os
import sys

from scapy.all import (
    TCP,
    UDP,
    get_if_list,
    sniff
)


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


def handle_pkt(pkt):
    """Handle received packet"""
    if UDP in pkt and pkt[UDP].dport == 4789:
        print("Received VXLAN packet:")
        pkt.show2()
        sys.stdout.flush()
    elif TCP in pkt and pkt[TCP].dport == 1234:
        print("Received decapsulated packet:")
        pkt.show2()
        sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description='Receive VXLAN packets for testing')
    parser.add_argument('--interface', help='Network interface to sniff on')
    args = parser.parse_args()

    if args.interface:
        iface = args.interface
    else:
        ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
        iface = ifaces[0]

    print("Sniffing VXLAN packets on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface,
          prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()