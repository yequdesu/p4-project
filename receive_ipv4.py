#!/usr/bin/env python3
"""
IPv4 packet receiver for testing
"""

import argparse
import os
import sys

from scapy.all import (
    TCP,
    UDP,
    IP,
    Raw,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR


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


class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [_IPOption_HDR,
                   FieldLenField("length", None, fmt="B",
                                 length_of="swids",
                                 adjust=lambda pkt, l: l + 4),
                   ShortField("count", 0),
                   FieldListField("swids",
                                  [],
                                  IntField("", 0),
                                  length_from=lambda pkt: pkt.count * 4)]


def handle_pkt(pkt):
    """Handle received packet"""
    if TCP in pkt and pkt[TCP].dport == 1234:
        print("Received IPv4 packet:")
        print(f"  Source: {pkt[IP].src}")
        print(f"  Destination: {pkt[IP].dst}")
        print(f"  TCP Port: {pkt[TCP].dport}")
        if Raw in pkt:
            print(f"  Payload: {pkt[Raw].load.decode('utf-8', errors='ignore')}")
        sys.stdout.flush()
    elif UDP in pkt and pkt[UDP].dport == 4321:
        print("Received UDP IPv4 packet:")
        print(f"  Source: {pkt[IP].src}")
        print(f"  Destination: {pkt[IP].dst}")
        print(f"  UDP Port: {pkt[UDP].dport}")
        if Raw in pkt:
            print(f"  Payload: {pkt[Raw].load.decode('utf-8', errors='ignore')}")
        sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description='Receive IPv4 packets for testing')
    parser.add_argument('--interface', help='Network interface to sniff on')
    args = parser.parse_args()

    if args.interface:
        iface = args.interface
    else:
        ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
        iface = ifaces[0]

    print("Sniffing IPv4 packets on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface,
          prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
