#!/usr/bin/env python3
"""
Yequdesu tunnel packet receiver for testing
"""

import argparse
import os
import sys

from scapy.all import sniff, get_if_list
from scapy.all import Packet, ShortField, bind_layers
from scapy.all import Ether, IP, TCP


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


class Yequdesu(Packet):
    """Yequdesu tunnel header"""
    name = "Yequdesu"
    fields_desc = [
        ShortField("proto_id", 0x800),  # IPv4
        ShortField("dst_id", 300)       # Tunnel ID
    ]


def handle_pkt(pkt):
    """Handle received packet"""
    if Yequdesu in pkt or (TCP in pkt and pkt[TCP].dport == 1234):
        print("Received Yequdesu tunnel packet:")
        pkt.show2()
        sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description='Receive Yequdesu tunnel packets for testing')
    parser.add_argument('--interface', help='Network interface to sniff on')
    args = parser.parse_args()

    # Bind layers for Yequdesu protocol
    bind_layers(Ether, Yequdesu, type=0x1313)
    bind_layers(Yequdesu, IP)

    if args.interface:
        iface = args.interface
    else:
        ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
        iface = ifaces[0]

    print("Sniffing Yequdesu tunnel packets on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface,
          prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()