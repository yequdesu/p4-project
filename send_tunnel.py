#!/usr/bin/env python3
"""
Yequdesu tunnel packet sender for testing
"""

import argparse
import sys
import socket
import random

from scapy.all import sendp, get_if_list, get_if_hwaddr, ShortField, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, TCP

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
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('message', type=str, help="The message to include in packet")
    parser.add_argument('--dst_id', type=int, default=300, help='The yequdesu dst_id to use')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    dst_id = args.dst_id
    iface = get_if()

    print("Sending Yequdesu tunnel packet on interface {} to dst_id {}".format(iface, str(dst_id)))

    # Create Yequdesu header (custom header)
    class Yequdesu(Packet):
        name = "Yequdesu"
        fields_desc = [
            ShortField("proto_id", 0x800),  # IPv4
            ShortField("dst_id", dst_id)    # Tunnel ID
        ]

    # Bind layers
    bind_layers(Ether, Yequdesu, type=0x1313)
    bind_layers(Yequdesu, IP)

    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x1313)
    pkt = pkt / Yequdesu(proto_id=0x800, dst_id=dst_id)
    pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    print("Yequdesu tunnel packet sent successfully")

if __name__ == '__main__':
    main()