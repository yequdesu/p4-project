#!/usr/bin/env python3
import os
import sys
from scapy.all import FieldLenField, FieldListField, IntField, IPOption, ShortField, get_if_list, sniff

from scapy.layers.inet import _IPOption_HDR


def get_interface():
    """Get the first eth0 interface"""
    ifaces = [i for i in get_if_list() if "eth0" in i]
    if not ifaces:
        print("Cannot find eth0 interface")
        sys.exit(1)
    return ifaces[0]


class IPOption_MRI(IPOption):
    """MRI IP Option for switch path tracking"""
    name = "MRI"
    option = 31
    fields_desc = [
        _IPOption_HDR,
        FieldLenField("length", None, fmt="B",
                     length_of="swids",
                     adjust=lambda pkt, l: l + 4),
        ShortField("count", 0),
        FieldListField("swids", [], IntField("", 0),
                      length_from=lambda pkt: pkt.count * 4)
    ]


def handle_packet(pkt):
    """Process received packets"""
    print("Received packet:")
    pkt.show2()
    sys.stdout.flush()


def main():
    """Main function to sniff TCP packets"""
    iface = get_interface()
    print(f"Sniffing on {iface}")
    sys.stdout.flush()
    
    sniff(filter="tcp", iface=iface, prn=handle_packet)


if __name__ == '__main__':
    main()
