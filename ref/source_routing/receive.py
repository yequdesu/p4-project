#!/usr/bin/env python3
import os
import sys
from scapy.all import Ether, TCP, UDP, IPOption, Packet, bind_layers, get_if_list, sniff
from scapy.fields import *
from scapy.layers.inet import _IPOption_HDR

def get_interface():
    """Get network interface"""
    ifaces = [i for i in get_if_list() if "eth0" in i]
    return ifaces[0] if ifaces else None

class IPOption_MRI(IPOption):
    """MRI IP Option Header"""
    name = "MRI"
    option = 31
    fields_desc = [ 
        _IPOption_HDR,
        FieldLenField("length", None, fmt="B", length_of="swids", adjust=lambda pkt,l:l+4),
        ShortField("count", 0),
        FieldListField("swids", [], IntField("", 0), length_from=lambda pkt:pkt.count*4)
    ]

class SourceRoute(Packet):
    """Source Routing Header"""
    fields_desc = [ 
        BitField("bos", 0, 1),    # Beginning of stack flag
        BitField("port", 0, 15)   # Port number
    ]

class SourceRoutingTail(Packet):
    """Source Routing Tail"""
    fields_desc = [ 
        XShortField("etherType", 0x800)  # Ethernet type
    ]

def handle_packet(pkt):
    """Handle received packet"""
    print("Received packet")
    pkt.show2()
    sys.stdout.flush()

def setup_protocols():
    """Setup protocol layer bindings"""
    bind_layers(Ether, SourceRoute, type=0x1234)
    bind_layers(SourceRoute, SourceRoute, bos=0)
    bind_layers(SourceRoute, SourceRoutingTail, bos=1)

def main():
    """Main function"""
    iface = get_interface()
    if not iface:
        print("Cannot find eth0 interface")
        return 1
    
    setup_protocols()
    print(f"Sniffing on interface {iface}")
    sys.stdout.flush()
    
    sniff(iface=iface, prn=handle_packet)
    return 0

if __name__ == '__main__':
    sys.exit(main())
