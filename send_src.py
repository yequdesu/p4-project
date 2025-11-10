#!/usr/bin/env python3
import argparse
import random
import socket
import sys
from scapy.all import IP, TCP, UDP, Ether, Packet, bind_layers, get_if_hwaddr, get_if_list, sendp
from scapy.fields import *

# 2 2 2 1
# 3 2 2 1

def get_interface():
    """Get network interface"""
    ifaces = [i for i in get_if_list() if "eth0" in i]
    return ifaces[0] if ifaces else None


class SourceRoute(Packet):
    """Source Routing Header"""
    fields_desc = [
        BitField("bos", 0, 1),    # Beginning of stack flag
        BitField("port", 0, 15)   # Port number
    ]


# Setup protocol bindings
bind_layers(Ether, SourceRoute, type=0x0900)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)


def create_ipv4_packet(iface, addr, message):
    """Create IPv4 forwarding packet"""
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152, 65535)) / message
    return pkt


def create_source_routing_packet(iface, addr, message, ports):
    """Create source routing packet"""
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    # Add source routing headers
    for i, port in enumerate(ports):
        pkt = pkt / SourceRoute(bos=0, port=port)

    # Set last header's BOS flag
    if pkt.haslayer(SourceRoute):
        pkt.getlayer(SourceRoute, len(ports)).bos = 1

    pkt = pkt / IP(dst=addr) / UDP(dport=4321, sport=1234) / message
    return pkt


def main():
    """Main function"""
    print("IPv4 forwarding: ./send_src.py <target IP address> <message> --mode ip")
    print("Source routing : ./send_src.py <target IP address> <message> [--ports p1 p2 ...]")

    if len(sys.argv) < 3:
        print('Usage: ./send_src.py <destination> <message> [--mode ip] [--ports p1 p2 ...]')
        return 1

    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address")
    parser.add_argument('message', type=str, help="The message to include in packet")
    parser.add_argument('--mode', type=str, default=None, help="Mode: 'ip' for IPv4 forwarding")
    parser.add_argument('--ports', nargs='*', type=int, help="Source routing ports (space separated)")
    args = parser.parse_args()

    iface = get_interface()
    if not iface:
        print("Cannot find eth0 interface")
        return 1

    addr = socket.gethostbyname(args.ip_addr)
    print(f"Sending on interface {iface} to {addr}")

    if args.mode == "ip":
        # IPv4 forwarding mode
        pkt = create_ipv4_packet(iface, addr, args.message)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
    elif args.mode is None:
        # Source routing mode
        if args.ports:
            # Use command line specified ports
            ports = args.ports
            pkt = create_source_routing_packet(iface, addr, args.message, ports)
            pkt.show2()
            sendp(pkt, iface=iface, verbose=False)
        else:
            # Interactive mode
            while True:
                print()
                user_input = input('Type space separated port numbers (e.g., "2 3 2 2 1") or "q" to quit: ')

                if user_input.lower() == "q":
                    break

                try:
                    ports = [int(p) for p in user_input.split()]
                    pkt = create_source_routing_packet(iface, addr, args.message, ports)
                    pkt.show2()
                    sendp(pkt, iface=iface, verbose=False)
                except ValueError:
                    print("Invalid input. Please enter numbers only.")
    else:
        print("Mode must be 'ip' or omitted for source routing")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())