#!/usr/bin/env python3
"""
Unified packet sender for IPv4 and IPv6 testing
"""

import argparse
import sys
import subprocess

def main():
    parser = argparse.ArgumentParser(description='Unified packet sender')
    parser.add_argument('--ip', help='Destination IP (IPv4 or IPv6)', required=True)
    parser.add_argument('--count', type=int, default=1, help='Number of packets to send (IPv4 only)')
    parser.add_argument('--message', default='Hello', help='Message to send')

    args = parser.parse_args()

    # Determine if IPv4 or IPv6
    try:
        # Try to parse as IPv4
        parts = args.ip.split('.')
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            # IPv4 - send_ipv4.py expects: <destination> "<message>"
            cmd = ['python3', 'send_ipv4.py', args.ip, args.message]
        else:
            # Try IPv6
            if ':' in args.ip:
                # IPv6 - send_ipv6.py expects: <destination> "<message>"
                cmd = ['python3', 'send_ipv6.py', args.ip, args.message]
            else:
                print("Invalid IP address format")
                return
    except:
        print("Invalid IP address format")
        return

    # Execute the appropriate sender
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to send packet: {e}")
    except FileNotFoundError:
        print(f"Sender script not found for IP: {args.ip}")

if __name__ == '__main__':
    main()