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
    parser.add_argument('--src-route', nargs='*', type=int, help='Source routing ports (space separated)')

    args = parser.parse_args()

    # Check if source routing is requested
    if args.src_route is not None:
        # Source routing mode
        cmd = ['python3', 'send_src.py', args.ip, args.message]
        if args.src_route:
            # Pre-specify ports, run non-interactively
            cmd.extend(['--ports'] + [str(p) for p in args.src_route])
        # Execute source routing sender
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to send source routing packet: {e}")
        except FileNotFoundError:
            print("send_src.py not found")
        return

    # Check for tunnel mode
    if args.ip.startswith('tunnel:'):
        # Yequdesu tunnel mode - send_tunnel.py expects: <destination> "<message>"
        actual_ip = args.ip[7:]  # Remove 'tunnel:' prefix
        cmd = ['python3', 'send_tunnel.py', actual_ip, args.message]
    else:
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