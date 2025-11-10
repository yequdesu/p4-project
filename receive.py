#!/usr/bin/env python3
"""
Unified packet receiver for IPv4 and IPv6 testing
"""

import argparse
import sys
import subprocess
import threading
import time

def run_receiver(script_name):
    """Run a receiver script in background"""
    try:
        subprocess.run(['python3', script_name], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Receiver {script_name} failed: {e}")
    except KeyboardInterrupt:
        print(f"Stopped {script_name}")

def main():
    parser = argparse.ArgumentParser(description='Unified packet receiver')
    parser.add_argument('--ipv4', action='store_true', help='Run IPv4 receiver only')
    parser.add_argument('--ipv6', action='store_true', help='Run IPv6 receiver only')
    parser.add_argument('--src-route', action='store_true', help='Run source routing receiver only')
    parser.add_argument('--tunnel', action='store_true', help='Run Yequdesu tunnel receiver only')
    parser.add_argument('--both', action='store_true', help='Run both IPv4 and IPv6 receivers')
    parser.add_argument('--all', action='store_true', help='Run all receivers (IPv4, IPv6, source routing, tunnel)')

    args = parser.parse_args()

    if args.all:
        # Run all receivers in parallel
        print("Starting all receivers (IPv4, IPv6, source routing, tunnel)...")
        ipv4_thread = threading.Thread(target=run_receiver, args=('receive_ipv4.py',))
        ipv6_thread = threading.Thread(target=run_receiver, args=('receive_ipv6.py',))
        src_thread = threading.Thread(target=run_receiver, args=('receive_src.py',))
        tunnel_thread = threading.Thread(target=run_receiver, args=('receive_tunnel.py',))

        ipv4_thread.start()
        ipv6_thread.start()
        src_thread.start()
        tunnel_thread.start()

        try:
            ipv4_thread.join()
            ipv6_thread.join()
            src_thread.join()
            tunnel_thread.join()
        except KeyboardInterrupt:
            print("\nStopping receivers...")

    elif args.both or (not args.ipv4 and not args.ipv6 and not args.src_route and not args.tunnel):
        # Run both IPv4 and IPv6 receivers
        print("Starting both IPv4 and IPv6 receivers...")
        ipv4_thread = threading.Thread(target=run_receiver, args=('receive_ipv4.py',))
        ipv6_thread = threading.Thread(target=run_receiver, args=('receive_ipv6.py',))

        ipv4_thread.start()
        ipv6_thread.start()

        try:
            ipv4_thread.join()
            ipv6_thread.join()
        except KeyboardInterrupt:
            print("\nStopping receivers...")

    elif args.ipv4:
        print("Starting IPv4 receiver...")
        run_receiver('receive_ipv4.py')

    elif args.ipv6:
        print("Starting IPv6 receiver...")
        run_receiver('receive_ipv6.py')

    elif args.src_route:
        print("Starting source routing receiver...")
        run_receiver('receive_src.py')

    elif args.tunnel:
        print("Starting Yequdesu tunnel receiver...")
        run_receiver('receive_tunnel.py')

if __name__ == '__main__':
    main()