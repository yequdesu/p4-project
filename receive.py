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
    parser.add_argument('--both', action='store_true', help='Run both IPv4 and IPv6 receivers')

    args = parser.parse_args()

    if args.both or (not args.ipv4 and not args.ipv6):
        # Run both receivers in parallel
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

if __name__ == '__main__':
    main()