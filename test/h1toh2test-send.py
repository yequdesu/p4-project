#!/usr/bin/env python3
"""
H1 to H2 Test Sender
Sends test packets from h1 to h2 for all modalities
"""

import subprocess
import time
import sys

def send_packet(cmd, description):
    """Send a packet and report status"""
    print(f"\n=== {description} ===")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ Packet sent successfully")
            return True
        else:
            print("✗ Failed to send packet")
            print("Error:", result.stderr.strip())
            return False
    except subprocess.TimeoutExpired:
        print("✗ Send timeout")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def main():
    print("H1 TO H2 TEST SENDER")
    print("Sending test packets from h1 to h2")
    print("Make sure h1toh2test-rece.py is running on h2")

    input("\nPress Enter to start sending test packets...")

    tests = [
        ("IPv4 Routing", "python3 send.py --ip 10.0.2.2 --message 'IPv4 test from h1'"),
        ("IPv6 Routing", "python3 send_ipv6.py 2001:db8:1::2 'IPv6 test from h1'"),
        ("Yequdesu Tunnel", "python3 send_tunnel.py 10.0.2.4 'Yequdesu test from h1'"),
        ("VXLAN", "python3 send_vxlan.py 10.0.2.2 'VXLAN test from h1'")
    ]

    results = []
    for test_name, cmd in tests:
        success = send_packet(cmd, f"Sending {test_name}")
        results.append((test_name, success))
        time.sleep(1)  # Brief pause between sends

    print("\n" + "="*50)
    print("SEND SUMMARY (h1 -> h2)")
    print("="*50)

    for test_name, success in results:
        status = "✓ SENT" if success else "✗ FAILED"
        print(f"{test_name}: {status}")

    print("\nCheck h2 terminal for received packets")

if __name__ == '__main__':
    main()