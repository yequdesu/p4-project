#!/usr/bin/env python3
"""
H2 to H1 Test Sender
Sends test packets from h2 to h1 for all modalities
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
    print("H2 TO H1 TEST SENDER")
    print("Sending test packets from h2 to h1")
    print("Make sure h2toh1test-rece.py is running on h1")

    input("\nPress Enter to start sending test packets...")

    tests = [
        ("IPv4 Routing", "python3 send.py --ip 10.0.1.1 --message 'IPv4 test from h2'"),
        ("IPv6 Routing", "python3 send_ipv6.py 2001:db8:1::1 'IPv6 test from h2'"),
        ("Yequdesu Tunnel", "python3 send_tunnel.py 10.0.1.3 'Yequdesu test from h2' --dst_id 301"),
        ("VXLAN", "python3 send_vxlan.py 10.0.1.1 'VXLAN test from h2'")
    ]

    results = []
    for test_name, cmd in tests:
        success = send_packet(cmd, f"Sending {test_name}")
        results.append((test_name, success))
        time.sleep(1)  # Brief pause between sends

    print("\n" + "="*50)
    print("SEND SUMMARY (h2 -> h1)")
    print("="*50)

    for test_name, success in results:
        status = "✓ SENT" if success else "✗ FAILED"
        print(f"{test_name}: {status}")

    print("\nCheck h1 terminal for received packets")

if __name__ == '__main__':
    main()