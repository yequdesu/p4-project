#!/usr/bin/env python3
"""
Level 4 Test Script: Multi-modal scheduling and data integrity arbitration
"""

import socket
import struct
import time
import threading
import sys
import os

# Add utils to path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))

def create_tcp_packet(src_ip, dst_ip, payload="Level 4 Test"):
    """Create a TCP packet that matches receive_ipv4.py expectations"""
    # TCP header (simplified)
    src_port = 12345  # Random source port
    dst_port = 1234   # Matches receive_ipv4.py TCP port
    seq_num = 0
    ack_num = 0
    data_offset = 5  # 5 * 4 = 20 bytes
    flags = 0x02     # SYN flag
    window = 8192
    checksum = 0
    urgent_ptr = 0

    tcp_header = struct.pack('!HHLLBBHHH',
                            src_port, dst_port, seq_num, ack_num,
                            data_offset << 4, flags, window, checksum, urgent_ptr)

    payload_bytes = payload.encode('utf-8')
    return tcp_header + payload_bytes

def send_test_packet(src_ip, dst_ip, interface="eth0", payload="Level 4 Test"):
    """Send test TCP packet that matches receive_ipv4.py"""
    try:
        # Create TCP socket for proper routing
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind to source IP
        sock.bind((src_ip, 0))

        # Connect to destination (this will create the TCP packet)
        try:
            sock.connect((dst_ip, 1234))  # Connect to TCP port 1234
            sock.send(payload.encode('utf-8'))
            print(f"Sent TCP packet: {src_ip} -> {dst_ip}:1234 with payload: {payload}")
            sock.close()
            return True
        except ConnectionRefusedError:
            print(f"Connection refused - make sure receive_ipv4.py is running on {dst_ip}")
            sock.close()
            return False

    except Exception as e:
        print(f"Failed to send packet: {e}")
        return False

def receive_test_packets(interface="eth0", timeout=10):
    """Receive test packets"""
    try:
        # Create raw socket to receive all IP packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        # Bind to interface
        if interface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, 25, interface.encode())  # SO_BINDTODEVICE = 25
            except:
                pass  # Ignore if not supported

        # Set timeout
        sock.settimeout(timeout)

        packets_received = []

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                packet, addr = sock.recvfrom(65535)
                packets_received.append((packet, addr, time.time()))
                print(f"Received packet from {addr} at {time.time()}")
            except socket.timeout:
                break

        sock.close()
        return packets_received

    except Exception as e:
        print(f"Failed to receive packets: {e}")
        return []

def test_multimodal_scheduling():
    """Test multimodal scheduling functionality"""
    print("=== Testing Multi-modal Scheduling ===")
    print("Note: Make sure receive_ipv4.py is running on the destination host")

    # Test h1 -> h2 communication (should trigger scheduling)
    print("Testing h1 -> h2 (should use multi-modal scheduling)")
    success = send_test_packet("10.0.1.1", "10.0.2.2", payload="Multi-modal test h1->h2")
    if success:
        print("✓ Packet sent successfully - check h2 for reception")
    else:
        print("✗ Failed to send packet")

    time.sleep(2)  # Wait a bit

    # Test h2 -> h1 communication (should trigger scheduling)
    print("Testing h2 -> h1 (should use multi-modal scheduling)")
    success = send_test_packet("10.0.2.2", "10.0.1.1", payload="Multi-modal test h2->h1")
    if success:
        print("✓ Packet sent successfully - check h1 for reception")
    else:
        print("✗ Failed to send packet")

def test_data_integrity():
    """Test data integrity arbitration"""
    print("\n=== Testing Data Integrity Arbitration ===")

    # This test would require running the controller and monitoring
    # the integrity check results. For now, we'll just send packets
    # and note that integrity checking should happen automatically.

    print("Data integrity checking is performed automatically by the P4 program")
    print("and controller. Check controller logs for integrity arbitration results.")

def test_transparency():
    """Test end-to-end transparency"""
    print("\n=== Testing End-to-End Transparency ===")

    # Send packets and verify they arrive with original content
    test_payload = "Transparency test: This should arrive unchanged"

    print(f"Sending transparent test packet with payload: {test_payload}")
    success = send_test_packet("10.0.1.1", "10.0.2.2", payload=test_payload)

    if success:
        print("✓ Test packet sent - check h2 for reception")
        print("Expected: Packet should arrive at h2 with identical payload")
    else:
        print("✗ Failed to send test packet")

def run_tests():
    """Run all Level 4 tests"""
    print("Level 4 Test Suite: Multi-modal Scheduling and Data Integrity Arbitration")
    print("=" * 70)
    print("IMPORTANT: Make sure receive_ipv4.py is running on h2 before running this test!")
    print("Run: python3 receive_ipv4.py")
    print("=" * 70)

    try:
        test_multimodal_scheduling()
        test_data_integrity()
        test_transparency()

        print("\n" + "=" * 70)
        print("Test suite completed.")
        print("\nExpected results:")
        print("1. Packets should be sent successfully")
        print("2. h2 should receive packets via receive_ipv4.py")
        print("3. Controller logs should show integrity arbitration")
        print("4. Switch logs should show modality scheduling")

    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"\nTest failed with error: {e}")

if __name__ == "__main__":
    run_tests()