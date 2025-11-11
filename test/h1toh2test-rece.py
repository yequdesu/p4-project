#!/usr/bin/env python3
"""
H1 to H2 Test Receiver
Receives and verifies test packets sent from h1 to h2
"""

import subprocess
import time
import threading
import sys

class PacketReceiver:
    def __init__(self, test_name, cmd):
        self.test_name = test_name
        self.cmd = cmd
        self.process = None
        self.received = False
        self.thread = None

    def start(self):
        """Start the receiver in a separate thread"""
        self.thread = threading.Thread(target=self._run_receiver)
        self.thread.daemon = True
        self.thread.start()

    def _run_receiver(self):
        """Run the receiver command"""
        try:
            self.process = subprocess.Popen(
                self.cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            print(f"Started {self.test_name} receiver (PID: {self.process.pid})")

            # Monitor output for 30 seconds
            start_time = time.time()
            while time.time() - start_time < 30:
                if self.process.poll() is not None:
                    break

                # Check for output
                output = self.process.stdout.readline()
                if output:
                    print(f"[{self.test_name}] {output.strip()}")
                    if "got a" in output.lower() or "received" in output.lower():
                        self.received = True

                time.sleep(0.1)

        except Exception as e:
            print(f"Error in {self.test_name} receiver: {e}")

    def stop(self):
        """Stop the receiver"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        print(f"Stopped {self.test_name} receiver")

def main():
    print("H1 TO H2 TEST RECEIVER")
    print("Receiving test packets sent from h1")
    print("Make sure h1toh2test-send.py is running on h1")

    # Define receivers for each modality
    receivers = [
        PacketReceiver("IPv4 Receiver", "python3 receive.py"),
        PacketReceiver("IPv6 Receiver", "python3 receive_ipv6.py"),
        PacketReceiver("VXLAN Receiver", "python3 receive_vxlan.py"),
        PacketReceiver("Yequdesu Receiver", "python3 receive_tunnel.py")
    ]

    print("\nStarting all receivers...")
    for receiver in receivers:
        receiver.start()

    print("\nAll receivers started. Waiting for packets from h1...")
    print("Test will run for 30 seconds")

    # Wait for test duration
    time.sleep(30)

    print("\n" + "="*50)
    print("RECEIVE SUMMARY (h1 -> h2)")
    print("="*50)

    all_received = True
    for receiver in receivers:
        receiver.stop()
        status = "✓ RECEIVED" if receiver.received else "✗ NOT RECEIVED"
        print(f"{receiver.test_name}: {status}")
        if not receiver.received:
            all_received = False

    print("\n" + "="*50)
    if all_received:
        print("🎉 ALL PACKETS RECEIVED SUCCESSFULLY!")
    else:
        print("⚠️  SOME PACKETS WERE NOT RECEIVED")
        print("Check the output above and network configuration")

if __name__ == '__main__':
    main()