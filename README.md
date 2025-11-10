# P4 Project: Dual-Modal Network with IPv4/IPv6 Forwarding

## Overview

This project implements a dual-modal network using P4 programmable switches, supporting both IPv4 and IPv6 forwarding with tunnel-based multi-hop routing.

## Architecture

### Network Topology
- **Hosts**: h1 (10.0.1.1, 2001:db8:1::1), h2 (10.0.2.2, 2001:db8:1::2)
- **Switches**: s1, s2, s11, s12, s21, s22
- **IPv4 Path**: h1 → s1 → s11 → s12 → s2 → h2
- **IPv6 Path**: h1 → s1 → s21 → s22 → s2 → h2

### P4 Program (basic.p4)
- **Headers**: Ethernet, IPv4, IPv6, ARP, myTunnel
- **Actions**: ipv4_forward, ipv6_forward, myTunnel_ingress/forward/egress, send_arp_reply
- **Tables**: ipv4_lpm, ipv6_lpm, myTunnel_exact, arp_match
- **Features**: Tunnel-based forwarding, ARP response, checksum computation

### Controller (controller.py)
- **P4Runtime Integration**: Dynamic rule deployment
- **Tunnel Management**: IPv4 tunnels (100-101), IPv6 tunnels (200-201)
- **Routing Rules**: LPM-based forwarding with tunnel encapsulation
- **ARP Handling**: Gateway IP response for both protocols

## Features

### Level 1: IPv4 Single-Modal Network
- ✅ IPv4 packet forwarding via tunnel encapsulation
- ✅ Multi-hop routing: s1 → s11 → s12 → s2
- ✅ ARP request/response handling
- ✅ P4Runtime control plane integration

### Level 2: IPv4/IPv6 Dual-Modal Network
- ✅ IPv6 packet forwarding with hop limit decrement
- ✅ Separate IPv6 path: s1 → s21 → s22 → s2
- ✅ Dual-stack support on s1 and s2
- ✅ IPv4/IPv6 coexistence verification

## Testing Tools

### Packet Testing
- `send.py`: Unified IPv4/IPv6 packet sender
- `receive.py`: Unified IPv4/IPv6 packet receiver
- `send_ipv4.py`: IPv4-specific sender (Scapy)
- `receive_ipv4.py`: IPv4-specific receiver (Scapy)
- `send_ipv6.py`: IPv6-specific sender (Scapy)
- `receive_ipv6.py`: IPv6-specific receiver (Scapy)

### Verification Commands
```bash
# Build and run network
make build
make run

# Start controller (Terminal 2)
python3 controller.py

# Test connectivity (Mininet CLI)
mininet> pingall
mininet> h1 ping h2

# Send test packets
python3 send.py --ip 10.0.2.2 --count 3 --message "IPv4 test"
python3 send.py --ip 2001:db8:1::2 --message "IPv6 test"

# Packet capture verification
tcpdump -r pcaps/s11-eth2_out.pcap -c 5  # Should show tunnel packets
tcpdump -r pcaps/s21-eth2_out.pcap -c 5  # Should show tunnel packets
```

## File Structure

```
├── basic.p4              # Main P4 program
├── controller.py         # P4Runtime controller
├── topology.json         # Network topology definition
├── send.py              # Unified packet sender
├── receive.py           # Unified packet receiver
├── send_ipv4.py         # IPv4 packet sender
├── receive_ipv4.py      # IPv4 packet receiver
├── send_ipv6.py         # IPv6 packet sender
├── receive_ipv6.py      # IPv6 packet receiver
├── Makefile             # Build and run scripts
├── build/               # Compiled P4 artifacts
├── pcaps/               # Packet capture files
├── logs/                # Switch and controller logs
└── ref/                 # Reference implementations
```

## Key Technical Details

### Tunnel-Based Forwarding
- **Ingress**: Packets encapsulated with tunnel header (proto_id + dst_id)
- **Transit**: Switches forward based on tunnel dst_id only
- **Egress**: Destination switch decapsulates and delivers to host

### Dual-Modal Operation
- **IPv4 Tunnels**: 100 (h1→h2), 101 (h2→h1)
- **IPv6 Tunnels**: 200 (h1→h2), 201 (h2→h1)
- **Path Separation**: IPv4 uses s11/s12, IPv6 uses s21/s22

### Verification Methods
- **Connectivity**: ping, pingall commands
- **Packet Inspection**: tcpdump on switch interfaces
- **Protocol Validation**: Scapy packet crafting and analysis
- **Path Verification**: Tunnel encapsulation/decapsulation checks

## Usage

1. **Setup Environment**
   ```bash
   make build
   make run
   ```

2. **Deploy Rules**
   ```bash
   python3 controller.py
   ```

3. **Test Network**
   ```bash
   # In Mininet CLI
   mininet> pingall
   mininet> h1 ping h2
   ```

4. **Send Custom Packets**
   ```bash
   python3 send.py --ip 10.0.2.2 --message "Test"
   python3 send.py --ip 2001:db8:1::2 --message "IPv6 Test"
   ```

## Notes

- IPv6 ping may not work in Mininet due to environment limitations
- Use Scapy-based tools for comprehensive IPv6 testing
- Packet captures in `pcaps/` directory for analysis
- Controller logs in `logs/` directory for debugging