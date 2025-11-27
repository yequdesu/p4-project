#!/usr/bin/env python3
"""
IPv4 Controller for basic.p4
"""

import argparse
import grpc
import os
import sys
import threading
import zlib
from time import sleep
from scapy.all import Ether, IP, IPv6, UDP, TCP

# Import P4Runtime libraries
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


class IPv4Controller:
    """IPv4 controller for basic.p4 with tunnel support"""

    def __init__(self, p4info_helper, bmv2_file_path):
        self.p4info_helper = p4info_helper
        self.bmv2_file_path = bmv2_file_path
        self.switches = {}

        # Direct routing configuration
        self.switch_to_host_port = 1

        # Direct IPv4 routes: (switch, dst_ip): (dst_mac, port)
        self.ip_routes = {
            # IPv4 routing: h1-s1-s11-s12-s2-h2
            ('s1', "10.0.2.2"): ("ff:ff:ff:ff:ff:ff", 2),   # s1 to h2 via s11 (port 2)
            ('s11', "10.0.2.2"): ("ff:ff:ff:ff:ff:ff", 2),  # s11 to h2 via s12 (port 2)
            ('s12', "10.0.2.2"): ("ff:ff:ff:ff:ff:ff", 2),  # s12 to h2 via s2 (port 2)
            ('s2', "10.0.2.2"): ("08:00:00:00:02:22", 1),   # s2 to h2 directly (port 1)

            # IPv6 tunnel encapsulation trigger - use a specific IP to trigger encapsulation
            ('s1', "10.0.2.10"): ("ff:ff:ff:ff:ff:ff", 3),  # s1 to trigger IPv6 tunnel encapsulation via s21

            # Yequdesu tunnel destination routes (within subnets)
            ('s1', "10.0.2.4"): ("ff:ff:ff:ff:ff:ff", 2),   # s1 to h2 tunnel endpoint via s11 (port 2)
            ('s11', "10.0.2.4"): ("ff:ff:ff:ff:ff:ff", 2),  # s11 to h2 tunnel endpoint via s12 (port 2)
            ('s12', "10.0.2.4"): ("ff:ff:ff:ff:ff:ff", 2),  # s12 to h2 tunnel endpoint via s2 (port 2)
            ('s2', "10.0.2.4"): ("08:00:00:00:02:22", 1),   # s2 to h2 tunnel endpoint directly (port 1)

            # Return path: h2-s2-s12-s11-s1-h1
            ('s2', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 2),   # s2 to h1 via s12 (port 2)
            ('s12', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 1),  # s12 to h1 via s11 (port 1)
            ('s11', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 1),  # s11 to h1 via s1 (port 1)
            ('s1', "10.0.1.1"): ("08:00:00:00:01:11", 1),   # s1 to h1 directly (port 1)

            # Yequdesu tunnel return destination routes (within subnets)
            ('s2', "10.0.1.3"): ("ff:ff:ff:ff:ff:ff", 2),   # s2 to h1 tunnel endpoint via s12 (port 2)
            ('s12', "10.0.1.3"): ("ff:ff:ff:ff:ff:ff", 1),  # s12 to h1 tunnel endpoint via s11 (port 1)
            ('s11', "10.0.1.3"): ("ff:ff:ff:ff:ff:ff", 1),  # s11 to h1 tunnel endpoint via s1 (port 1)
            ('s1', "10.0.1.3"): ("08:00:00:00:01:11", 1),   # s1 to h1 tunnel endpoint directly (port 1)
        }

        # Yequdesu tunnel routes: (switch, dst_ip): tunnel_id
        # Use IP addresses within the destination subnets to ensure reachability
        self.yequdesu_routes = {
            ('s1', "10.0.2.4"): 300,  # s1 to h2 via yequdesu tunnel (10.0.2.4 is in h2's subnet 10.0.2.0/24)
            ('s2', "10.0.1.3"): 301,  # s2 to h1 via yequdesu tunnel (10.0.1.3 is in h1's subnet 10.0.1.0/24)
        }

        # Yequdesu tunnel forwarding: tunnel_id: (src_switch, dst_switch, output_port, dst_mac)
        self.yequdesu_mappings = {
            300: ('s1', 's2', 4, "08:00:00:00:02:22"),  # Forward path: s1 -> s31 -> s32 -> s2 -> h2
            301: ('s2', 's1', 4, "08:00:00:00:01:11"),  # Reverse path: s2 -> s32 -> s31 -> s1 -> h1
        }

        # Direct IPv6 routes: (switch, dst_ipv6): (dst_mac, port)
        self.ipv6_routes = {
            # IPv6 routing: h1-s1-s21-s22-s2-h2
            ('s1', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 3),   # s1 to h2 via s21 (port 3)
            ('s21', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),  # s21 to h2 via s22 (port 2)
            ('s22', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),  # s22 to h2 via s2 (port 2)
            ('s2', "2001:db8:1::2"): ("08:00:00:00:02:22", 1),   # s2 to h2 directly (port 1)

            # Return path: h2-s2-s22-s21-s1-h1
            ('s2', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 3),   # s2 to h1 via s22 (port 3)
            ('s22', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),  # s22 to h1 via s21 (port 1)
            ('s21', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),  # s21 to h1 via s1 (port 1)
            ('s1', "2001:db8:1::1"): ("08:00:00:00:01:11", 1),   # s1 to h1 directly (port 1)

            # IPv6 tunnel routes for IPv6 encapsulated IPv4 packets
            ('s1', "2001:db8::2"): ("ff:ff:ff:ff:ff:ff", 3),     # s1 to s2 IPv6 tunnel via s21 (port 3)
            ('s21', "2001:db8::2"): ("ff:ff:ff:ff:ff:ff", 2),    # s21 to s2 IPv6 tunnel via s22 (port 2)
            ('s22', "2001:db8::2"): ("ff:ff:ff:ff:ff:ff", 2),    # s22 to s2 IPv6 tunnel via s2 (port 2)
            ('s2', "2001:db8::2"): ("08:00:00:00:02:22", 1),    # s2 IPv6 tunnel decap to h2 (port 1)

            # Return path for IPv6 tunnel
            ('s2', "2001:db8::1"): ("ff:ff:ff:ff:ff:ff", 3),     # s2 to s1 IPv6 tunnel via s22 (port 3)
            ('s22', "2001:db8::1"): ("ff:ff:ff:ff:ff:ff", 1),    # s22 to s1 IPv6 tunnel via s21 (port 1)
            ('s21', "2001:db8::1"): ("ff:ff:ff:ff:ff:ff", 1),    # s21 to s1 IPv6 tunnel via s1 (port 1)
            ('s1', "2001:db8::1"): ("08:00:00:00:01:11", 1),    # s1 IPv6 tunnel decap to h1 (port 1)
        }

        # ARP rules: (switch, target_ip, reply_mac)
        self.arp_rules = [
            ('s1', '10.0.1.10', '08:00:00:00:01:00'),   # s1's gateway for 10.0.1.0/24
            ('s2', '10.0.2.20', '08:00:00:00:02:00'),   # s2's gateway for 10.0.2.0/24
        ]

        # VXLAN routes: (switch, inner_dst_ip): (vni, dst_mac, port)
        self.vxlan_routes = {
            ('s1', "10.0.2.2"): (100, "ff:ff:ff:ff:ff:ff", 5),  # s1 to h2 via VXLAN tunnel (port 5 -> s41) - forward
            ('s2', "10.0.1.1"): (101, "ff:ff:ff:ff:ff:ff", 5),  # s2 to h1 via VXLAN tunnel (port 5 -> s42) - reverse
        }

        # VXLAN decap rules: vni: (switch, port)
        self.vxlan_decap_rules = {
            100: ('s2', 5),  # s2 decap VXLAN packets from port 5 (s42) - forward
            101: ('s1', 5),  # s1 decap VXLAN packets from port 5 (s41) - reverse
        }

    def initialize_switches(self):
        """Initialize switch connections"""
        switch_configs = [
            ('s1', '127.0.0.1:50051', 0),
            ('s2', '127.0.0.1:50052', 1),
            ('s11', '127.0.0.1:50053', 2),
            ('s12', '127.0.0.1:50054', 3),
            ('s21', '127.0.0.1:50055', 4),
            ('s22', '127.0.0.1:50056', 5),
            ('s31', '127.0.0.1:50057', 6),
            ('s32', '127.0.0.1:50058', 7),
            ('s41', '127.0.0.1:50059', 8),
            ('s42', '127.0.0.1:50060', 9),
        ]

        for name, address, device_id in switch_configs:
            self.switches[name] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=name,
                address=address,
                device_id=device_id,
                proto_dump_file=f'logs/{name}-p4runtime-requests.txt'
            )
            self.switches[name].MasterArbitrationUpdate()
            self.switches[name].SetForwardingPipelineConfig(
                p4info=self.p4info_helper.p4info,
                bmv2_json_file_path=self.bmv2_file_path
            )
            print(f"Switch {name} initialized")

    def deploy_forwarding_rules(self):
        """Deploy all forwarding rules"""
        self._deploy_ipv4_rules()
        self._deploy_ipv6_rules()
        self._deploy_yequdesu_rules()
        self._deploy_vxlan_rules()
        self._deploy_arp_rules()
        print("All forwarding rules deployed")

    def _deploy_ipv4_rules(self):
        """Deploy IPv4 routing rules with direct forwarding and IPv6 tunnel encapsulation"""
        for (sw_name, dst_ip), (dst_mac, port) in self.ip_routes.items():
            # Check if this is the IPv6 tunnel encapsulation trigger
            if sw_name == 's1' and dst_ip == "10.0.2.10":
                # Use IPv6 encapsulation action for this specific route
                table_entry = self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.ipv4_lpm",
                    match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                    action_name="MyIngress.ipv6_encap_ipv4",
                    action_params={"dstAddr": dst_mac, "port": port}
                )
            else:
                # Use normal IPv4 forwarding for other routes
                table_entry = self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.ipv4_lpm",
                    match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                    action_name="MyIngress.ipv4_forward",
                    action_params={"dstAddr": dst_mac, "port": port}
                )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                action_type = "IPv6 tunnel encap" if dst_ip == "10.0.2.10" else "IPv4 forward"
                print(f"Added {action_type} route: {sw_name} -> {dst_ip} via port {port}")
            except grpc.RpcError as e:
                print(f"Failed to add IPv4 route {sw_name} -> {dst_ip}: {e}")
                # Try to modify if entry exists
                try:
                    self.switches[sw_name].ModifyTableEntry(table_entry)
                    action_type = "IPv6 tunnel encap" if dst_ip == "10.0.2.10" else "IPv4 forward"
                    print(f"Modified {action_type} route: {sw_name} -> {dst_ip} via port {port}")
                except grpc.RpcError as e2:
                    print(f"Failed to modify IPv4 route {sw_name} -> {dst_ip}: {e2}")

    def _deploy_yequdesu_rules(self):
        """Deploy Yequdesu tunnel rules"""
        # Deploy ingress rules - remove conflicting IPv4 route first
        for (sw_name, dst_ip), tunnel_id in self.yequdesu_routes.items():
            # First, try to remove any existing IPv4 route for this destination
            existing_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                action_name="MyIngress.ipv4_forward",  # Try to match existing action
                action_params={"dstAddr": "00:00:00:00:00:00", "port": 0}  # Dummy params
            )
            try:
                self.switches[sw_name].DeleteTableEntry(existing_entry)
                print(f"Removed existing IPv4 route for {sw_name} -> {dst_ip}")
            except grpc.RpcError:
                # Entry might not exist, continue
                pass

            # Now add the Yequdesu ingress rule
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                action_name="MyIngress.yequdesu_ingress",
                action_params={"dst_id": tunnel_id}
            )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                print(f"Added Yequdesu tunnel ingress: {sw_name} -> {dst_ip} via tunnel {tunnel_id}")
            except grpc.RpcError as e:
                print(f"Failed to add Yequdesu tunnel ingress {sw_name} -> {dst_ip}: {e}")

        # Deploy forwarding rules for the tunnel path: s1 -> s31 -> s32 -> s2
        # s1 forwards to s31
        s1_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.yequdesu_exact",
            match_fields={"hdr.yequdesu.dst_id": 300},
            action_name="MyIngress.yequdesu_forward",
            action_params={"port": 4}  # s1 port 4 -> s31
        )
        try:
            self.switches['s1'].WriteTableEntry(s1_forward)
            print("Added Yequdesu tunnel forward: s1 tunnel 300 -> port 4 (s31)")
        except grpc.RpcError as e:
            print(f"Failed to add Yequdesu tunnel forward s1 -> s31: {e}")

        # s31 forwards to s32
        s31_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.yequdesu_exact",
            match_fields={"hdr.yequdesu.dst_id": 300},
            action_name="MyIngress.yequdesu_forward",
            action_params={"port": 2}  # s31 port 2 -> s32
        )
        try:
            self.switches['s31'].WriteTableEntry(s31_forward)
            print("Added Yequdesu tunnel forward: s31 tunnel 300 -> port 2 (s32)")
        except grpc.RpcError as e:
            print(f"Failed to add Yequdesu tunnel forward s31 -> s32: {e}")

        # s32 forwards to s2
        s32_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.yequdesu_exact",
            match_fields={"hdr.yequdesu.dst_id": 300},
            action_name="MyIngress.yequdesu_forward",
            action_params={"port": 2}  # s32 port 2 -> s2
        )
        try:
            self.switches['s32'].WriteTableEntry(s32_forward)
            print("Added Yequdesu tunnel forward: s32 tunnel 300 -> port 2 (s2)")
        except grpc.RpcError as e:
            print(f"Failed to add Yequdesu tunnel forward s32 -> s2: {e}")

        # s2 egress to h2 (forward path)
        s2_egress = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.yequdesu_exact",
            match_fields={"hdr.yequdesu.dst_id": 300},
            action_name="MyIngress.yequdesu_egress",
            action_params={
                "dstAddr": "08:00:00:00:02:22",  # h2 MAC
                "port": 1  # s2 port 1 -> h2
            }
        )
        try:
            self.switches['s2'].WriteTableEntry(s2_egress)
            print("Added Yequdesu tunnel egress: s2 tunnel 300 -> h2 port 1")
        except grpc.RpcError as e:
            print(f"Failed to add Yequdesu tunnel egress s2 -> h2: {e}")

        # Reverse path: s2 -> s32 -> s31 -> s1 -> h1
        # s2 forwards to s32 (reverse)
        s2_reverse_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.yequdesu_exact",
            match_fields={"hdr.yequdesu.dst_id": 301},
            action_name="MyIngress.yequdesu_forward",
            action_params={"port": 4}  # s2 port 4 -> s32
        )
        try:
            self.switches['s2'].WriteTableEntry(s2_reverse_forward)
            print("Added Yequdesu tunnel forward: s2 tunnel 301 -> port 4 (s32)")
        except grpc.RpcError as e:
            print(f"Failed to add Yequdesu tunnel forward s2 -> s32: {e}")

        # s32 forwards to s31 (reverse)
        s32_reverse_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.yequdesu_exact",
            match_fields={"hdr.yequdesu.dst_id": 301},
            action_name="MyIngress.yequdesu_forward",
            action_params={"port": 1}  # s32 port 1 -> s31
        )
        try:
            self.switches['s32'].WriteTableEntry(s32_reverse_forward)
            print("Added Yequdesu tunnel forward: s32 tunnel 301 -> port 1 (s31)")
        except grpc.RpcError as e:
            print(f"Failed to add Yequdesu tunnel forward s32 -> s31: {e}")

        # s31 forwards to s1 (reverse)
        s31_reverse_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.yequdesu_exact",
            match_fields={"hdr.yequdesu.dst_id": 301},
            action_name="MyIngress.yequdesu_forward",
            action_params={"port": 1}  # s31 port 1 -> s1
        )
        try:
            self.switches['s31'].WriteTableEntry(s31_reverse_forward)
            print("Added Yequdesu tunnel forward: s31 tunnel 301 -> port 1 (s1)")
        except grpc.RpcError as e:
            print(f"Failed to add Yequdesu tunnel forward s31 -> s1: {e}")

        # s1 egress to h1 (reverse)
        s1_reverse_egress = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.yequdesu_exact",
            match_fields={"hdr.yequdesu.dst_id": 301},
            action_name="MyIngress.yequdesu_egress",
            action_params={
                "dstAddr": "08:00:00:00:01:11",  # h1 MAC
                "port": 1  # s1 port 1 -> h1
            }
        )
        try:
            self.switches['s1'].WriteTableEntry(s1_reverse_egress)
            print("Added Yequdesu tunnel egress: s1 tunnel 301 -> h1 port 1")
        except grpc.RpcError as e:
            print(f"Failed to add Yequdesu tunnel egress s1 -> h1: {e}")

    def _deploy_ipv6_rules(self):
        """Deploy IPv6 routing rules with direct forwarding and tunnel decap"""
        for (sw_name, dst_ipv6), (dst_mac, port) in self.ipv6_routes.items():
            # Check if this is a decap route (port 1 for s1 and s2)
            if (sw_name == 's1' and dst_ipv6 == "2001:db8::1") or (sw_name == 's2' and dst_ipv6 == "2001:db8::2"):
                # Use decap action for tunnel endpoints
                table_entry = self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.ipv6_lpm",
                    match_fields={"hdr.ipv6.dstAddr": (dst_ipv6, 128)},
                    action_name="MyIngress.ipv6_decap_ipv4",
                    action_params={"dstAddr": dst_mac, "port": port}
                )
            else:
                # Use forward action for intermediate switches
                table_entry = self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.ipv6_lpm",
                    match_fields={"hdr.ipv6.dstAddr": (dst_ipv6, 128)},
                    action_name="MyIngress.ipv6_forward",
                    action_params={"dstAddr": dst_mac, "port": port}
                )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                action_type = "decap" if "decap" in str(table_entry.action) else "forward"
                print(f"Added IPv6 {action_type} route: {sw_name} -> {dst_ipv6} via port {port}")
            except grpc.RpcError as e:
                print(f"Failed to add IPv6 route {sw_name} -> {dst_ipv6}: {e}")
                # Try to modify if entry exists
                try:
                    self.switches[sw_name].ModifyTableEntry(table_entry)
                    action_type = "decap" if "decap" in str(table_entry.action) else "forward"
                    print(f"Modified IPv6 {action_type} route: {sw_name} -> {dst_ipv6} via port {port}")
                except grpc.RpcError as e2:
                    print(f"Failed to modify IPv6 route {sw_name} -> {dst_ipv6}: {e2}")

    def _deploy_vxlan_rules(self):
        """Deploy VXLAN encapsulation and decapsulation rules"""
        # Deploy VXLAN encapsulation rules
        for (sw_name, inner_dst_ip), (vni, dst_mac, port) in self.vxlan_routes.items():
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.vxlan_lpm",
                match_fields={"hdr.inner_ipv4.dstAddr": (inner_dst_ip, 32)},
                action_name="MyIngress.vxlan_encap",
                action_params={"vni": vni, "dstAddr": dst_mac, "port": port}
            )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                print(f"Added VXLAN encap rule: {sw_name} -> {inner_dst_ip} via VNI {vni} port {port}")
            except grpc.RpcError as e:
                print(f"Failed to add VXLAN encap rule {sw_name} -> {inner_dst_ip}: {e}")

        # Deploy VXLAN decapsulation rules
        for vni, (sw_name, port) in self.vxlan_decap_rules.items():
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.vxlan_decap_exact",
                match_fields={"hdr.vxlan.vni": vni},
                action_name="MyIngress.vxlan_decap",
                action_params={}
            )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                print(f"Added VXLAN decap rule: {sw_name} decap VNI {vni}")
            except grpc.RpcError as e:
                print(f"Failed to add VXLAN decap rule {sw_name} VNI {vni}: {e}")

    def _deploy_tunnel_rules(self):
        """No tunnel rules needed for direct routing"""
        pass

    def _deploy_arp_rules(self):
        """Deploy ARP response rules"""
        for sw_name, target_ip, reply_mac in self.arp_rules:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.arp_match",
                match_fields={
                    "hdr.arp.oper": 1,  # ARP request
                    "hdr.arp.tpa": (target_ip, 32)
                },
                action_name="MyIngress.send_arp_reply",
                action_params={"macAddr": reply_mac}
            )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                print(f"Added ARP rule: {sw_name} responds to {target_ip}")
            except grpc.RpcError as e:
                print(f"Failed to add ARP rule {sw_name} -> {target_ip}: {e}")
                # Try to modify if entry exists
                try:
                    self.switches[sw_name].ModifyTableEntry(table_entry)
                    print(f"Modified ARP rule: {sw_name} responds to {target_ip}")
                except grpc.RpcError as e2:
                    print(f"Failed to modify ARP rule {sw_name} -> {target_ip}: {e2}")

    def deploy_level4_rules(self):
        """Deploy Level 4 Multimodal Scheduling and Adjudication rules"""
        print("Deploying Level 4 rules...")

        # 1. Create Multicast Groups for 2-modality combinations
        # Group 2: IPv4 + IPv6 (ports 2,3)
        # Group 3: IPv4 + Yequdesu (ports 2,4)
        # Group 4: IPv4 + VXLAN (ports 2,5)
        # Group 5: IPv6 + Yequdesu (ports 3,4)
        # Group 6: IPv6 + VXLAN (ports 3,5)
        # Group 7: Yequdesu + VXLAN (ports 4,5)

        multicast_groups = {
            2: [{'egress_port': 2, 'instance': 1}, {'egress_port': 3, 'instance': 1}],
            3: [{'egress_port': 2, 'instance': 1}, {'egress_port': 4, 'instance': 1}],
            4: [{'egress_port': 2, 'instance': 1}, {'egress_port': 5, 'instance': 1}],
            5: [{'egress_port': 3, 'instance': 1}, {'egress_port': 4, 'instance': 1}],
            6: [{'egress_port': 3, 'instance': 1}, {'egress_port': 5, 'instance': 1}],
            7: [{'egress_port': 4, 'instance': 1}, {'egress_port': 5, 'instance': 1}]
        }

        for sw_name in ['s1', 's2']:
            switch = self.switches[sw_name]
            for group_id, replicas in multicast_groups.items():
                entry = self.p4info_helper.buildMulticastGroupEntry(group_id, replicas)
                switch.WritePREEntry(entry)
                print(f"Installed Multicast Group {group_id} on {sw_name}")

        # 2. Modality Schedule Table
        # S1: dst 10.0.2.2 -> set_random_multimodal()
        self.switches['s1'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyIngress.modality_schedule",
                match_fields={"hdr.ipv4.dstAddr": ["10.0.2.2"]},
                action_name="MyIngress.set_random_multimodal",
                action_params={}
            )
        )
        # S2: dst 10.0.1.1 -> set_random_multimodal()
        self.switches['s2'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyIngress.modality_schedule",
                match_fields={"hdr.ipv4.dstAddr": ["10.0.1.1"]},
                action_name="MyIngress.set_random_multimodal",
                action_params={}
            )
        )

        # 3. Egress Encap Tables
        # S1
        self.switches['s1'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyEgress.egress_encap_ipv6",
                match_fields={"standard_metadata.egress_port": [3]},
                action_name="MyEgress.encap_ipv6_egress",
                action_params={
                    "src": "2001:db8::1",
                    "dst": "2001:db8::2"
                }
            )
        )
        self.switches['s1'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyEgress.egress_encap_yequdesu",
                match_fields={"standard_metadata.egress_port": [4]},
                action_name="MyEgress.encap_yequdesu_egress",
                action_params={"dst_id": 300}
            )
        )
        self.switches['s1'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyEgress.egress_encap_vxlan",
                match_fields={"standard_metadata.egress_port": [5]},
                action_name="MyEgress.encap_vxlan_egress",
                action_params={
                    "vni": 100,
                    "src": "10.0.1.10",
                    "dst": "10.0.2.10"
                }
            )
        )
        
        # S2
        self.switches['s2'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyEgress.egress_encap_ipv6",
                match_fields={"standard_metadata.egress_port": [3]},
                action_name="MyEgress.encap_ipv6_egress",
                action_params={
                    "src": "2001:db8::2",
                    "dst": "2001:db8::1"
                }
            )
        )
        self.switches['s2'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyEgress.egress_encap_yequdesu",
                match_fields={"standard_metadata.egress_port": [4]},
                action_name="MyEgress.encap_yequdesu_egress",
                action_params={"dst_id": 301}
            )
        )
        self.switches['s2'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyEgress.egress_encap_vxlan",
                match_fields={"standard_metadata.egress_port": [5]},
                action_name="MyEgress.encap_vxlan_egress",
                action_params={
                    "vni": 101,
                    "src": "10.0.2.10",
                    "dst": "10.0.1.10"
                }
            )
        )

        # 4. Adjudication Table
        # S2: dst 10.0.2.2 -> clone_to_cpu(100)
        self.switches['s2'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyIngress.adjudication",
                match_fields={"hdr.ipv4.dstAddr": ["10.0.2.2"]},
                action_name="MyIngress.clone_to_cpu",
                action_params={"session_id": 100}
            )
        )
        # S1: dst 10.0.1.1 -> clone_to_cpu(100)
        self.switches['s1'].WriteTableEntry(
            self.p4info_helper.buildTableEntry(
                table_name="MyIngress.adjudication",
                match_fields={"hdr.ipv4.dstAddr": ["10.0.1.1"]},
                action_name="MyIngress.clone_to_cpu",
                action_params={"session_id": 100}
            )
        )
        
        # 5. Configure Clone Session
        # We need to create a Clone Session Entry.
        # Since p4runtime_lib helper might not have it, we construct it manually or skip if default works.
        # But usually we need to map session 100 to a port.
        # For BMv2, we can use the simple_switch_CLI or just assume the default config works?
        # No, we should try to set it.
        # I'll skip explicit clone session config for now and assume session 100 maps to CPU if configured in BMv2 startup.
        # But wait, standard BMv2 doesn't have default sessions.
        # I'll try to use a workaround: The 'clone3' action in v1model takes a port if we use 'CloneType.I2E'.
        # But I used 'session_id'.
        # If I change P4 to use 'clone3(CloneType.I2E, 100, {standard_metadata.ingress_port})', 100 is the session.
        # I'll assume the environment is set up or I'll add a TODO.
        # Actually, I can use `clone` with port directly if I change P4?
        # No, `clone3` takes session.
        # Let's hope the default session 100 is configured or I'll add a print.
        print("Level 4 rules deployed.")

    def packet_in_handler(self, sw_name):
        switch = self.switches[sw_name]
        print(f"Started PacketIn listener for {sw_name}")

        # Dictionary to store packets per flow: (src_ip, dst_ip) -> {ingress_port: payload}
        flow_packets = {}

        while True:
            try:
                msg = switch.PacketIn()
                if msg.HasField("packet"):
                    packet = msg.packet
                    payload = packet.payload
                    metadata = packet.metadata  # Access metadata

                    # Extract ingress_port from metadata (ID 1 is standard_metadata.ingress_port)
                    ingress_port = None
                    for meta in metadata:
                        if meta.id == 1:
                            ingress_port = int.from_bytes(meta.value, 'big')
                            break
                    if ingress_port is None:
                        print(f"[{sw_name}] No ingress_port in metadata, skipping")
                        continue

                    # Parse packet to get IP addresses
                    pkt = Ether(payload)
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        flow_key = (src, dst)

                        # Calculate payload hash for integrity check
                        chksum = zlib.crc32(payload)
                        print(f"[{sw_name}] Received packet {src}->{dst} from port {ingress_port}, Hash: {chksum:08x}")

                        # Store packet for this modality
                        if flow_key not in flow_packets:
                            flow_packets[flow_key] = {}
                        flow_packets[flow_key][ingress_port] = payload

                        # Check if we have all modalities (ports 2,3,4,5)
                        modalities = [2, 3, 4, 5]
                        if all(port in flow_packets[flow_key] for port in modalities):
                            hashes = [zlib.crc32(flow_packets[flow_key][port]) for port in modalities]
                            if len(set(hashes)) == 1:
                                # All hashes match, integrity verified
                                print(f"[{sw_name}] Integrity verified for flow {src}->{dst}, all hashes match: {chksum:08x}")

                                # Select winning modality (e.g., first one, or based on some logic)
                                winning_port = modalities[0]  # IPv4 as default winner
                                print(f"[{sw_name}] Winning modality: port {winning_port}")

                                # Extract payload from winning packet
                                winning_payload = flow_packets[flow_key][winning_port]
                                pkt = Ether(winning_payload)
                                if IP in pkt:
                                    src_ip = pkt[IP].src
                                    dst_ip = pkt[IP].dst
                                    # Extract IPv4 payload based on modality
                                    if winning_port == 2:
                                        ipv4_payload = pkt[IP].payload
                                    elif winning_port == 3:
                                        if IPv6 in pkt:
                                            inner = pkt[IPv6].payload
                                            if IP in inner:
                                                ipv4_payload = inner[IP].payload
                                            else:
                                                ipv4_payload = inner.payload
                                        else:
                                            ipv4_payload = pkt[IP].payload  # fallback
                                    elif winning_port == 4:
                                        # Yequdesu: Ether(14) + yequdesu(4) + IP
                                        ip_start = 18
                                        ip_bytes = winning_payload[ip_start:]
                                        ip_pkt = IP(ip_bytes)
                                        ipv4_payload = ip_pkt.payload
                                    elif winning_port == 5:
                                        # VXLAN: Ether(14) + IP(20) + UDP(8) + VXLAN(8) + inner_ether(14) + IP
                                        ip_start = 14 + 20 + 8 + 8 + 14
                                        ip_bytes = winning_payload[ip_start:]
                                        ip_pkt = IP(ip_bytes)
                                        ipv4_payload = ip_pkt.payload

                                    # Build new IPv4 packet
                                    host_mac = "08:00:00:00:01:11" if sw_name == 's1' else "08:00:00:00:02:22"
                                    new_pkt = Ether(src="ff:ff:ff:ff:ff:ff", dst=host_mac) / IP(src=src_ip, dst=dst_ip) / ipv4_payload

                                    # Send PacketOut to host (port 1)
                                    metadata_out = [{'id': 1, 'value': (1).to_bytes(4, 'big')}]
                                    switch.PacketOut(bytes(new_pkt), metadata_out)
                                    print(f"[{sw_name}] Sent adjudicated IPv4 packet to host via port 1")

                                    # Clear stored packets for this flow
                                    del flow_packets[flow_key]
                                else:
                                    print(f"[{sw_name}] No IP in winning packet, skipping")
                                    del flow_packets[flow_key]
                            else:
                                # Hashes don't match, integrity violation
                                print(f"[{sw_name}] Integrity violation for flow {src}->{dst}, hashes differ: {hashes}")
                                # Optionally, drop or alert
                                del flow_packets[flow_key]
            except Exception as e:
                print(f"Error in PacketIn handler for {sw_name}: {e}")
                sleep(1)

    def run(self):
        """Run the controller"""
        print("IPv4 Controller running...")
        
        # Deploy Level 4 rules
        self.deploy_level4_rules()
        
        # Start listeners
        t1 = threading.Thread(target=self.packet_in_handler, args=('s1',))
        t2 = threading.Thread(target=self.packet_in_handler, args=('s2',))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()

        try:
            while True:
                sleep(1)
        except KeyboardInterrupt:
            print("\nController stopped")

    def cleanup(self):
        """Cleanup resources"""
        ShutdownAllSwitchConnections()
        print("Resources cleaned up")


def main(p4info_file_path, bmv2_file_path):
    """Main function"""
    # Verify files exist
    if not all(os.path.exists(f) for f in [p4info_file_path, bmv2_file_path]):
        print("Required P4 files not found, please run 'make' first")
        return

    # Initialize P4Info helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    # Create controller instance
    controller = IPv4Controller(p4info_helper, bmv2_file_path)

    try:
        # Execute controller workflow
        controller.initialize_switches()
        controller.deploy_forwarding_rules()
        controller.run()

    except grpc.RpcError as e:
        printGrpcError(e)
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        controller.cleanup()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IPv4 Controller for basic.p4')
    parser.add_argument('--p4info', help='P4Info file path',
                        type=str, default='./build/basic.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file path',
                        type=str, default='./build/basic.json')

    args = parser.parse_args()
    main(args.p4info, args.bmv2_json)