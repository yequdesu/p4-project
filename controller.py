#!/usr/bin/env python3
"""
IPv4 Controller for basic.p4
"""

import argparse
import grpc
import os
import sys
from time import sleep

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

            # Return path: h2-s2-s12-s11-s1-h1
            ('s2', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 2),   # s2 to h1 via s12 (port 2)
            ('s12', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 1),  # s12 to h1 via s11 (port 1)
            ('s11', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 1),  # s11 to h1 via s1 (port 1)
            ('s1', "10.0.1.1"): ("08:00:00:00:01:11", 1),   # s1 to h1 directly (port 1)
        }

        # Yequdesu tunnel routes: (switch, dst_ip): tunnel_id
        self.yequdesu_routes = {
            ('s1', "10.0.2.2"): 300,  # s1 to h2 via yequdesu tunnel
        }

        # Yequdesu tunnel forwarding: tunnel_id: (src_switch, dst_switch, output_port, dst_mac)
        self.yequdesu_mappings = {
            300: ('s1', 's2', 4, "08:00:00:00:02:22"),  # New path: s1 -> s31 -> s32 -> s2 -> h2
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
        }

        # ARP rules: (switch, target_ip, reply_mac)
        self.arp_rules = [
            ('s1', '10.0.1.10', '08:00:00:00:01:00'),   # s1's gateway for 10.0.1.0/24
            ('s2', '10.0.2.20', '08:00:00:00:02:00'),   # s2's gateway for 10.0.2.0/24
        ]

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
        self._deploy_arp_rules()
        print("All forwarding rules deployed")

    def _deploy_ipv4_rules(self):
        """Deploy IPv4 routing rules with direct forwarding"""
        for (sw_name, dst_ip), (dst_mac, port) in self.ip_routes.items():
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                action_name="MyIngress.ipv4_forward",
                action_params={"dstAddr": dst_mac, "port": port}
            )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                print(f"Added IPv4 route: {sw_name} -> {dst_ip} via port {port}")
            except grpc.RpcError as e:
                print(f"Failed to add IPv4 route {sw_name} -> {dst_ip}: {e}")
                # Try to modify if entry exists
                try:
                    self.switches[sw_name].ModifyTableEntry(table_entry)
                    print(f"Modified IPv4 route: {sw_name} -> {dst_ip} via port {port}")
                except grpc.RpcError as e2:
                    print(f"Failed to modify IPv4 route {sw_name} -> {dst_ip}: {e2}")

    def _deploy_yequdesu_rules(self):
        """Deploy Yequdesu tunnel rules"""
        # Deploy ingress rules
        for (sw_name, dst_ip), tunnel_id in self.yequdesu_routes.items():
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

        # s2 egress to h2
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

    def _deploy_ipv6_rules(self):
        """Deploy IPv6 routing rules with direct forwarding"""
        for (sw_name, dst_ipv6), (dst_mac, port) in self.ipv6_routes.items():
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv6_lpm",
                match_fields={"hdr.ipv6.dstAddr": (dst_ipv6, 128)},
                action_name="MyIngress.ipv6_forward",
                action_params={"dstAddr": dst_mac, "port": port}
            )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                print(f"Added IPv6 route: {sw_name} -> {dst_ipv6} via port {port}")
            except grpc.RpcError as e:
                print(f"Failed to add IPv6 route {sw_name} -> {dst_ipv6}: {e}")
                # Try to modify if entry exists
                try:
                    self.switches[sw_name].ModifyTableEntry(table_entry)
                    print(f"Modified IPv6 route: {sw_name} -> {dst_ipv6} via port {port}")
                except grpc.RpcError as e2:
                    print(f"Failed to modify IPv6 route {sw_name} -> {dst_ipv6}: {e2}")

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

    def run(self):
        """Run the controller"""
        print("IPv4 Controller running...")
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