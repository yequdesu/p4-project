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

        # Tunnel configuration based on topology: h1-s1-s11-s12-s2-h2
        self.switch_to_host_port = 1
        # tunnel_id: (src_switch, dst_switch, output_port, dst_mac)
        self.tunnel_mappings = {
            100: ('s1', 's2', 2, "08:00:00:00:02:22"),  # s1 -> s2 via s11-s12 path
            101: ('s2', 's1', 2, "08:00:00:00:01:11"),  # s2 -> s1 return path
            # Need to add forwarding rules for intermediate switches s11 and s12
            102: ('s11', 's2', 2, "08:00:00:00:02:22"), # s11 -> s2 via s12
            103: ('s12', 's2', 2, "08:00:00:00:02:22"), # s12 -> s2
        }

        # (switch, dst_ip): tunnel_id
        self.ip_routes = {
            ('s1', "10.0.2.2"): 100,  # s1 to h2
            ('s2', "10.0.1.1"): 101,  # s2 to h1
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
        self._deploy_tunnel_rules()
        self._deploy_arp_rules()
        print("All forwarding rules deployed")

    def _deploy_ipv4_rules(self):
        """Deploy IPv4 routing rules with tunnel ingress"""
        for (sw_name, dst_ip), tunnel_id in self.ip_routes.items():
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                action_name="MyIngress.myTunnel_ingress",
                action_params={"dst_id": tunnel_id}
            )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
                print(f"Added IPv4 tunnel route: {sw_name} -> {dst_ip} via tunnel {tunnel_id}")
            except grpc.RpcError as e:
                print(f"Failed to add tunnel route {sw_name} -> {dst_ip}: {e}")
                # Try to modify if entry exists
                try:
                    self.switches[sw_name].ModifyTableEntry(table_entry)
                    print(f"Modified IPv4 tunnel route: {sw_name} -> {dst_ip} via tunnel {tunnel_id}")
                except grpc.RpcError as e2:
                    print(f"Failed to modify tunnel route {sw_name} -> {dst_ip}: {e2}")

    def _deploy_tunnel_rules(self):
        """Deploy tunnel forwarding rules"""
        # For tunnel 100: s1 -> s11 -> s12 -> s2 -> h2
        # s1 forwards to s11
        s1_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.myTunnel_exact",
            match_fields={"hdr.myTunnel.dst_id": 100},
            action_name="MyIngress.myTunnel_forward",
            action_params={"port": 2}  # s1 port 2 -> s11
        )
        self.switches['s1'].WriteTableEntry(s1_forward)
        print("Added tunnel forward: s1 tunnel 100 -> port 2 (s11)")

        # s11 forwards to s12
        s11_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.myTunnel_exact",
            match_fields={"hdr.myTunnel.dst_id": 100},
            action_name="MyIngress.myTunnel_forward",
            action_params={"port": 2}  # s11 port 2 -> s12
        )
        self.switches['s11'].WriteTableEntry(s11_forward)
        print("Added tunnel forward: s11 tunnel 100 -> port 2 (s12)")

        # s12 forwards to s2
        s12_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.myTunnel_exact",
            match_fields={"hdr.myTunnel.dst_id": 100},
            action_name="MyIngress.myTunnel_forward",
            action_params={"port": 2}  # s12 port 2 -> s2
        )
        self.switches['s12'].WriteTableEntry(s12_forward)
        print("Added tunnel forward: s12 tunnel 100 -> port 2 (s2)")

        # s2 egress to h2
        s2_egress = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.myTunnel_exact",
            match_fields={"hdr.myTunnel.dst_id": 100},
            action_name="MyIngress.myTunnel_egress",
            action_params={
                "dstAddr": "08:00:00:00:02:22",  # h2 MAC
                "port": 1  # s2 port 1 -> h2
            }
        )
        self.switches['s2'].WriteTableEntry(s2_egress)
        print("Added tunnel egress: s2 tunnel 100 -> h2 port 1")

        # For return path tunnel 101: s2 -> s12 -> s11 -> s1 -> h1
        # s2 forwards to s12
        s2_return_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.myTunnel_exact",
            match_fields={"hdr.myTunnel.dst_id": 101},
            action_name="MyIngress.myTunnel_forward",
            action_params={"port": 2}  # s2 port 2 -> s12
        )
        self.switches['s2'].WriteTableEntry(s2_return_forward)
        print("Added tunnel forward: s2 tunnel 101 -> port 2 (s12)")

        # s12 forwards to s11
        s12_return_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.myTunnel_exact",
            match_fields={"hdr.myTunnel.dst_id": 101},
            action_name="MyIngress.myTunnel_forward",
            action_params={"port": 1}  # s12 port 1 -> s11
        )
        self.switches['s12'].WriteTableEntry(s12_return_forward)
        print("Added tunnel forward: s12 tunnel 101 -> port 1 (s11)")

        # s11 forwards to s1
        s11_return_forward = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.myTunnel_exact",
            match_fields={"hdr.myTunnel.dst_id": 101},
            action_name="MyIngress.myTunnel_forward",
            action_params={"port": 1}  # s11 port 1 -> s1
        )
        self.switches['s11'].WriteTableEntry(s11_return_forward)
        print("Added tunnel forward: s11 tunnel 101 -> port 1 (s1)")

        # s1 egress to h1
        s1_egress = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.myTunnel_exact",
            match_fields={"hdr.myTunnel.dst_id": 101},
            action_name="MyIngress.myTunnel_egress",
            action_params={
                "dstAddr": "08:00:00:00:01:11",  # h1 MAC
                "port": 1  # s1 port 1 -> h1
            }
        )
        self.switches['s1'].WriteTableEntry(s1_egress)
        print("Added tunnel egress: s1 tunnel 101 -> h1 port 1")

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