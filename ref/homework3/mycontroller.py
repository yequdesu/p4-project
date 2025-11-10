#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


class SwitchController:
    """Controller for managing P4 switch configurations"""
    
    def __init__(self, p4info_helper):
        self.p4info_helper = p4info_helper
        self.switches = {}
    
    def add_switch(self, name, address, device_id, log_file=None):
        """Add a switch connection"""
        if not log_file:
            log_file = f'logs/{name}-p4runtime-requests.txt'
        
        self.switches[name] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=name,
            address=address,
            device_id=device_id,
            proto_dump_file=log_file
        )
        return self.switches[name]
    
    def initialize_switches(self):
        """Initialize all switches with master arbitration and pipeline config"""
        for switch in self.switches.values():
            switch.MasterArbitrationUpdate()
        
        for switch in self.switches.values():
            switch.SetForwardingPipelineConfig(
                p4info=self.p4info_helper.p4info,
                bmv2_json_file_path=self.bmv2_file_path
            )
    
    def write_ecmp_group_rule(self, switch_name, dst_addr, prefix_len, ecmp_base, ecmp_count):
        """Write ECMP group rule"""
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ecmp_group",
            match_fields={
                "hdr.ipv4.dstAddr": [dst_addr, prefix_len]
            },
            action_name="MyIngress.set_ecmp_select",
            action_params={
                "ecmp_base": ecmp_base,
                "ecmp_count": ecmp_count
            }
        )
        self.switches[switch_name].WriteTableEntry(table_entry)
    
    def write_ecmp_nhop_rule(self, switch_name, ecmp_select, nhop_dmac, nhop_ipv4, port):
        """Write ECMP next hop rule"""
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ecmp_nhop",
            match_fields={
                "meta.ecmp_select": ecmp_select
            },
            action_name="MyIngress.set_nhop",
            action_params={
                "nhop_dmac": nhop_dmac,
                "nhop_ipv4": nhop_ipv4,
                "port": port
            }
        )
        self.switches[switch_name].WriteTableEntry(table_entry)
    
    def write_ipv4_lpm_rule(self, switch_name, dst_addr, prefix_len, dst_mac, port):
        """Write IPv4 LPM rule"""
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": [dst_addr, prefix_len]
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": dst_mac,
                "port": port
            }
        )
        self.switches[switch_name].WriteTableEntry(table_entry)


def configure_edge_switches(controller):
    """Configure ECMP rules for edge switches (s1 and s6)"""
    # Switch s1 configuration
    controller.write_ecmp_group_rule('s1', '10.0.0.1', 32, 0, 4)
    for i, (dmac, port) in enumerate([
        ('00:00:00:00:01:02', 2),
        ('00:00:00:00:01:03', 3),
        ('00:00:00:00:01:04', 4),
        ('00:00:00:00:01:05', 5)
    ]):
        controller.write_ecmp_nhop_rule('s1', i, dmac, '10.0.2.2', port)
    controller.write_ipv4_lpm_rule('s1', '10.0.1.1', 32, '08:00:00:00:01:01', 1)
    
    # Switch s6 configuration
    controller.write_ecmp_group_rule('s6', '10.0.0.2', 32, 0, 4)
    for i, (dmac, port) in enumerate([
        ('00:00:00:00:06:02', 2),
        ('00:00:00:00:06:03', 3),
        ('00:00:00:00:06:04', 4),
        ('00:00:00:00:06:05', 5)
    ]):
        controller.write_ecmp_nhop_rule('s6', i, dmac, '10.0.1.1', port)
    controller.write_ipv4_lpm_rule('s6', '10.0.2.2', 32, '08:00:00:00:02:02', 1)


def configure_core_switches(controller):
    """Configure basic forwarding rules for core switches (s2, s3, s4, s5)"""
    core_switches = ['s2', 's3', 's4', 's5']
    
    for switch_name in core_switches:
        controller.write_ipv4_lpm_rule(switch_name, '10.0.1.1', 32, '08:00:00:00:01:01', 1)
        controller.write_ipv4_lpm_rule(switch_name, '10.0.2.2', 32, '08:00:00:00:02:02', 2)


def main(p4info_file_path, bmv2_file_path):
    """Main function to setup P4 switches"""
    # Instantiate P4Runtime helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    
    # Create switch controller
    controller = SwitchController(p4info_helper)
    controller.bmv2_file_path = bmv2_file_path
    
    try:
        # Add all switches
        switches_config = [
            ('s1', '127.0.0.1:50051', 0),
            ('s2', '127.0.0.1:50052', 1),
            ('s3', '127.0.0.1:50053', 2),
            ('s4', '127.0.0.1:50054', 3),
            ('s5', '127.0.0.1:50055', 4),
            ('s6', '127.0.0.1:50056', 5)
        ]
        
        for name, addr, device_id in switches_config:
            controller.add_switch(name, addr, device_id)
        
        # Initialize all switches
        controller.initialize_switches()
        
        # Configure switch rules
        configure_edge_switches(controller)
        configure_core_switches(controller)
        
        print("All switch configurations completed successfully!")
        
    except KeyboardInterrupt:
        print("\nShutting down controller...")
    except grpc.RpcError as e:
        printGrpcError(e)
    finally:
        ShutdownAllSwitchConnections()


def validate_file_paths(p4info_path, bmv2_json_path):
    """Validate that required files exist"""
    if not os.path.exists(p4info_path):
        raise FileNotFoundError(f"P4Info file not found: {p4info_path}\nHave you run 'make'?")
    if not os.path.exists(bmv2_json_path):
        raise FileNotFoundError(f"BMv2 JSON file not found: {bmv2_json_path}\nHave you run 'make'?")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller for Load Balancing')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, default='./build/load_balance.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, default='./build/load_balance.json')
    
    args = parser.parse_args()
    
    try:
        validate_file_paths(args.p4info, args.bmv2_json)
        main(args.p4info, args.bmv2_json)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
