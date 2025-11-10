#!/usr/bin/env python3
"""
P4Runtime Controller for Source Routing Implementation
"""

import argparse
import grpc
import os
import sys
from typing import Dict, List, Tuple, Any

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


class SwitchConfig:
    """Configuration for switch connections"""
    SWITCHES = [
        {'name': 's1', 'address': '127.0.0.1:50051', 'device_id': 0},
        {'name': 's2', 'address': '127.0.0.1:50052', 'device_id': 1},
        {'name': 's3', 'address': '127.0.0.1:50053', 'device_id': 2}
    ]


class RoutingTableManager:
    """Manages routing table entries for source routing"""
    
    @staticmethod
    def write_table_entry(p4info_helper, switch, table_name: str, 
                         match_fields: Dict, action_name: str, 
                         action_params: Dict[str, Any]) -> None:
        """Write a generic table entry to switch"""
        table_entry = p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            action_name=action_name,
            action_params=action_params
        )
        switch.WriteTableEntry(table_entry)
    
    @staticmethod
    def write_mac_rewrite_rules(p4info_helper, switch, 
                               destination_ip: str, prefix_len: int,
                               mac_address: str) -> None:
        """Write MAC address rewrite rules"""
        RoutingTableManager.write_table_entry(
            p4info_helper=p4info_helper,
            switch=switch,
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": [destination_ip, prefix_len]},
            action_name="MyIngress.rewriteMac",
            action_params={"dstAddr": mac_address}
        )
    
    @staticmethod
    def write_source_routing_rules(p4info_helper, switch, 
                                  destination_ip: str, prefix_len: int,
                                  action_name: str, hop_params: Dict[str, Any]) -> None:
        """Write source routing table entries"""
        RoutingTableManager.write_table_entry(
            p4info_helper=p4info_helper,
            switch=switch,
            table_name="MyIngress.src_routing_publish",
            match_fields={"hdr.ipv4.dstAddr": [destination_ip, prefix_len]},
            action_name=action_name,
            action_params=hop_params
        )


class RoutingConfiguration:
    """Centralized routing configuration for all switches"""
    
    # Host configurations
    HOST_CONFIGS = {
        'h1': {'ip': '10.0.1.1', 'mac': '08:00:00:00:01:11'},
        'h2': {'ip': '10.0.2.2', 'mac': '08:00:00:00:02:22'},
        'h3': {'ip': '10.0.3.3', 'mac': '08:00:00:00:03:33'}
    }
    
    # Switch routing rules
    SWITCH_ROUTING_RULES = {
        's1': [
            # 1-hop routes
            ('10.0.1.1', 32, 'MyIngress.add_head_1', {'bos1': 1, 'port1': 1}),
            # 2-hop routes
            ('10.0.2.2', 32, 'MyIngress.add_head_2', {'bos1': 0, 'port1': 2, 'bos2': 1, 'port2': 1}),
            ('10.0.3.3', 32, 'MyIngress.add_head_2', {'bos1': 0, 'port1': 3, 'bos2': 1, 'port2': 1})
        ],
        's2': [
            # 1-hop routes
            ('10.0.2.2', 32, 'MyIngress.add_head_1', {'bos1': 1, 'port1': 1}),
            # 2-hop routes
            ('10.0.1.1', 32, 'MyIngress.add_head_2', {'bos1': 0, 'port1': 2, 'bos2': 1, 'port2': 1}),
            ('10.0.3.3', 32, 'MyIngress.add_head_2', {'bos1': 0, 'port1': 3, 'bos2': 1, 'port2': 1})
        ],
        's3': [
            # 1-hop routes
            ('10.0.3.3', 32, 'MyIngress.add_head_1', {'bos1': 1, 'port1': 1}),
            # 2-hop routes
            ('10.0.1.1', 32, 'MyIngress.add_head_2', {'bos1': 0, 'port1': 2, 'bos2': 1, 'port2': 1}),
            ('10.0.2.2', 32, 'MyIngress.add_head_2', {'bos1': 0, 'port1': 3, 'bos2': 1, 'port2': 1})
        ]
    }


class SwitchManager:
    """Manages switch connections and operations"""
    
    def __init__(self, p4info_helper, bmv2_file_path: str):
        self.p4info_helper = p4info_helper
        self.bmv2_file_path = bmv2_file_path
        self.switches = {}
    
    def initialize_switches(self) -> None:
        """Initialize all switch connections and set up forwarding pipeline"""
        print("Initializing switch connections...")
        
        for switch_config in SwitchConfig.SWITCHES:
            self._create_switch_connection(switch_config)
        
        # Establish controller as master and install P4 program
        for switch_name, switch in self.switches.items():
            print(f"Setting up {switch_name}...")
            switch.MasterArbitrationUpdate()
            switch.SetForwardingPipelineConfig(
                p4info=self.p4info_helper.p4info,
                bmv2_json_file_path=self.bmv2_file_path
            )
    
    def _create_switch_connection(self, config: Dict) -> None:
        """Create a switch connection with logging"""
        proto_dump_file = f"logs/{config['name']}-p4runtime-requests.txt"
        self.switches[config['name']] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=config['name'],
            address=config['address'],
            device_id=config['device_id'],
            proto_dump_file=proto_dump_file
        )
    
    def configure_routing_tables(self) -> None:
        """Configure all routing tables on switches"""
        print("Configuring routing tables...")
        
        # Configure source routing tables
        self._configure_source_routing()
        
        # Configure MAC rewrite tables
        self._configure_mac_rewrite()
        
        print("Routing configuration completed successfully.")
    
    def _configure_source_routing(self) -> None:
        """Configure source routing tables"""
        for switch_name, routing_rules in RoutingConfiguration.SWITCH_ROUTING_RULES.items():
            switch = self.switches[switch_name]
            print(f"Configuring source routing for {switch_name}...")
            
            for dest_ip, prefix_len, action_name, hop_params in routing_rules:
                RoutingTableManager.write_source_routing_rules(
                    p4info_helper=self.p4info_helper,
                    switch=switch,
                    destination_ip=dest_ip,
                    prefix_len=prefix_len,
                    action_name=action_name,
                    hop_params=hop_params
                )
    
    def _configure_mac_rewrite(self) -> None:
        """Configure MAC address rewrite tables"""
        print("Configuring MAC rewrite tables...")
        
        # Each switch handles MAC rewrite for its directly connected host
        mac_rewrite_configs = [
            ('s1', '10.0.1.1', 32, RoutingConfiguration.HOST_CONFIGS['h1']['mac']),
            ('s2', '10.0.2.2', 32, RoutingConfiguration.HOST_CONFIGS['h2']['mac']),
            ('s3', '10.0.3.3', 32, RoutingConfiguration.HOST_CONFIGS['h3']['mac'])
        ]
        
        for switch_name, dest_ip, prefix_len, mac_addr in mac_rewrite_configs:
            RoutingTableManager.write_mac_rewrite_rules(
                p4info_helper=self.p4info_helper,
                switch=self.switches[switch_name],
                destination_ip=dest_ip,
                prefix_len=prefix_len,
                mac_address=mac_addr
            )


def validate_file_paths(p4info_path: str, bmv2_json_path: str) -> None:
    """Validate that required files exist"""
    if not os.path.exists(p4info_path):
        raise FileNotFoundError(f"p4info file not found: {p4info_path}")
    if not os.path.exists(bmv2_json_path):
        raise FileNotFoundError(f"BMv2 JSON file not found: {bmv2_json_path}")


def print_routing_summary() -> None:
    """Print a summary of the configured routing"""
    print("\n" + "="*50)
    print("Source Routing Configuration Summary")
    print("="*50)
    
    for host_name, config in RoutingConfiguration.HOST_CONFIGS.items():
        print(f"Host {host_name}: IP={config['ip']}, MAC={config['mac']}")
    
    print("\nSwitch Routing Rules:")
    for switch_name, rules in RoutingConfiguration.SWITCH_ROUTING_RULES.items():
        print(f"\n{switch_name}:")
        for dest_ip, prefix_len, action, params in rules:
            hop_count = action.split('_')[-1]  # Extract hop count from action name
            print(f"  {dest_ip}/{prefix_len} -> {action} (params: {params})")


def main(p4info_file_path: str, bmv2_file_path: str) -> None:
    """Main controller function"""
    validate_file_paths(p4info_file_path, bmv2_file_path)
    
    # Initialize P4Runtime helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    
    try:
        # Set up switch manager
        switch_manager = SwitchManager(p4info_helper, bmv2_file_path)
        switch_manager.initialize_switches()
        
        # Configure routing tables
        switch_manager.configure_routing_tables()
        
        # Print configuration summary
        print_routing_summary()
        
        print("\nSource routing controller is running. Press Ctrl+C to exit.")
        
        # Keep the controller running
        while True:
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down source routing controller.")
    except grpc.RpcError as e:
        printGrpcError(e)
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='P4Runtime Controller for Source Routing',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        '--p4info',
        help='p4info proto in text format from p4c',
        type=str,
        default='./build/source_routing_v2.p4.p4info.txtpb'
    )
    
    parser.add_argument(
        '--bmv2-json',
        help='BMv2 JSON file from p4c',
        type=str,
        default='./build/source_routing_v2.json'
    )
    
    args = parser.parse_args()
    
    try:
        main(args.p4info, args.bmv2_json)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Have you run 'make' to build the required files?")
        sys.exit(1)
