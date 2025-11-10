#!/usr/bin/env python3
"""
Enhanced Tunnel Controller with Link Statistics Logging
"""

import argparse
import grpc
import os
import sys
from datetime import datetime
from pathlib import Path
from time import sleep
from typing import Dict, List, Tuple

# Import P4Runtime libraries
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


class TunnelConfigManager:
    """Manages tunnel configuration and mappings"""
    
    def __init__(self):
        self.switch_to_host_port = 1
        # tunnel_id: (src_switch, dst_switch, output_port, dst_mac)
        self.tunnel_mappings = {
            100: ('s1', 's2', 2, "08:00:00:00:02:22"),
            101: ('s2', 's1', 2, "08:00:00:00:01:11"),
            200: ('s1', 's3', 3, "08:00:00:00:03:33"),
            201: ('s3', 's1', 2, "08:00:00:00:01:11"),
            300: ('s2', 's3', 3, "08:00:00:00:03:33"),
            301: ('s3', 's2', 3, "08:00:00:00:02:22")
        }
        
        # (switch, dst_ip): tunnel_id
        self.ip_routes = {
            ('s1', "10.0.2.2"): 100,
            ('s1', "10.0.3.3"): 200,
            ('s2', "10.0.1.1"): 101,
            ('s2', "10.0.3.3"): 300,
            ('s3', "10.0.1.1"): 201,
            ('s3', "10.0.2.2"): 301
        }
        
        # switch: (target_ip, reply_mac)
        self.arp_configs = {
            's1': ("10.0.1.10", "08:00:00:00:01:00"),
            's2': ("10.0.2.20", "08:00:00:00:02:00"),
            's3': ("10.0.3.30", "08:00:00:00:03:00")
        }


class LinkStatisticsLogger:
    """Logs link statistics to files"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.log_files = {}
        self.initialize_log_files()
    
    def initialize_log_files(self):
        """Create log files for each link"""
        link_pairs = ['s1s2', 's1s3', 's2s3']
        for link in link_pairs:
            log_file = self.log_dir / f"{link}.txt"
            self.log_files[link] = open(log_file, 'w', encoding='utf-8')
            self.log_files[link].write(f"# {link} link statistics - Started: {datetime.now()}\n")
            self.log_files[link].flush()
    
    def log_link_statistics(self, counter_data: Dict):
        """Log statistics for all links"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for link_name, tunnels in self._get_link_tunnels().items():
            log_entries = []
            
            for tunnel_id, direction in tunnels:
                if tunnel_id in counter_data:
                    ingress_sw, egress_sw = self._get_switches_from_tunnel(tunnel_id)
                    packet_count = counter_data[tunnel_id]
                    
                    if direction == 'ingress':
                        log_entries.append(f"{egress_sw} received {packet_count} packets, counter ID: {tunnel_id}")
                        log_entries.append(f"{ingress_sw} sent {packet_count} packets, counter ID: {tunnel_id}")
                    else:
                        log_entries.append(f"{egress_sw} received {packet_count} packets, counter ID: {tunnel_id}")
                        log_entries.append(f"{ingress_sw} sent {packet_count} packets, counter ID: {tunnel_id}")
                    
                    log_entries.append(f"{ingress_sw}->{egress_sw}")
            
            if log_entries:
                log_file = self.log_files[link_name]
                log_file.write(f"\n# {timestamp}\n")
                for i, entry in enumerate(log_entries, 1):
                    log_file.write(f"{i}{entry}\n")
                log_file.flush()
    
    def _get_link_tunnels(self) -> Dict:
        """Get tunnels for each link"""
        return {
            's1s2': [(100, 'ingress'), (101, 'ingress')],
            's1s3': [(200, 'ingress'), (201, 'ingress')],
            's2s3': [(300, 'ingress'), (301, 'ingress')]
        }
    
    def _get_switches_from_tunnel(self, tunnel_id: int) -> Tuple[str, str]:
        """Get source and destination switches from tunnel ID"""
        config_manager = TunnelConfigManager()
        src_sw, dst_sw, _, _ = config_manager.tunnel_mappings[tunnel_id]
        return src_sw, dst_sw
    
    def close_all(self):
        """Close all log files"""
        for log_file in self.log_files.values():
            log_file.close()


class TunnelController:
    """Main tunnel controller class"""
    
    def __init__(self, p4info_helper, bmv2_file_path):
        self.p4info_helper = p4info_helper
        self.bmv2_file_path = bmv2_file_path
        self.config_manager = TunnelConfigManager()
        self.logger = LinkStatisticsLogger()
        self.switches = {}
    
    def initialize_switches(self):
        """Initialize switch connections"""
        switch_configs = [
            ('s1', '127.0.0.1:50051', 0),
            ('s2', '127.0.0.1:50052', 1),
            ('s3', '127.0.0.1:50053', 2)
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
        """Deploy IPv4 routing rules"""
        for (sw_name, dst_ip), tunnel_id in self.config_manager.ip_routes.items():
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                action_name="MyIngress.myTunnel_ingress",
                action_params={"dst_id": tunnel_id}
            )
            self.switches[sw_name].WriteTableEntry(table_entry)
    
    def _deploy_tunnel_rules(self):
        """Deploy tunnel forwarding rules"""
        for tunnel_id, (ingress_sw, egress_sw, port, dst_mac) in self.config_manager.tunnel_mappings.items():
            # Forward rule
            forward_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.myTunnel_exact",
                match_fields={"hdr.myTunnel.dst_id": tunnel_id},
                action_name="MyIngress.myTunnel_forward",
                action_params={"port": port}
            )
            self.switches[ingress_sw].WriteTableEntry(forward_entry)
            
            # Egress rule
            egress_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.myTunnel_exact",
                match_fields={"hdr.myTunnel.dst_id": tunnel_id},
                action_name="MyIngress.myTunnel_egress",
                action_params={
                    "dstAddr": dst_mac,
                    "port": self.config_manager.switch_to_host_port
                }
            )
            self.switches[egress_sw].WriteTableEntry(egress_entry)
    
    def _deploy_arp_rules(self):
        """Deploy ARP response rules"""
        for sw_name, (target_ip, reply_mac) in self.config_manager.arp_configs.items():
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.arp_match",
                match_fields={
                    "hdr.arp.oper": [1],
                    "hdr.arp.tpa": [target_ip, 32]
                },
                action_name="MyIngress.send_arp_reply",
                action_params={"macAddr": reply_mac}
            )
            self.switches[sw_name].WriteTableEntry(table_entry)
    
    def collect_counter_data(self) -> Dict[int, int]:
        """Collect counter data from all switches"""
        counter_data = {}
        
        for tunnel_id in self.config_manager.tunnel_mappings.keys():
            ingress_sw, egress_sw, _, _ = self.config_manager.tunnel_mappings[tunnel_id]
            
            ingress_count = self._read_counter(self.switches[ingress_sw], 
                                             "MyIngress.ingressTunnelCounter", tunnel_id)
            egress_count = self._read_counter(self.switches[egress_sw],
                                            "MyIngress.egressTunnelCounter", tunnel_id)
            
            counter_data[tunnel_id] = ingress_count if ingress_count > 0 else egress_count
        
        return counter_data
    
    def _read_counter(self, switch, counter_name: str, index: int) -> int:
        """Read single counter value"""
        try:
            for response in switch.ReadCounters(
                self.p4info_helper.get_counters_id(counter_name), index):
                for entity in response.entities:
                    return entity.counter_entry.data.packet_count
        except:
            pass
        return 0
    
    def display_current_stats(self):
        """Display current statistics to console"""
        print(f"\nLink Statistics - {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 40)
        
        counter_data = self.collect_counter_data()
        
        for link_name, tunnels in self.logger._get_link_tunnels().items():
            total_packets = 0
            for tunnel_id, _ in tunnels:
                total_packets += counter_data.get(tunnel_id, 0)
            
            if total_packets > 0:
                print(f"{link_name}: {total_packets} packets")
    
    def run_monitoring_loop(self):
        """Run monitoring loop"""
        print("\nStarting link traffic monitoring...")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                counter_data = self.collect_counter_data()
                self.logger.log_link_statistics(counter_data)
                self.display_current_stats()
                sleep(2)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped")
    
    def cleanup(self):
        """Cleanup resources"""
        self.logger.close_all()
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
    controller = TunnelController(p4info_helper, bmv2_file_path)
    
    try:
        # Execute controller workflow
        controller.initialize_switches()
        controller.deploy_forwarding_rules()
        controller.run_monitoring_loop()
        
    except grpc.RpcError as e:
        printGrpcError(e)
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        controller.cleanup()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enhanced Tunnel Controller with Link Statistics')
    parser.add_argument('--p4info', help='P4Info file path',
                        type=str, default='./build/advanced_tunnel_arp.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file path',
                        type=str, default='./build/advanced_tunnel_arp.json')
    
    args = parser.parse_args()
    main(args.p4info, args.bmv2_json)
