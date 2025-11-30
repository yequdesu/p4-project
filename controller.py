#!/usr/bin/env python3
"""
IPv4 Controller for basic.p4 - Fixed for VXLAN Params and Rule Conflicts
"""

import argparse
import grpc
import os
import sys
import threading
import zlib
from time import sleep
from scapy.all import Ether, IP, UDP, TCP

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

        # Direct IPv4 routes
        self.ip_routes = {
            ('s1', "10.0.2.2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s11', "10.0.2.2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s12', "10.0.2.2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s2', "10.0.2.2"): ("08:00:00:00:02:22", 1),
            ('s1', "10.0.2.10"): ("ff:ff:ff:ff:ff:ff", 3), # Trigger IPv6 encap

            ('s1', "10.0.2.4"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s11', "10.0.2.4"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s12', "10.0.2.4"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s2', "10.0.2.4"): ("08:00:00:00:02:22", 1),

            ('s2', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s12', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s11', "10.0.1.1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s1', "10.0.1.1"): ("08:00:00:00:01:11", 1),

            ('s2', "10.0.1.3"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s12', "10.0.1.3"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s11', "10.0.1.3"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s1', "10.0.1.3"): ("08:00:00:00:01:11", 1),
        }

        self.yequdesu_routes = {
            ('s1', "10.0.2.4"): 300,
            ('s2', "10.0.1.3"): 301,
        }

        self.ipv6_routes = {
            ('s1', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 3),
            ('s11', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s12', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s21', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s22', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s31', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s32', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s41', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s42', "2001:db8:1::2"): ("ff:ff:ff:ff:ff:ff", 2),
            ('s2', "2001:db8:1::2"): ("08:00:00:00:02:22", 1),

            ('s2', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 3),
            ('s12', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s11', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s22', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s21', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s32', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s31', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s42', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s41', "2001:db8:1::1"): ("ff:ff:ff:ff:ff:ff", 1),
            ('s1', "2001:db8:1::1"): ("08:00:00:00:01:11", 1), # Decap
        }

        self.arp_rules = [
            ('s1', '10.0.1.10', '08:00:00:00:01:00'),
            ('s2', '10.0.2.20', '08:00:00:00:02:00'),
        ]

        self.vxlan_routes = {
            ('s1', "10.0.2.2"): (100, "ff:ff:ff:ff:ff:ff", 5),
            ('s2', "10.0.1.1"): (101, "ff:ff:ff:ff:ff:ff", 5),
        }

        self.vxlan_decap_rules = {
            100: ('s2', 5),
            101: ('s1', 5),
        }

    def initialize_switches(self):
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
                name=name, address=address, device_id=device_id,
                proto_dump_file=f'logs/{name}-p4runtime-requests.txt'
            )
            self.switches[name].MasterArbitrationUpdate()
            self.switches[name].SetForwardingPipelineConfig(
                p4info=self.p4info_helper.p4info,
                bmv2_json_file_path=self.bmv2_file_path
            )
            print(f"Switch {name} initialized")

    def deploy_forwarding_rules(self):
        self._deploy_ipv4_rules()
        self._deploy_ipv6_rules()
        self._deploy_yequdesu_rules()
        self._deploy_vxlan_rules()
        self._deploy_vxlan_transit_rules()
        self._deploy_arp_rules()
        print("All forwarding rules deployed")

    def _deploy_vxlan_transit_rules(self):
        """Deploy forwarding rules for VXLAN outer packets on intermediate switches"""
        # Intermediate switches config... (Keeping existing logic but wrapping in try-except for safety)
        switches_to_configure = {
            's11': [("10.0.2.10", 2), ("10.0.1.10", 1)],
            's12': [("10.0.2.10", 2), ("10.0.1.10", 1)],
            's21': [("10.0.2.10", 2), ("10.0.1.10", 1)],
            's22': [("10.0.2.10", 2), ("10.0.1.10", 1)],
            's31': [("10.0.2.10", 2), ("10.0.1.10", 1)],
            's32': [("10.0.2.10", 2), ("10.0.1.10", 1)],
            's41': [("10.0.2.10", 2), ("10.0.1.10", 1)],
            's42': [("10.0.2.10", 2), ("10.0.1.10", 1)],
        }

        for sw_name, rules in switches_to_configure.items():
            for ip, port in rules:
                try:
                    self.switches[sw_name].WriteTableEntry(self.p4info_helper.buildTableEntry(
                        table_name="MyIngress.ipv4_lpm",
                        match_fields={"hdr.ipv4.dstAddr": (ip, 32)},
                        action_name="MyIngress.ipv4_forward",
                        action_params={"dstAddr": "ff:ff:ff:ff:ff:ff", "port": port}))
                except Exception as e:
                    print(f"Error deploying VXLAN transit rule for {sw_name} ({ip}): {e}")
        
        print("VXLAN transit rules deployed.")

    def _deploy_ipv4_rules(self):
        for (sw_name, dst_ip), (dst_mac, port) in self.ip_routes.items():
            if sw_name == 's1' and dst_ip == "10.0.2.10":
                table_entry = self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.ipv4_lpm",
                    match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                    action_name="MyIngress.ipv6_encap_ipv4",
                    action_params={"dstAddr": dst_mac, "port": port}
                )
            else:
                table_entry = self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.ipv4_lpm",
                    match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                    action_name="MyIngress.ipv4_forward",
                    action_params={"dstAddr": dst_mac, "port": port}
                )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
            except Exception as e:
                print(f"Error deploying IPv4 rule for {sw_name} ({dst_ip}): {e}")

    def _deploy_yequdesu_rules(self):
        # Ingress
        for (sw_name, dst_ip), tunnel_id in self.yequdesu_routes.items():
            try:
                self.switches[sw_name].DeleteTableEntry(
                    self.p4info_helper.buildTableEntry(
                        table_name="MyIngress.ipv4_lpm",
                        match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                        action_name="MyIngress.ipv4_forward",
                        action_params={"dstAddr": "00:00:00:00:00:00", "port": 0}
                    )
                )
            except: pass
            
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
                action_name="MyIngress.yequdesu_ingress",
                action_params={"dst_id": tunnel_id}
            )
            try:
                self.switches[sw_name].WriteTableEntry(table_entry)
            except Exception as e:
                print(f"Error deploying Yequdesu ingress rule for {sw_name} ({dst_ip}): {e}")

        # Forwarding rules
        # [FIX] Only deploy one path for the exact match table to avoid conflicts
        
        # Path 1: s1->s11->s12->s2
        try:
            self.switches['s1'].WriteTableEntry(self.p4info_helper.buildTableEntry(
                table_name="MyIngress.yequdesu_exact", match_fields={"hdr.yequdesu.dst_id": 300},
                action_name="MyIngress.yequdesu_forward", action_params={"port": 2}))
        except Exception as e:
            print(f"Error deploying Yequdesu forward rule for s1 (dst_id: 300): {e}")

        # Configure intermediates for all paths, just in case
        for sw, port in [('s11', 2), ('s12', 2), ('s31', 2), ('s32', 2)]:
             try:
                self.switches[sw].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.yequdesu_exact", match_fields={"hdr.yequdesu.dst_id": 300},
                    action_name="MyIngress.yequdesu_forward", action_params={"port": port}))
             except: pass
        
        # S2 Egress
        try:
            self.switches['s2'].WriteTableEntry(self.p4info_helper.buildTableEntry(
                table_name="MyIngress.yequdesu_exact", match_fields={"hdr.yequdesu.dst_id": 300},
                action_name="MyIngress.yequdesu_egress", action_params={"dstAddr": "08:00:00:00:02:22", "port": 1}))
        except Exception as e:
            print(f"Error deploying Yequdesu egress rule for s2 (dst_id: 300): {e}")

        # Reverse path: s2 -> s1
        # [FIX] Only deploy one path (Path 1) for s2 to s1
        try:
            self.switches['s2'].WriteTableEntry(self.p4info_helper.buildTableEntry(
                table_name="MyIngress.yequdesu_exact", match_fields={"hdr.yequdesu.dst_id": 301},
                action_name="MyIngress.yequdesu_forward", action_params={"port": 2}))
        except Exception as e:
            print(f"Error deploying Yequdesu forward rule for s2 (dst_id: 301): {e}")

        # Configure intermediates for reverse
        for sw, port in [('s12', 1), ('s11', 1), ('s22', 1), ('s21', 1), ('s32', 1), ('s31', 1), ('s42', 1), ('s41', 1)]:
             try:
                self.switches[sw].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.yequdesu_exact", match_fields={"hdr.yequdesu.dst_id": 301},
                    action_name="MyIngress.yequdesu_forward", action_params={"port": port}))
             except: pass

        # S1 Egress
        try:
            self.switches['s1'].WriteTableEntry(self.p4info_helper.buildTableEntry(
                table_name="MyIngress.yequdesu_exact", match_fields={"hdr.yequdesu.dst_id": 301},
                action_name="MyIngress.yequdesu_egress", action_params={"dstAddr": "08:00:00:00:01:11", "port": 1}))
        except Exception as e:
            print(f"Error deploying Yequdesu egress rule for s1 (dst_id: 301): {e}")

    def _deploy_ipv6_rules(self):
        for (sw_name, dst_ipv6), (dst_mac, port) in self.ipv6_routes.items():
            if (sw_name == 's1' and dst_ipv6 == "2001:db8::1") or (sw_name == 's2' and dst_ipv6 == "2001:db8::2"):
                action_name = "MyIngress.ipv6_decap_ipv4"
            else:
                action_name = "MyIngress.ipv6_forward"

            try:
                self.switches[sw_name].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.ipv6_lpm",
                    match_fields={"hdr.ipv6.dstAddr": (dst_ipv6, 128)},
                    action_name=action_name,
                    action_params={"dstAddr": dst_mac, "port": port}
                ))
            except Exception as e:
                print(f"Error deploying IPv6 rule for {sw_name} ({dst_ipv6}): {e}")

    def _deploy_vxlan_rules(self):
        # [FIX] VTEP IPs for source/dest calculation
        vtep_ips = {
            's1': "10.0.1.10",
            's2': "10.0.2.10"
        }

        for (sw_name, inner_dst_ip), (vni, dst_mac, port) in self.vxlan_routes.items():
            # Calculate parameters for P4 action
            src_ip = vtep_ips.get(sw_name, "0.0.0.0")
            dst_ip = "10.0.2.10" if sw_name == 's1' else "10.0.1.10"

            try:
                self.switches[sw_name].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.vxlan_lpm",
                    match_fields={"hdr.ipv4.dstAddr": (inner_dst_ip, 32)},
                    action_name="MyIngress.vxlan_encap",
                    # [FIX] Include srcIp and dstIp to match P4 action signature
                    action_params={
                        "vni": vni, 
                        "dstAddr": dst_mac, 
                        "port": port,
                        "srcIp": src_ip,
                        "dstIp": dst_ip
                    }
                ))
            except Exception as e:
                print(f"Error deploying VXLAN encap rule for {sw_name} ({inner_dst_ip}): {e}")

        for vni, (sw_name, port) in self.vxlan_decap_rules.items():
            try:
                self.switches[sw_name].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.vxlan_decap_exact",
                    match_fields={"hdr.vxlan.vni": vni},
                    action_name="MyIngress.vxlan_decap",
                    action_params={}
                ))
            except Exception as e:
                print(f"Error deploying VXLAN decap rule for {sw_name} (vni: {vni}): {e}")

    def _deploy_arp_rules(self):
        for sw_name, target_ip, reply_mac in self.arp_rules:
            try:
                self.switches[sw_name].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.arp_match",
                    match_fields={"hdr.arp.oper": 1, "hdr.arp.tpa": (target_ip, 32)},
                    action_name="MyIngress.send_arp_reply",
                    action_params={"macAddr": reply_mac}
                ))
            except Exception as e:
                print(f"Error deploying ARP rule for {sw_name} ({target_ip}): {e}")

    def deploy_level4_rules(self):
            print("Deploying Level 4 rules...")
            # 1. Multicast groups (Ports 2-5)
            multicast_groups = {
                2: [{'egress_port': 3, 'instance': 1}, {'egress_port': 4, 'instance': 1}], 
                3: [{'egress_port': 3, 'instance': 1}, {'egress_port': 5, 'instance': 1}], 
                4: [{'egress_port': 4, 'instance': 1}, {'egress_port': 5, 'instance': 1}], 
                5: [{'egress_port': 3, 'instance': 1}, {'egress_port': 4, 'instance': 1}], 
                6: [{'egress_port': 3, 'instance': 1}, {'egress_port': 5, 'instance': 1}],
                7: [{'egress_port': 4, 'instance': 1}, {'egress_port': 5, 'instance': 1}]
            }
            for sw_name in ['s1', 's2']:
                for group_id, replicas in multicast_groups.items():
                    self.switches[sw_name].WritePREEntry(self.p4info_helper.buildMulticastGroupEntry(group_id, replicas))
            print("Multicast groups configured.")

            # 2. Modality Schedule (Ingress)
            for sw, dst in [('s1', "10.0.2.2"), ('s2', "10.0.1.1")]:
                self.switches[sw].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.modality_schedule",
                    match_fields={"hdr.ipv4.dstAddr": [dst]},
                    action_name="MyIngress.set_random_multimodal", action_params={}))

            # 3. Egress Encapsulation
            for sw, src_ipv6, dst_ipv6, y_id, v_id, v_src, v_dst in [
                ('s1', "2001:db8::1", "2001:db8::2", 300, 100, "10.0.1.10", "10.0.2.10"),
                ('s2', "2001:db8::2", "2001:db8::1", 301, 101, "10.0.2.10", "10.0.1.10")
            ]:
                self.switches[sw].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyEgress.egress_encap_ipv6", match_fields={"standard_metadata.egress_port": [3]},
                    action_name="MyEgress.encap_ipv6_egress", action_params={"src": src_ipv6, "dst": dst_ipv6}))
                self.switches[sw].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyEgress.egress_encap_yequdesu", match_fields={"standard_metadata.egress_port": [4]},
                    action_name="MyEgress.encap_yequdesu_egress", action_params={"dst_id": y_id}))
                self.switches[sw].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyEgress.egress_encap_vxlan", match_fields={"standard_metadata.egress_port": [5]},
                    action_name="MyEgress.encap_vxlan_egress", action_params={"vni": v_id, "src": v_src, "dst": v_dst}))

            # 4. Adjudication (Ingress) - Clone to CPU (Session 100)
            for sw, dst in [('s2', "10.0.2.2"), ('s1', "10.0.1.1")]:
                self.switches[sw].WriteTableEntry(self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.adjudication",
                    match_fields={"hdr.ipv4.dstAddr": [dst]},
                    action_name="MyIngress.clone_to_cpu",
                    action_params={"session_id": 100}))
                
            # 5. Configure Clone Session 100 to send to CPU (Port 255)
            try:
                clone_entry = self.p4info_helper.buildCloneSessionEntry(clone_session_id=100, replicas=[{'egress_port': 255, 'instance': 1}])
                self.switches['s1'].WritePREEntry(clone_entry)
                self.switches['s2'].WritePREEntry(clone_entry)
                print("Clone Session 100 configured on S1 and S2")
            except Exception as e:
                print(f"Error configuring Clone Session: {e}")

            print("Level 4 rules deployed.")

    def packet_in_handler(self, sw_name):
        """
        Handler: Expects duplicate packets due to hardware forwarding.
        Logic: Use sets to check consistency and forward one copy (though hardware already forwarded one).
        Since P4 code does NOT drop the original packet, we just use this for "Audit".
        """
        switch = self.switches[sw_name]
        print(f"[{sw_name}] Listener started...")

        flow_packets = {}

        while True:
            try:
                msg = switch.PacketIn()
                if msg.HasField("packet"):
                    packet = msg.packet
                    payload = packet.payload
                    
                    ingress_port = None
                    for meta in packet.metadata:
                        if meta.id == 1:
                            ingress_port = int.from_bytes(meta.value, 'big')
                            break
                    
                    if ingress_port is None: continue

                    pkt = Ether(payload)
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        ip_id = pkt[IP].id
                        
                        flow_key = (src, dst, ip_id)
                        
                        if flow_key not in flow_packets:
                            flow_packets[flow_key] = {}
                        
                        if ingress_port not in flow_packets[flow_key]:
                             flow_packets[flow_key][ingress_port] = payload
                             print(f"[{sw_name}] Recv ID:{ip_id} Port:{ingress_port} | Flows: {len(flow_packets)}")

                        if len(flow_packets[flow_key]) >= 2:
                            payloads = list(flow_packets[flow_key].values())
                            hashes = [zlib.crc32(p) for p in payloads]
                            
                            if len(set(hashes)) == 1:
                                print(f"[{sw_name}] AUDIT PASS: ID {ip_id} matched on {len(hashes)} ports.")
                                # No need to PacketOut since hardware forwarded it (we commented out drop())
                                del flow_packets[flow_key]
                            else:
                                print(f"[{sw_name}] AUDIT FAIL: ID {ip_id} hashes mismatch! {hashes}")
                                del flow_packets[flow_key]

            except Exception as e:
                print(f"[{sw_name}] Error: {e}")

    def run(self):
        print("IPv4 Controller running...")
        self.deploy_level4_rules()
        
        t1 = threading.Thread(target=self.packet_in_handler, args=('s1',))
        t2 = threading.Thread(target=self.packet_in_handler, args=('s2',))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()

        try:
            while True: sleep(1)
        except KeyboardInterrupt:
            print("\nController stopped")

    def cleanup(self):
        ShutdownAllSwitchConnections()

def main(p4info_file_path, bmv2_file_path):
    if not all(os.path.exists(f) for f in [p4info_file_path, bmv2_file_path]):
        print("Required P4 files not found.")
        return
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    controller = IPv4Controller(p4info_helper, bmv2_file_path)
    try:
        controller.initialize_switches()
        controller.deploy_forwarding_rules()
        controller.run()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        controller.cleanup()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--p4info', type=str, default='./build/basic.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', type=str, default='./build/basic.json')
    args = parser.parse_args()
    main(args.p4info, args.bmv2_json)