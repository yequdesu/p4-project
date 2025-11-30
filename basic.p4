// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_YEQUDESU = 0x1313;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_SRCROUTING = 0x0900;
#define MAX_HOPS 9
const bit<8> TYPE_UDP = 17;
const bit<16> VXLAN_PORT = 4789;

// ARP opcodes needed for processing
const bit<16> ARP_OPER_REPLY = 2;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> udpPort_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header yequdesu_t {
    bit<16> proto_id;
    bit<16> dst_id;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header arp_t {
    bit<16> htype; 
    bit<16> ptype; 
    bit<8>  hlen; 
    bit<8>  plen; 
    bit<16> oper; 
    macAddr_t sha; 
    ip4Addr_t spa; 
    macAddr_t tha; 
    ip4Addr_t tpa; 
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payLoadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    bit<128>  srcAddr;
    bit<128>  dstAddr;
}

header udp_t {
    udpPort_t srcPort;
    udpPort_t dstPort;
    bit<16>   length;
    bit<16>   checksum;
}

header vxlan_t {
    bit<8>  flags;
    bit<24> reserved1;
    bit<24> vni;
    bit<8>  reserved2;
}

struct metadata {
    ip4Addr_t dst_ipv4; // dst ip for ARP
    bit<1> do_multimodal;
    bit<3> selected_modalities;
    // 标志位：判断是否为解封装后的包
    bit<1> is_tunnel_packet;
}

struct headers {
    ethernet_t              ethernet;
    yequdesu_t              yequdesu;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    arp_t                   arp;
    ipv4_t                  ipv4;
    ipv6_t                  ipv6;
    udp_t                   udp;
    vxlan_t                 vxlan;
    ethernet_t              inner_ethernet;
    ipv4_t                  inner_ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_YEQUDESU: parse_yequdesu;
            TYPE_SRCROUTING: parse_srcRouting;
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            VXLAN_PORT: parse_vxlan;
            default: accept;
        }
    }

    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            TYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition accept;
    }

    state parse_yequdesu {
        packet.extract(hdr.yequdesu);
        transition select(hdr.yequdesu.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;  // save dst ip for ARP
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            4: parse_ipv4;  // IPv4 encapsulated in IPv6
            default: accept;
        }
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1: parse_ipv4;
            default: parse_srcRouting;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    action ipv6_decap_ipv4(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ipv6.setInvalid();
        // 标记为隧道解封包
        meta.is_tunnel_packet = 1;
    }

    action yequdesu_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action yequdesu_egress(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = hdr.yequdesu.proto_id;
        hdr.yequdesu.setInvalid();
        // 标记为隧道解封包
        meta.is_tunnel_packet = 1;
    }

    action yequdesu_ingress(bit<16> dst_id) {
        hdr.yequdesu.setValid();
        hdr.yequdesu.dst_id = dst_id;
        hdr.yequdesu.proto_id = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_YEQUDESU;
    }

    action ipv6_encap_ipv4(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = TYPE_IPV6;

        hdr.ipv6.setValid();
        hdr.ipv6.version = 6;
        hdr.ipv6.trafficClass = 0;
        hdr.ipv6.flowLabel = 0;
        hdr.ipv6.payLoadLen = hdr.ipv4.totalLen;
        hdr.ipv6.nextHdr = 4; // IPv4
        hdr.ipv6.hopLimit = 64;
        hdr.ipv6.srcAddr = 0x20010DB8000000000000000000000001; // 2001:db8::1
        hdr.ipv6.dstAddr = 0x20010DB8000000000000000000000002; // 2001:db8::2

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_random_multimodal() {
        bit<32> hash_val;
        // [FIX] 使用 hash extern 的 max 参数 (32w6) 来限制范围为 [0, 5]
        // 避免使用 % 运算符导致编译错误
        hash(hash_val, HashAlgorithm.crc32, 32w0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.identification, standard_metadata.ingress_global_timestamp}, 32w6);
        
        bit<16> choice = (bit<16>)hash_val; // hash_val 现在保证在 0-5 之间
        standard_metadata.mcast_grp = choice + 2; // 映射到组 2-7
        
        meta.do_multimodal = 1;
        hdr.ipv4.ttl = 100;
    }

    action clone_to_cpu(bit<32> session_id) {
        clone(CloneType.I2E, session_id);
        // drop(); // Clone 后丢弃原包
    }

    table modality_schedule {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { set_random_multimodal; NoAction; }
        default_action = NoAction();
    }

    table adjudication {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { clone_to_cpu; NoAction; }
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            ipv6_encap_ipv4;
            yequdesu_ingress;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            ipv6_decap_ipv4;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // Source routing actions
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }
    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }
    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    // [FIX] 移除了未使用的 table src_routing_publish 及其关联 action
    // 以避免编译器警告
    
    action rewriteMac(macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = dstAddr;
    }

    table yequdesu_exact {
        key = {
            hdr.yequdesu.dst_id: exact;
        }
        actions = {
            yequdesu_forward;
            yequdesu_egress;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table ipv4_lpm_src {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            rewriteMac;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action send_arp_reply(macAddr_t macAddr) {
        hdr.ethernet.dstAddr = hdr.arp.sha;
        hdr.ethernet.srcAddr = macAddr;
        hdr.arp.oper = ARP_OPER_REPLY;
        hdr.arp.tha = hdr.arp.sha;
        hdr.arp.tpa = hdr.arp.spa;
        hdr.arp.sha = macAddr;
        hdr.arp.spa = meta.dst_ipv4;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action vxlan_encap(bit<24> vni, macAddr_t dstAddr, egressSpec_t port, ip4Addr_t srcIp, ip4Addr_t dstIp) {
        standard_metadata.egress_spec = port;
        
        // 保存内层
        hdr.inner_ethernet = hdr.ethernet;
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.inner_ethernet.setValid();
        hdr.inner_ipv4.setValid();

        // 外层 Ethernet
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = TYPE_IPV4;

        // 外层 IPv4
        hdr.ipv4.setValid();
        hdr.ipv4.version = 4;
        hdr.ipv4.ihl = 5;
        hdr.ipv4.diffserv = 0;
        hdr.ipv4.totalLen = hdr.inner_ipv4.totalLen + 50; 
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = TYPE_UDP;
        hdr.ipv4.srcAddr = srcIp; // 使用参数
        hdr.ipv4.dstAddr = dstIp; // 使用参数

        // UDP 和 VXLAN 设置同上...
        hdr.udp.setValid();
        hdr.udp.srcPort = 4789;
        hdr.udp.dstPort = 4789;
        hdr.udp.length = hdr.ipv4.totalLen - 20;
        hdr.udp.checksum = 0;

        hdr.vxlan.setValid();
        hdr.vxlan.flags = 0x08;
        hdr.vxlan.reserved1 = 0;
        hdr.vxlan.vni = vni;
        hdr.vxlan.reserved2 = 0;
    }

    action vxlan_decap() {
        hdr.vxlan.setInvalid();
        hdr.udp.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv4.setInvalid();
        // 标记为隧道解封包
        meta.is_tunnel_packet = 1;
    }

    table arp_match {
        key = {
            hdr.arp.oper: exact;
            hdr.arp.tpa: lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    table vxlan_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            vxlan_encap;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table vxlan_decap_exact {
        key = {
            hdr.vxlan.vni: exact;
        }
        actions = {
            vxlan_decap;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        bit<1> is_processed = 0;

        // 1. 处理 L2/ARP/Source Routing
        if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_match.apply();
            is_processed = 1;
        }
        else if (hdr.ethernet.etherType == TYPE_SRCROUTING) {
            if (hdr.srcRoutes[0].isValid()){
                if (hdr.srcRoutes[0].bos == 1){
                    srcRoute_finish();
                    if (hdr.ipv4.isValid()){
                        ipv4_lpm_src.apply();
                    }
                }
                srcRoute_nhop();
                update_ttl();
            }
            is_processed = 1;
        }

        // 2. 隧道解封装检查 (逻辑并行)
        if (is_processed == 0) {
            if (hdr.ethernet.etherType == TYPE_YEQUDESU && hdr.yequdesu.isValid()) {
                yequdesu_exact.apply(); // 可能执行 decap
            }
            else if (hdr.vxlan.isValid()) {
                vxlan_decap_exact.apply(); // 执行 decap
            }
            else if (hdr.ipv6.isValid()) {
                ipv6_lpm.apply(); // 可能执行 decap
            }
        }

        // 3. IPv4 核心处理
        if (is_processed == 0 && hdr.ipv4.isValid()) {
            
            // 裁决逻辑：如果是刚刚解封的隧道包，进入裁决表
            if (meta.is_tunnel_packet == 1) {
                adjudication.apply(); 
            }
            // [修改点] 调度逻辑：如果是原生包，且 *不是* 控制面发回的包 (Port 255)，才进行调度
            else {
                // 假设 CPU 端口是 255 (BMv2 默认)
                if (standard_metadata.ingress_port != 255) {
                    modality_schedule.apply();
                }
            }
            
            // 转发逻辑
            if (meta.do_multimodal == 0) {
                 // 如果是 VXLAN 封装
                if (vxlan_lpm.apply().hit) {
                    // 已处理
                } else {
                    ipv4_lpm.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action encap_ipv6_egress(bit<128> src, bit<128> dst) {
        hdr.ethernet.etherType = TYPE_IPV6;
        hdr.ipv6.setValid();
        hdr.ipv6.version = 6;
        hdr.ipv6.trafficClass = 0;
        hdr.ipv6.flowLabel = 0;
        hdr.ipv6.payLoadLen = hdr.ipv4.totalLen;
        hdr.ipv6.nextHdr = 4; // IPv4
        hdr.ipv6.hopLimit = 64;
        hdr.ipv6.srcAddr = src;
        hdr.ipv6.dstAddr = dst;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.etherType = 0x86dd;
    }

    action encap_yequdesu_egress(bit<16> dst_id) {
        hdr.yequdesu.setValid();
        hdr.yequdesu.dst_id = dst_id;
        hdr.yequdesu.proto_id = 0x800; // IPv4
        hdr.ethernet.etherType = TYPE_YEQUDESU;
    }

    action encap_vxlan_egress(bit<24> vni, ip4Addr_t src, ip4Addr_t dst) {
        // 1. 保存内层头部 (Critical Fix)
        hdr.inner_ethernet = hdr.ethernet;
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.inner_ethernet.setValid();
        hdr.inner_ipv4.setValid();

        // 2. 构建外层 Ethernet
        hdr.ethernet.etherType = TYPE_IPV4;
        // 注意：此处通常需要修改 Ethernet MAC 以指向下一跳网关
        // 但根据现有逻辑，IPv6封装也没改MAC且能通，可能依赖环境宽容或ARP
        // 这里保持原样仅修改 Type

        // 3. 构建外层 IPv4
        hdr.ipv4.setValid(); // 重新标记为 Valid (作为外层)
        hdr.ipv4.version = 4;
        hdr.ipv4.ihl = 5;
        hdr.ipv4.diffserv = 0;
        // Total Length = InnerEth(14) + InnerIP(Len) + UDP(8) + VXLAN(8) + OuterIP(20) = InnerIP + 50
        hdr.ipv4.totalLen = hdr.inner_ipv4.totalLen + 50; 
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = TYPE_UDP;
        hdr.ipv4.srcAddr = src;
        hdr.ipv4.dstAddr = dst;
        // hdr.ipv4.hdrChecksum 由 Deparser/Checksum 计算

        // 4. 构建 UDP
        hdr.udp.setValid();
        hdr.udp.srcPort = 4789; // 或使用 hash
        hdr.udp.dstPort = 4789;
        hdr.udp.length = hdr.ipv4.totalLen - 20; // UDP length excludes IP header
        hdr.udp.checksum = 0;

        // 5. 构建 VXLAN
        hdr.vxlan.setValid();
        hdr.vxlan.flags = 0x08;
        hdr.vxlan.reserved1 = 0;
        hdr.vxlan.vni = vni;
        hdr.vxlan.reserved2 = 0;
    }

    table egress_encap_ipv6 {
        key = { standard_metadata.egress_port: exact; }
        actions = { encap_ipv6_egress; NoAction; }
        default_action = NoAction();
    }

    table egress_encap_yequdesu {
        key = { standard_metadata.egress_port: exact; }
        actions = { encap_yequdesu_egress; NoAction; }
        default_action = NoAction();
    }

    table egress_encap_vxlan {
        key = { standard_metadata.egress_port: exact; }
        actions = { encap_vxlan_egress; NoAction; }
        default_action = NoAction();
    }

    apply {
        egress_encap_ipv6.apply();
        egress_encap_yequdesu.apply();
        egress_encap_vxlan.apply();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.yequdesu);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;