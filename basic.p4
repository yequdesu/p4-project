// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_SRCROUTING = 0x0900;
const bit<32> MAX_TUNNEL_ID = 1 << 16;
#define MAX_HOPS 9

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4 = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET = 6;
const bit<8>  ARP_PLEN_IPV4 = 4;
const bit<16> ARP_OPER_REQUEST = 1;
const bit<16> ARP_OPER_REPLY = 2;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header arp_t {
    bit<16> htype; // format of hardware address
    bit<16> ptype; // format of protocol address
    bit<8>  hlen; // length of hardware address
    bit<8>  plen; // length of protocol address
    bit<16> oper; // request or reply operation
    macAddr_t sha; // src mac address
    ip4Addr_t spa; // src ip address
    macAddr_t tha; // dst mac address
    ip4Addr_t tpa; // dst ip address
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

struct metadata {
    ip4Addr_t dst_ipv4; // dst ip for ARP
}

struct headers {
    ethernet_t              ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    arp_t                   arp;
    ipv4_t                  ipv4;
    ipv6_t                  ipv6;
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
            TYPE_SRCROUTING: parse_srcRouting;
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            TYPE_ARP: parse_arp;
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
        transition accept;
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition accept;
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


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
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
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


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

    // 1 hop
    action add_head_1(
        bit<1>    bos1,
        bit<15>   port1
    ){
        hdr.ethernet.etherType = TYPE_SRCROUTING;
        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port1;
        hdr.srcRoutes[0].bos = bos1;
    }

    // 2 hops
    action add_head_2(
        bit<1>    bos1,
        bit<15>   port1,
        bit<1>    bos2,
        bit<15>   port2
    ){
        hdr.ethernet.etherType = TYPE_SRCROUTING;

        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port2;
        hdr.srcRoutes[0].bos = bos2;

        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port1;
        hdr.srcRoutes[0].bos = bos1;
    }

    // 3 hops
    action add_head_3(
        bit<1>    bos1,
        bit<15>   port1,
        bit<1>    bos2,
        bit<15>   port2,
        bit<1>    bos3,
        bit<15>   port3
    ){
        hdr.ethernet.etherType = TYPE_SRCROUTING;

        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port3;
        hdr.srcRoutes[0].bos = bos3;

        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port2;
        hdr.srcRoutes[0].bos = bos2;

        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port1;
        hdr.srcRoutes[0].bos = bos1;
    }


    table src_routing_publish {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            add_head_1;
            add_head_2;
            add_head_3;
            drop;
        }
        default_action = drop();
        size = 1024;
    }

    //rewrite destination MAC so that the target host will reply
    action rewriteMac(macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = dstAddr;
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
        hdr.ethernet.dstAddr = hdr.arp.sha;      // Ethernet target address = ARP source MAC address
        hdr.ethernet.srcAddr = macAddr;           // Ethernet source address = the action argument macAddr

        hdr.arp.oper = ARP_OPER_REPLY;            // modify the ARP packet type to reply
        // set the fields to reply
        hdr.arp.tha = hdr.arp.sha;                // ARP target MAC address = ARP source MAC address
        hdr.arp.tpa = hdr.arp.spa;                // ARP target IP address = ARP source IP address
        hdr.arp.sha = macAddr;                    // ARP source MAC address = the action argument macAddr
        hdr.arp.spa = meta.dst_ipv4;              // ARP source IP address = ARP target IP address

        standard_metadata.egress_spec = standard_metadata.ingress_port; // return to the port it comes from
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

    apply {
        if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_match.apply();
        }
        else if (hdr.ethernet.etherType == TYPE_SRCROUTING) {
            // Source routing modality - independent path control
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
        }
        else {
            // IPv4 and IPv6 modalities - conventional routing
            if (hdr.ipv4.isValid()) {
                // Process IPv4 packets
                ipv4_lpm.apply();
            }
            else if (hdr.ipv6.isValid()) {
                // Process IPv6 packets
                ipv6_lpm.apply();
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
    apply {  }
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
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
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
