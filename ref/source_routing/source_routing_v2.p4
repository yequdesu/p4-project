/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

#define MAX_HOPS 9

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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t              ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    ipv4_t                  ipv4;
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
            TYPE_IPV4      : parse_ipv4;
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

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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

    // 4 hops
    action add_head_4(
        bit<1>    bos1,
        bit<15>   port1,
        bit<1>    bos2,
        bit<15>   port2,
        bit<1>    bos3,
        bit<15>   port3,
        bit<1>    bos4,
        bit<15>   port4
    ){
        hdr.ethernet.etherType = TYPE_SRCROUTING;
        
        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port4;
        hdr.srcRoutes[0].bos = bos4;

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
    
    // From 5 to MAX_HOPS hops, their actions can refer actions above

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

    //rewrite destination MAC so that the tarket host will reply
    action rewriteMac(macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = dstAddr;
    }
    
    table ipv4_lpm {
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

    apply {
        // not srtRoutes, the first hop
        if(!hdr.srcRoutes[0].isValid()){
            src_routing_publish.apply();
        }
        if (hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
                if (hdr.ipv4.isValid()){
                    ipv4_lpm.apply();
                }
            }
            srcRoute_nhop();
            update_ttl();
        }
        else {
            drop();
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
        packet.emit(hdr.ipv4);
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
