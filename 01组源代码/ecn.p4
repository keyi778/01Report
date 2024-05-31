/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_CPU  = 0x2333;
const bit<19> ECN_THRESHOLD_DEFAULT = 10;
//ethernet_t + cpu_t length, used to truncate
const bit<32> CPU_PACKET_HEADER_LENGTH = 42;
const bit<32> MAX_TUNNEL_ID = 1 << 16;


// instance type identifying cloned packet from egress
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2

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
//addtion
header additional_t {
    bit<16> dstPort;
    bit<8> protocol;
    bit<16> fwd_pkt_len_max;
    bit<16> fwd_pkt_len_min;
    bit<16> fwd_pkt_len_mean;
    bit<16> fwd_pkt_len_std;
    bit<16> bwd_pkt_len_std;
    bit<16> bwd_pkt_len_mean;
    bit<16> bwd_pkt_len_max;
    bit<16> bwd_pkt_len_min;
}
//tcp
header tcp_t {
    bit<1> fin;
    bit<1> syn;
    bit<1> rst;
    bit<1> psh;
    bit<1> ack;
    bit<1> urg;
    bit<1> cwe;
    bit<1> ece;
}

header cpu_t {
    ip4Addr_t src_ip;
    ip4Addr_t dst_ip;
    bit<1> tcp_fin;
    bit<1> tcp_syn;
    bit<1> tcp_rst;
    bit<1> tcp_psh;
    bit<1> tcp_ack;
    bit<1> tcp_urg;
    bit<1> tcp_cwe;
    bit<1> tcp_ece;
    bit<16> dst_port;
    bit<8> additional_protocol;
    bit<16> fwd_pkt_len_max;
    bit<16> fwd_pkt_len_min;
    bit<16> fwd_pkt_len_mean;
    bit<16> fwd_pkt_len_std;
    bit<16> bwd_pkt_len_std;
    bit<16> bwd_pkt_len_mean;
    bit<16> bwd_pkt_len_max;
    bit<16> bwd_pkt_len_min;
    bit<8> pad;
}

struct metadata {

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t 	  tcp;
    additional_t additional;
    cpu_t        cpu;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
	    6:parse_tcp;
	    default: accept;
	 }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_additional {
        packet.extract(hdr.additional);
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
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv4_forwarda(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.tcp.fin = 0;
        hdr.tcp.syn = 0;
        hdr.tcp.rst = 1;
        hdr.tcp.psh = 1;
        hdr.tcp.ack = 0;
        hdr.tcp.urg = 0;
        hdr.tcp.cwe = 0;
        hdr.tcp.ece = 1;
        hdr.additional.dstPort = 443;
        hdr.additional.protocol = 6;
        hdr.additional.fwd_pkt_len_max = 935;
        hdr.additional.fwd_pkt_len_min = 0;
        hdr.additional.fwd_pkt_len_mean = 187;
        hdr.additional.fwd_pkt_len_std = 418;
        hdr.additional.bwd_pkt_len_max = 249;
        hdr.additional.bwd_pkt_len_min = 0;
        hdr.additional.bwd_pkt_len_mean = 124;
        hdr.additional.bwd_pkt_len_std = 176;
    }
    action ipv4_forwardb(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.tcp.fin = 0;
        hdr.tcp.syn = 0;
        hdr.tcp.rst = 1;
        hdr.tcp.psh = 1;
        hdr.tcp.ack = 0;
        hdr.tcp.urg = 0;
        hdr.tcp.cwe = 0;
        hdr.tcp.ece = 1;
        hdr.additional.dstPort = 443;
        hdr.additional.protocol = 6;
        hdr.additional.fwd_pkt_len_max = 388;
        hdr.additional.fwd_pkt_len_min = 0;
        hdr.additional.fwd_pkt_len_mean = 119;
        hdr.additional.fwd_pkt_len_std = 160;
        hdr.additional.bwd_pkt_len_max = 1460;
        hdr.additional.bwd_pkt_len_min = 0;
        hdr.additional.bwd_pkt_len_mean = 461;
        hdr.additional.bwd_pkt_len_std = 652;
    }
        action ipv4_forwardc(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.tcp.fin = 0;
        hdr.tcp.syn = 0;
        hdr.tcp.rst = 1;
        hdr.tcp.psh = 1;
        hdr.tcp.ack = 0;
        hdr.tcp.urg = 0;
        hdr.tcp.cwe = 0;
        hdr.tcp.ece = 1;
        hdr.additional.dstPort = 8080;
        hdr.additional.protocol = 6;
        hdr.additional.fwd_pkt_len_max = 326;
        hdr.additional.fwd_pkt_len_min = 0;
        hdr.additional.fwd_pkt_len_mean = 108;
        hdr.additional.fwd_pkt_len_std = 188;
        hdr.additional.bwd_pkt_len_max = 112;
        hdr.additional.bwd_pkt_len_min = 0;
        hdr.additional.bwd_pkt_len_mean = 32;
        hdr.additional.bwd_pkt_len_std = 53;
    }
        action ipv4_forwardd(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.tcp.fin = 0;
        hdr.tcp.syn = 0;
        hdr.tcp.rst = 1;
        hdr.tcp.psh = 1;
        hdr.tcp.ack = 0;
        hdr.tcp.urg = 0;
        hdr.tcp.cwe = 0;
        hdr.tcp.ece = 1;
        hdr.additional.dstPort = 80;
        hdr.additional.protocol = 6;
        hdr.additional.fwd_pkt_len_max = 259;
        hdr.additional.fwd_pkt_len_min = 0;
        hdr.additional.fwd_pkt_len_mean = 86;
        hdr.additional.fwd_pkt_len_std = 149;
        hdr.additional.bwd_pkt_len_max = 935;
        hdr.additional.bwd_pkt_len_min = 0;
        hdr.additional.bwd_pkt_len_mean = 233;
        hdr.additional.bwd_pkt_len_std = 467;
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
    table ipv4_lpma {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forwarda;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table ipv4_lpmb {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forwardb;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table ipv4_lpmc {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forwardc;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table ipv4_lpmd {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forwardd;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.srcAddr ==  0x7F000001) {
		ipv4_lpma.apply();
	    }
	    else if(hdr.ipv4.srcAddr == 0x7F000002) {
		ipv4_lpmb.apply();
	    }
	    else if(hdr.ipv4.srcAddr == 0x7F000003) {
		ipv4_lpmc.apply();
	    }
	    else if(hdr.ipv4.srcAddr == 0x7F000004) {
		ipv4_lpmd.apply();
	    }
	    else{
	    	ipv4_lpm.apply();
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
    apply {
        // process cloned egress packet
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {
            hdr.cpu.setValid();

            hdr.cpu.src_ip = hdr.ipv4.srcAddr;
            hdr.cpu.dst_ip = hdr.ipv4.dstAddr;
            hdr.cpu.tcp_fin = hdr.tcp.fin;
            hdr.cpu.tcp_syn = hdr.tcp.syn;
            hdr.cpu.tcp_rst = hdr.tcp.rst;
            hdr.cpu.tcp_psh = hdr.tcp.psh;
            hdr.cpu.tcp_ack = hdr.tcp.ack;
            hdr.cpu.tcp_urg = hdr.tcp.urg;
            hdr.cpu.tcp_cwe = hdr.tcp.cwe;
            hdr.cpu.tcp_ece = hdr.tcp.ece;
            hdr.cpu.dst_port = hdr.additional.dstPort;
            hdr.cpu.additional_protocol = hdr.additional.protocol;
            hdr.cpu.fwd_pkt_len_max = hdr.additional.fwd_pkt_len_max;
            hdr.cpu.fwd_pkt_len_min = hdr.additional.fwd_pkt_len_min;
            hdr.cpu.fwd_pkt_len_mean = hdr.additional.fwd_pkt_len_mean;
            hdr.cpu.fwd_pkt_len_std = hdr.additional.fwd_pkt_len_std;
            hdr.cpu.bwd_pkt_len_mean = hdr.additional.bwd_pkt_len_mean;
            hdr.cpu.bwd_pkt_len_std = hdr.additional.bwd_pkt_len_std;
            hdr.cpu.bwd_pkt_len_max = hdr.additional.bwd_pkt_len_max;
            hdr.cpu.bwd_pkt_len_min = hdr.additional.bwd_pkt_len_min;
            hdr.ethernet.etherType = TYPE_CPU;

            hdr.ipv4.setInvalid();
            hdr.additional.setInvalid();
            hdr.tcp.setInvalid();
            truncate(CPU_PACKET_HEADER_LENGTH); //ether+cpu header
        }
        else {
            // clone packet, preserving meta.ecn_threshold and meta.egress_port for cpu header
            clone_preserving_field_list(CloneType.E2E, 100, 0);
        }
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
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.additional);
        packet.emit(hdr.cpu);
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
