/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;

const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;

const bit<16> GTP_UDP_PORT     = 2152;

const bit<32> MAC_LEARN_RECEIVER = 1;
const bit<32> ARP_LEARN_RECEIVER = 1025;

const bit<48> OWN_MAC = 0x001122334455;
const bit<48> BCAST_MAC = 0xFFFFFFFFFFFF;
const bit<32> GW_IP = 0x0A000001; // 10.0.0.1

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16>   etherType;
}

header vlan_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
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
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    bit<48>  sha;
    bit<32> spa;
    bit<48>  tha;
    bit<32> tpa;
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

/* GPRS Tunnelling Protocol (GTP) common part for v1 and v2 */

header gtp_common_t {
	bit<3> version; /* this should be 1 for GTPv1 and 2 for GTPv2 */
	bit<1> pFlag;   /* protocolType for GTPv1 and pFlag for GTPv2 */
	bit<1> tFlag;   /* only used by GTPv2 - teid flag */
	bit<1> eFlag;   /* only used by GTPv1 - E flag */
	bit<1> sFlag;   /* only used by GTPv1 - S flag */
	bit<1> pnFlag;  /* only used by GTPv1 - PN flag */
	bit<8> messageType;
	bit<16> messageLength;
}

header gtp_teid_t {
	bit<32> teid;
}

/* GPRS Tunnelling Protocol (GTP) v1 */

/* 
This header part exists if any of the E, S, or PN flags are on.
*/

header gtpv1_optional_t {
	bit<16> sNumber;
	bit<8> pnNumber;
	bit<8> nextExtHdrType;
}

/* Extension header if E flag is on. */

header gtpv1_extension_hdr_t {
	bit<8> plength; /* length in 4-octet units */
	varbit<128> contents; 
	bit<8> nextExtHdrType;
}


/* GPRS Tunnelling Protocol (GTP) v2 (also known as evolved-GTP or eGTP) */


header gtpv2_ending_t {
	bit<24> sNumber;
	bit<8> reserved;
}

/* TCP */
/*
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
*/
/* UDP */

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

/* Local metadata */

struct gtp_metadata_t {
	bit<32> teid;
	bit<8> color;
}

struct arp_metadata_t {
    bit<32> dst_ipv4;
    bit<48>  mac_da;
    bit<48>  mac_sa;
    bit<9>   egress_port;
    bit<48>  my_mac;
}

struct routing_metadata_t {
    bit<8> nhgrp;
}


struct metadata {
    gtp_metadata_t gtp_metadata;
    arp_metadata_t arp_metadata;
    routing_metadata_t routing_metadata;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv4_t       inner_ipv4;
    icmp_t       icmp;
    icmp_t	 inner_icmp;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    vlan_t       vlan;
    gtp_common_t gtp_common;
    gtp_teid_t gtp_teid;
    gtpv1_extension_hdr_t gtpv1_extension_hdr;
    gtpv1_optional_t gtpv1_optional;
    gtpv2_ending_t gtpv2_ending;
    udp_t udp;
    udp_t inner_udp;
}

/************************************************************************
************************ D I G E S T  ***********************************
*************************************************************************/

struct mac_learn_digest {
    bit<48> srcAddr;
    bit<8>  ingress_port;
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
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.arp_metadata.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.arp_metadata.dst_ipv4 = hdr.ipv4.dstAddr;
        transition select(hdr.ipv4.protocol) {
            IPPROTO_ICMP : parse_icmp;
            IPPROTO_UDP  : parse_udp;
            default      : accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            GTP_UDP_PORT : parse_gtp;
            default      : accept;    
        }
    }

    state parse_gtp {
        packet.extract(hdr.gtp_common);
        transition select(hdr.gtp_common.version, hdr.gtp_common.tFlag) {
		    (1,0)	: parse_teid;
		    (1,1) : parse_teid;
		    (2,1) : parse_teid;
		    (2,0) : parse_gtpv2;
		    default : accept;
	    }
    }

    state parse_teid {
        packet.extract(hdr.gtp_teid);
        transition parse_inner;
/*select( hdr.gtp_common.version, hdr.gtp_common.eFlag, hdr.gtp_common.sFlag, hdr.gtp_common.pnFlag ) {
		    0x10 &  0x18 : parse_gtpv2; / v2 /
		    0x0c & 0x1c : parse_gtpv1optional; / v1 + E /
		    0x0a & 0x1a : parse_gtpv1optional; / v1 + S /
		    0x09 & 0x19 : parse_gtpv1optional; / v1 + PN 
		    default 	: parse_inner;
	    }*/
    }
 
    state parse_gtpv2 {
        packet.extract(hdr.gtpv2_ending);
        transition accept;
    }

    state parse_gtpv1optional {
        packet.extract(hdr.gtpv1_optional);
        transition parse_inner;
    }

    state parse_inner {
        packet.extract(hdr.inner_ipv4);
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

    meter(256, MeterType.bytes) teid_meters;

    action drop() {
        mark_to_drop();
    }
    
    action mac_learn() {
    /*    digest(MAC_LEARN_RECEIVER, { hdr.ethernet.srcAddr, standard_metadata.ingress_port } );*/
    }

    action arp_digest() {
        NoAction(); /*digest(ARP_LEARN_RECEIVER, */
    }

    action arp_reply() {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;
        hdr.ethernet.srcAddr = OWN_MAC;
        
        hdr.arp.oper         = ARP_OPER_REPLY;
        
        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;
        hdr.arp_ipv4.sha     = OWN_MAC;
        hdr.arp_ipv4.spa     = meta.arp_metadata.dst_ipv4;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action send_icmp_reply() {
        bit<48>   tmp_mac;
        bit<32>  tmp_ip;

        tmp_mac              = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp_mac;

        tmp_ip               = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr     = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr     = tmp_ip;

        hdr.icmp.type        = ICMP_ECHO_REPLY;
        hdr.icmp.checksum    = 0; // For now

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
	    hdr.ethernet.srcAddr = OWN_MAC;
    }

    action bcast() {
        standard_metadata.egress_spec = 100;
    }

   action gtp_encapsulate(bit<32> teid, bit<32> ip) {
        hdr.inner_ipv4.setValid();
        hdr.inner_ipv4 = hdr.ipv4;
	    hdr.udp.setValid();
        hdr.gtp_common.setValid();
        hdr.gtp_teid.setValid();
        hdr.udp.srcPort = GTP_UDP_PORT;
        hdr.udp.dstPort = GTP_UDP_PORT;
        hdr.udp.checksum = 0;
        hdr.udp.plength = hdr.ipv4.totalLen + 8;
        hdr.gtp_teid.teid = teid;
        hdr.gtp_common.version = 1;
        hdr.gtp_common.pFlag = 1;
        hdr.gtp_common.messageType = 255;
        hdr.gtp_common.messageLength = hdr.ipv4.totalLen + 8;
        hdr.ipv4.srcAddr = GW_IP;
        hdr.ipv4.dstAddr = ip;
        hdr.ipv4.protocol = IPPROTO_UDP;
        hdr.ipv4.ttl = 255;
        hdr.ipv4.totalLen = hdr.udp.plength + 28;
        meta.gtp_metadata.teid = teid;	
    }

    action gtp_decapsulate() {
        hdr.ipv4 = hdr.inner_ipv4;
        meta.gtp_metadata.teid =  hdr.gtp_teid.teid;
        hdr.udp.setInvalid();
        hdr.gtp_common.setInvalid();
        hdr.gtp_teid.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    action set_nhgrp(bit<8> nhgrp) {
        meta.routing_metadata.nhgrp = nhgrp;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action apply_meter(bit<32> mid) {
        teid_meters.execute_meter(mid, meta.gtp_metadata.color );
    }

    action pkt_send(bit<48> nhmac, bit<9> port) {
        hdr.ethernet.srcAddr = OWN_MAC; // simplified
        hdr.ethernet.dstAddr = nhmac;
        standard_metadata.egress_spec = port;
    }
/*
table smac {
    key = {
		standard_metadata.ingress_port : exact;
        hdr.ethernet.srcAddr : exact;
    }
    actions = {mac_learn; NoAction;}
    size = 512;
    default_action = mac_learn;
}

table dmac {
    key = {
        hdr.ethernet.dstAddr : exact;
    }
    actions = {forward; bcast;}
    size = 512;
    default_action = bcast;
}
*/

table ue_selector {
	key = {
		hdr.ipv4.dstAddr : lpm;
		hdr.udp.dstPort  : ternary; /* in most of the cases the mask is 0 */
	}
	actions = { drop; gtp_encapsulate; gtp_decapsulate;}
	size = 10000;
    default_action = drop;
}

table teid_rate_limiter {
	key = {
		meta.gtp_metadata.teid : exact;
	}
	actions = { apply_meter; NoAction; drop;}
	size = 256;
	default_action = drop;
}

table m_filter {
	key = {
		meta.gtp_metadata.color : exact;
	}
	actions = { drop; NoAction; }	
	size = 256;
	const default_action = drop;
	const entries = { ( 0 ) : NoAction();} /* GREEN */
}

table ipv4_lpm {
	key = {
		hdr.ipv4.dstAddr : lpm;
	}
	actions = { set_nhgrp; drop; }
	size = 256;
	default_action = drop;
}

table ipv4_forward {
    key = {
		meta.routing_metadata.nhgrp : exact;        
    }
    actions = {pkt_send; drop; }
    size = 64;
    default_action = drop;
}



apply {
    /* TODO add L2*/
	if ( (hdr.ethernet.dstAddr == OWN_MAC) || (hdr.ethernet.dstAddr == BCAST_MAC) )
	{
		    if ( hdr.ipv4.isValid() ) {
			    ue_selector.apply();
			    teid_rate_limiter.apply();
			    m_filter.apply();
			    ipv4_lpm.apply();
			    ipv4_forward.apply();
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

control Ipv4ComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
/*	update_checksum(
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
            HashAlgorithm.csum16);*/
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
 	    packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
		 packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp_common);
        packet.emit(hdr.gtp_teid);
        packet.emit(hdr.inner_ipv4);
		packet.emit(hdr.inner_icmp);
	packet.emit(hdr.inner_udp);
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
Ipv4ComputeChecksum(),
MyDeparser()
) main;
