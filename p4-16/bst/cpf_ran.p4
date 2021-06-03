#ifndef _CPF_RAN_P4_
#define _CPF_RAN_P4_

#include "common_config.p4"

// ---------------------------------------------------------------------------
// RAN parser
//
// - count number of NACKs in meta.d8
//
// ---------------------------------------------------------------------------

parser RANIngressParser(packet_in pkt,
			out header_t hdr,
#ifdef __TARGET_TOFINO__
			out common_metadata_t meta,
			out ingress_intrinsic_metadata_t ig_intr_md
#endif
#ifdef __TARGET_PSA__
			inout common_metadata_t meta,
			in psa_ingress_parser_input_metadata_t istd,
			in EMPTY resubmit_meta,
			in EMPTY recirculate_meta
#endif
#ifdef __TARGET_V1__
			inout common_metadata_t meta,
			inout standard_metadata_t stm
#endif
		      ) {

    state start {
#ifdef __TARGET_TOFINO__
	pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.rx_port = ig_intr_md.ingress_port;
#endif
#ifdef __TARGET_PSA__
        meta.rx_port = istd.ingress_port;
#endif
#ifdef __TARGET_V1__
        meta.rx_port = stm.ingress_port;
#endif
	transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
//            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP : parse_arp;
            default: accept;  // TODO: add VLAN and MAC-in-MAC support later
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4) : parse_arp2;
            default : accept;
        }
    }

    state parse_arp2 {
        transition select(hdr.arp.hlen, hdr.arp.plen) {
            (ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        pkt.extract(hdr.arp_ipv4);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.frag_offset, 
                          hdr.ipv4.protocol, 
                          hdr.ipv4.ihl) {
            (0, IPPROTO_UDP, 5)  : parse_udp;
            (0, IPPROTO_ICMP, 5) : parse_icmp;
            default              : accept;
        }
    }
     
/*    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IPPROTO_UDP  : parse_udp;
            IPPROTO_ICMP : parse_icmp;
            default      : accept;
        }
    }*/
     
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
	    UDP_PORT_GTPU   : parse_gtpu;
	    UDP_PORT_BUFFER : parse_phys_buffer;
	    UDP_DPORT_RLC   : parse_rlc;
            default         : accept;
        }
    }

    state parse_phys_buffer {
	pkt.extract(hdr.buffering);
	transition select(hdr.buffering.nack_count){
	    0       : parse_inner_headers;
	    default : parse_rlc_status_nacks;
	}
    }

    state parse_inner_headers { // FIXME: now only assuming IPv4 / UDP payload (kind of correct)
	pkt.extract(hdr.ipv4_x);
	pkt.extract(hdr.udp_x);
	transition accept;
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_gtpu {
	pkt.extract(hdr.gtp);
	transition select(hdr.gtp.eFlag, hdr.gtp.sFlag, hdr.gtp.pnFlag) {
            (_, _, _) : parse_gtpopt;
	    (_, 1, _) : parse_gtpopt;
	    (_, _, 1) : parse_gtpopt;
	    default   : parse_ue_hdr;
	}
    }

    state parse_gtpopt {
	pkt.extract(hdr.gtpopt);
	transition parse_ue_hdr;
    }

    state parse_ue_hdr {
        pkt.extract(hdr.ipv4_u); // FIXME:  now assuming IPv4 payload only
        transition accept;       // FIXME2: not parsing user's UDP/TCP, maybe add later
    }

    state parse_rlc {
	transition select(pkt.lookahead<bit<1>>()){
	    0 : parse_rlc_status;
	    1 : parse_rlc_ack_mode;
	}
    }

    state parse_rlc_ack_mode { // RLC data packet
	pkt.extract(hdr.rlc_ack_mode);
	transition parse_ue_hdr;
    }

    state parse_rlc_status { // RLC control packet (FIXME: only status support)
	pkt.extract(hdr.rlc_status);
	transition select(hdr.rlc_status.e){
	    1 : parse_rlc_status_nacks;
	    0 : parse_rlc_st_teid;
	}
    }

    state parse_rlc_status_nacks {
	pkt.extract(hdr.rlc_nack_1);
	meta.d8 = 1; // N_NACKS
        meta.err = 1;
	transition select(hdr.rlc_nack_1.e) {
#ifndef __TARGET_V1__ // FIXME: t4p4s currently doesn't support header stacks
//	    1       : parse_rlc_status_nacks_2;
	    default : parse_rlc_st_teid;
#else
            default : parse_rlc_st_teid;
#endif
	}
    }

    state parse_rlc_st_teid { // RLC data packet
	pkt.extract(hdr.rlc_st_teid);
	transition accept;
    }
/*
#ifndef __TARGET_V1__ // FIXME: t4p4s currently doesn't support header stacks
    state parse_rlc_status_nacks_2 {
	pkt.extract(hdr.rlc_nack_more.next);
	transition select(hdr.rlc_nack_more.last.e){
	    1       : parse_rlc_status_nacks_2;
	    default : count_nacks;
	}
    }

    state count_nacks {
//	meta.d8 = hdr.rlc_nack_more.count; //BUG?
//	transition parse_inner_headers;
	transition accept;
    }
#endif
*/
}


// ---------------------------------------------------------------------------
//
// UPLINK
//
// in:  RLC in UDP/IPv4
// out: GTP in UDP/IPv4 (reuse external header)
//
// ---------------------------------------------------------------------------

control RANUplink(inout header_t hdr,
		  in    common_metadata_t meta,
		  in    ipv4_addr_t myip,
                  in    bit<32> teid
		 ) {
    apply {
	hdr.gtp.setValid();
	hdr.gtp.teid = teid;

	hdr.gtp.version       = 0x01;
	hdr.gtp.pFlag         = 1;
	hdr.gtp.messageType   = 0xff;
	hdr.gtp.messageLength = hdr.ipv4_u.total_len;

	// TODO: generate RLC status messages to the UE (ACK) - cloned pkt
	// TODO: remove saved packets from the buffer - cloned pkt

        hdr.ipv4.dst_addr = STATIC_UPF_ADDR;
        hdr.ipv4.src_addr = myip;
	hdr.udp.dst_port = UDP_PORT_GTPU;
	hdr.rlc_ack_mode.setInvalid();
    }
}


// ---------------------------------------------------------------------------
//
// DOWNLINK
//
// in:  GTP in UDP/IPv4 maybe with seq_num option
// out: Packet with buffer header encapsulating RLC data frame
//      - keep UE header
//      - set middle hdr ([ip/udp]_x) for RLC encaps
//      - reuse GTP seq_num if available, generate if not (per UE register)
//      - reuse top header for buffering
//
// ---------------------------------------------------------------------------

control RANDownlink(inout header_t hdr,
		    in    common_metadata_t meta
		   )
//(bit<32> num_users)
{
#ifndef __TARGET_V1__
    Register<bit<16>, bit<32>>(NUM_USERS) last_seqn_store;
    RegisterAction<bit<16>, bit<32>, bit<16>>(last_seqn_store) igs = {
	void apply(inout bit<16> data, out bit<16> result) {
            result = data;
	    data = data + 1;
	}
    };
    action incr_get_seqn(in bit<32> id, out bit<16> res) {
        res = igs.execute(id);
    }
#else
    register<bit<16>>(NUM_USERS) last_seqn_store;
    action incr_get_seqn(in bit<32> id, out bit<16> res) {
	last_seqn_store.read(res, id);
	last_seqn_store.write(id, res + 1);
    }
    bit<16> _sn;
#endif

    apply {
        // setting RLC
	hdr.rlc_ack_mode.setValid();
	hdr.rlc_ack_mode.dc = 1;
	hdr.rlc_ack_mode.p  = 0x0;
	hdr.rlc_ack_mode.si = 0x00;
	hdr.rlc_ack_mode.r  = 0x00;
	if (hdr.gtp.sFlag == 1) {
	    hdr.rlc_ack_mode.sn = hdr.gtpopt.seq_num;
	}
	else {
#ifndef __TARGET_V1__
	    hdr.rlc_ack_mode.sn = igs.execute(hdr.gtp.teid);
#else
	    incr_get_seqn(hdr.gtp.teid, _sn);
	    hdr.rlc_ack_mode.sn = _sn;
#endif
	}
	hdr.ipv4_x.setValid(); // use internal hdr for RLC (external -> buffer hdr)
        hdr.ipv4_x = hdr.ipv4;
	hdr.udp_x.setValid();
        hdr.udp_x.src_port = UDP_SPORT_RLC;
	hdr.udp_x.dst_port = UDP_DPORT_RLC;
	hdr.udp_x.length = hdr.ipv4_u.total_len + 15; // UE packet + RLC + UDP

	// setting buffer hdr
	// FIXME: later add packet cloning here
	hdr.buffering.setValid();
	hdr.buffering.endpoint_id = hdr.gtp.teid;
	hdr.buffering.ack_sn = hdr.rlc_ack_mode.sn;
	hdr.buffering.nack_count = 0xff; //0xff MEANS NOT A STATUS MESSAGE

	hdr.udp.src_port = UDP_PORT_BUFFER;
	hdr.udp.dst_port = UDP_PORT_BUFFER;
        hdr.ipv4.dst_addr = BUFFER_SERVICE_IP;
	hdr.gtp.setInvalid();
    }
}


// ---------------------------------------------------------------------------
//
// DOWNLINK resend (and also first packet - TODO)
//
// in:  Packet with buffer header in UDP/IPv4
// out: RLC encapsulated packet in UDP/IPv4
//      - move middle header to top for routing
//      - remove middle header
//
// ---------------------------------------------------------------------------

control RANResend(inout header_t hdr,
		  in    common_metadata_t meta
		 ) {
    apply {
	hdr.ipv4 = hdr.ipv4_x;
        hdr.udp  = hdr.udp_x;
	hdr.ipv4_x.setInvalid();
	hdr.udp_x.setInvalid();
	hdr.buffering.setInvalid();

	if (hdr.rlc_ack_mode.isValid()) {
	    hdr.rlc_ack_mode.dc = 1;
	    hdr.rlc_ack_mode.p  = 0x0;
	    hdr.rlc_ack_mode.si = 0x00;
	    hdr.rlc_ack_mode.r  = 0x00;
	}
    }
}


// ---------------------------------------------------------------------------
//
// UPLINK status message from UE
//
// in:  Packet with RLC status header (ACK/NACK)
// out: Packet with buffer header encapsulating RLC control frame
//      - reuse top header for buffering
//
// ---------------------------------------------------------------------------

control RANStatus(inout header_t hdr,
		  in    common_metadata_t meta
		 ) {
    apply {
	hdr.buffering.setValid();
	hdr.buffering.endpoint_id = hdr.rlc_st_teid.teid;
        hdr.buffering.ack_sn = hdr.rlc_status.sn;

	hdr.rlc_status.setInvalid();
	hdr.udp.dst_port = UDP_PORT_BUFFER;
        hdr.ipv4.dst_addr = BUFFER_SERVICE_IP;
    }
}


// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// PPF/RAN pipeline - only needed if RAN is the main P4 functionality
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#ifndef _MAIN_FN_DEFINED_
#define _MAIN_FN_DEFINED_ 1

#include "transport.p4" // import modules here

control RANIngress(inout header_t hdr,
		   inout common_metadata_t meta,
#ifdef __TARGET_TOFINO__
		   in ingress_intrinsic_metadata_t ig_intr_md,
		   in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
		   inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
		   inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
#endif
#ifdef __TARGET_PSA__
		   in psa_ingress_input_metadata_t istd,
		   inout psa_ingress_output_metadata_t ostd
#endif
#ifdef __TARGET_V1__
		   inout standard_metadata_t stm
#endif
		  ) {

#ifndef __TARGET_V1__
    // Stateful structures
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS_AND_BYTES) rx;	// TODO: do a per port ctr later
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS_AND_BYTES) tx;
#else
    counter(1, CounterType.packets_and_bytes) rx;
    counter(1, CounterType.packets_and_bytes) tx;
#endif

    bit<32> _teid = 0;
    bit<4>  _id = 1;
    mac_addr_t _my_mac = EPG_VIRT_MAC;
    ipv4_addr_t _my_ip = 0;

    /**********************************************************************************/

    action drop() {
#ifdef __TARGET_TOFINO__
	ig_dprsr_md.drop_ctl = 1;
#endif
#ifdef __TARGET_PSA__
	ostd.drop = true;
#endif
#ifdef __TARGET_V1__
	mark_to_drop(stm);
#endif
    }

    action send(PortId_t port){
#ifdef __TARGET_TOFINO__
	ig_tm_md.ucast_egress_port = port;
#endif
#ifdef __TARGET_PSA__
        ostd.drop = false;
	ostd.egress_port = port;
#endif
#ifdef __TARGET_V1__
        stm.egress_spec = port;
#endif
    }

#ifdef __TARGET_TOFINO__
    action ran_status() {
	hdr.buffering.setValid();
	hdr.buffering.endpoint_id = hdr.rlc_st_teid.teid;

	hdr.rlc_status.setInvalid();
	hdr.udp.src_port = UDP_PORT_BUFFER;
	hdr.udp.dst_port = UDP_PORT_BUFFER;
        hdr.ipv4.dst_addr = BUFFER_SERVICE_IP;
    }
#endif

    apply {
	rx.count(0);
#ifdef __TARGET_TOFINO__
	L2_in.apply(hdr, meta, ig_dprsr_md, ig_tm_md, _my_ip);
#else
	L2_in.apply(hdr, meta, _my_ip);
#endif
#ifdef __TARGET_V1__
	if (meta.gen_mac_digest == 1) {
	    digest<mac_learn_digest>((bit<32>)MAC_LEARN_DIGEST, { hdr.eth.src_addr, meta.rx_port } );
	}
#endif
#ifndef __TARGET_TOFINO__
	if (meta.drop == 1) { drop(); exit; }
	if (meta.send == 1) { send(meta.tx_port); exit; }
#endif

	if (hdr.udp.isValid() && hdr.udp.dst_port == UDP_PORT_BUFFER) { // coming from the buffer (resend)
	    RANResend.apply(hdr, meta);
	}
	else {
	    if (hdr.rlc_ack_mode.isValid()) { // RLC DATA PDU (UL)
		RANUplink.apply(hdr, meta, _my_ip, hdr.rlc_ack_mode.teid);
	    }
	    else if (hdr.rlc_status.isValid()) { // RLC CONTROL SDU (UL)
#ifdef __TARGET_TOFINO__
		hdr.buffering.ack_sn = cp_h16.get(hdr.rlc_status.sn);
		ran_status();
#else
		RANStatus.apply(hdr, meta);
#endif
	    }
	    else { // DOWNLINK (check GTP)
		RANDownlink.apply(hdr, meta);
	    }
	}

#ifdef __TARGET_TOFINO__
	Router.apply(hdr, meta, ig_dprsr_md);
#else
	Router.apply(hdr, meta);
#endif
#ifdef __TARGET_V1__
	if (meta.gen_arp_digest == 1) {
	    digest<arp_digest>((bit<32>)ARP_MISS_DIGEST, { meta.d32, hdr.eth.dst_addr } );
	}
#endif
#ifndef __TARGET_TOFINO__
	if (meta.drop == 1) { drop(); exit; }
	if (meta.send == 1) { send(meta.tx_port); exit; }
#endif

#ifdef __TARGET_TOFINO__
	L2_out.apply(hdr, meta, ig_tm_md);
#else
	L2_out.apply(hdr, meta);
#endif
#ifndef __TARGET_TOFINO__
	send(meta.tx_port);
#endif
	tx.count(0);
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------

control RANIngressDeparser(packet_out pkt,
#ifdef __TARGET_TOFINO__
			   inout header_t hdr,
			   in common_metadata_t meta,
			   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
#endif
#ifdef __TARGET_PSA__
			   out EMPTY clone_i2e_meta,
			   out EMPTY resubmit_meta,
			   out EMPTY normal_meta,
			   inout header_t hdr,
			   in common_metadata_t meta,
			   in psa_ingress_output_metadata_t istd
#endif
#ifdef __TARGET_V1__
			   in header_t hdr
#endif
			 ) {
#ifdef __TARGET_TOFINO__
    Digest <mac_learn_digest_data>() mac_learn_digest;
    Digest <arp_digest_data>() arp_digest;
    Checksum() cs;
#endif
#ifdef __TARGET_PSA__
    InternetChecksum() cs;
#endif

    apply {
#ifdef __TARGET_PSA__
	TransportDigestGen.apply(hdr, meta);
	cs.clear();
	cs.add({hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.l4s, hdr.ipv4.ecn,
                hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags,
	        hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
	hdr.ipv4.hdr_checksum = cs.get();
#endif
#ifdef __TARGET_TOFINO__
	if (ig_dprsr_md.digest_type == 1) {
	    mac_learn_digest.pack({hdr.digest_hack.mac_addr, meta.rx_port});
	}
	if (ig_dprsr_md.digest_type == 2) {
	    arp_digest.pack({meta.d32, hdr.eth.dst_addr});
	}
	hdr.ipv4.hdr_checksum = cs.update({
			      hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.l4s, hdr.ipv4.ecn,
			      hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags,
			      hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol,
			      hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
#endif
	pkt.emit(hdr);
    }
}

#ifdef __TARGET_TOFINO__
Pipeline(RANIngressParser(),
	 RANIngress(),
	 RANIngressDeparser(),
	 CommonEgressParser(),
	 EmptyEgress(),
	 EmptyEgressDeparser()
	) ran_pipe;
Switch(ran_pipe) main;
#endif // TOFINO

#ifdef __TARGET_PSA__
IngressPipeline(RANIngressParser(),
		RANIngress(),
		RANIngressDeparser()) ipipe;
EgressPipeline(EmptyEgressParser(),
	       EmptyEgress(),
	       EmptyEgressDeparser()) epipe;
PSA_Switch(ipipe, PacketReplicationEngine(), epipe, BufferingQueueingEngine()) main;
#endif // PSA

#ifdef __TARGET_V1__
V1Switch(RANIngressParser(), MyVerifyChecksum(), RANIngress(), EmptyEgress(), Ipv4ComputeChecksum(), RANIngressDeparser()) main;
#endif // V1MODEL

#endif // _MAIN_FN_DEFINED_

#endif // _CPF_RAN_P4_
