#include "Includes/headers.p4"
#include "Includes/parser.p4"

/* ACTIONS */
action _nop() {
}
action _drop() {
		drop();
}
action mac_learn() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

action arp_learn() {
    generate_digest(ARP_RECEIVER, arp_digest);
}
action forward(s_mac, port) {
	modify_field(ethernet.srcAddr, s_mac);
    modify_field(standard_metadata.egress_port, port);
}

/* action _nop1(s_mac) {
		modify_field(ethernet.srcAddr, s_mac);
}*/
action gtp_handler (){
	modify_field (gtpMetadata.teid ,  gtpTeid.teid);
	/* gtp decapsulate  */ 
	copy_header(ipv4, innerIpv4);
	remove_header(udp);
	remove_header(gtp);
	remove_header(gtpTeid);
}  
	action UE_select (ip_src , ip_dst , teid){
	
	    /* GTP encpsulation */
		
	copy_header(innerIpv4, ipv4);
	add_header(udp);
	add_header(gtp);
	add_header(gtpTeid);
	
	modify_field(udp.srcPort, GTP_UDP_PORT);
	modify_field(udp.dstPort, GTP_UDP_PORT); /* TODO: is the same port used for UL and DL??? */
	modify_field(udp.checksum, 0);
	add(udp.length, egress_metadata.payload_length, 36); /* TODO: should be handled in T4P4S */
	
	modify_field(gtpTeid.teid, teid); /* GTPv1-U */
	modify_field(gtp.version, 1);
	modify_field(gtp.pFlag, 1);
	modify_field(gtp.messageType, 255); /* TODO: clarify what should be here ;255 = G-PDU */
	add(gtp.messageLength, egress_metadata.payload_length, 20);
	
	modify_field(ipv4.srcAddr, ip_src);
	modify_field(ipv4.dtsAddr, ip);
	modify_field(ipv4.protocol, IP_PROTOCOL_UDP);
	modify_field(ipv4.ttl, 255);
add(ipv4.totalLength, egress_metadata.payload_length, 56 ); /* IP + UDP + GTP + TEID + IP + PAYLOAD */
	
	}
action set_next_hop ( s_mac, d_mac , port){
	modify_field(ethernet.srcAddr, s_mac);
	modify_field(ethernet.dstAddr, d_mac);
	modify_field(standard_metadata.egress_port, port);
	subtract_from_field(ipv4.ttl , 1);
	}
	/*
action save_nxt_hop (nexthop) {
	modify_field(local_metadata.nexthop , nexthop);
	subtract_from_field(ipv4.ttl , 1); 
}*/

/* Tables */ 
/* l2 fwd */ 
table smac {
    reads {    
        ethernet.srcAddr : exact ;
    }
    actions {
	mac_learn; /* contacts to CP through the digesst*/ 
	_nop;
	}
    size : 512;  /* how to set the sizes of tables */
}
table dmac {
    reads {
        ethernet.dstAddr : exact;
		/* vlan.vid : exact ;*/
    }
    actions {
	forward;
	_drop; 
	_nop; 
	}
    size : 512;
}
table arp_select {
	reads {
		ethernet.etherType : exact ;
	}
	actions {
		arp_learn;
		_nop;
		_drop; /* incase Eth type is diffrent */
	}	
}
table udp_select {
	reads {

		ipv4.dstAddr : lpm; /*exact instead of lpm*/ 
		udp.dst_port : ternary;
}
	actions {
		gtp_handler;
}
/* size : 000 */
}
table UE_UL {
	reads {
	gtpMetadata.teid : exact;
	}
	actions {
	UE_select ; 
	}
	}
	table UE_DL {
		reads {
		gtpMetadata.teid : exact;
		}
		actions {
		UE_select ;
		}
	}
table l3_fib {
	reads {			ipv4.dstAddr : lpm;	}
	actions {	set_next_hop;	}
}

/* flow control */ 

/* in this P4 implementation the snow3G encrypt/decrypt  blocs are not 
implemented because P4_14 doesnt support this. It will be possible if 
implemented in P4_16 using the EXTERN type */

control ingress {
    apply(smac);
	apply(dmac) {
		_nop {  
					apply (arp_select) ;
					apply (udp_select) ;
					
					if ( /* how  to decide the flow? I think it should be based on IP */ ) {
				        apply (UE_UL );
						apply (l3_fib);
						apply (d_mac );
					}
					default {
						apply (UE_UL) ;
						apply (l3_fib);
						apply (d_mac) ;
					}
		}
	}
}
control egress {
} 
