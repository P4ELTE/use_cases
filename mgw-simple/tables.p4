/* L2 forwarding - components */

/* Defines */

#define MAC_LEARN_RECEIVER 1024
#define ARP_LEARN_RECEIVER 1025
#define OWN_MAC 00:11:22:33:44:55 /* TODO: check the format */

/* Digest definitions */

field_list mac_learn_digest {
    ethernet.srcAddr;
    standard_metadata.ingress_port;
}

field_list arp_learn_digest {
	ethernet.srcAddr;
	arp.senderIP;
	arp.senderHA;
    arp.targetIP;
}

/* Action definitions */

action _nop() {
}

action mac_learn() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

action forward(port) {
    modify_field(standard_metadata.egress_port, port);
	modify_field(ethernet.srcAddr, OWN_MAC);
}

action bcast() {
    modify_field(standard_metadata.egress_port, 100);

}

action arp_reply(macaddr) {
	modify_field( ethernet.dstAddr, arpMetadata.ethSrc );
	modify_field( arp.oper, 2 );
	modify_field( arp.senderIP, arpMetadata.targetIP);
	modify_field( arp.senderHA, macaddr);
	modify_field( arp.targetIP, arpMetadata.senderIP);
	modify_field( arp.targetHA, arpMetadata.senderHA);
}

action arp_digest() {
	generate_digest(ARP_LEARN_RECEIVER, arp_learn_digest);
}

action gtp_encapsulate(teid, ip) {
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
	
	modify_field(ipv4.srcAddr, GW_IP);
	modify_field(ipv4.dtsAddr, ip);
	modify_field(ipv4.protocol, IP_PROTOCOL_UDP);
	modify_field(ipv4.ttl, 255);
	add(ipv4.totalLength, egress_metadata.payload_length, 56 ); /* IP + UDP + GTP + TEID + IP + PAYLOAD */
}

action gtp_decapsulate() {
	copy_header(ipv4, innerIpv4);
	remove_header(udp);
	remove_header(gtp);
	remove_header(gtpTeid);
}

table smac {
    reads {
		standard_metadata.ingress_port : exact;
        ethernet.srcAddr : exact;
    }
    actions {mac_learn; _nop;}
    size : 512;
}

table dmac {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {forward; bcast;}
    size : 512;
}

table arp_lookup {
	reads {
		arp.targetIP : exact;
	}
	actions {arp_reply;arp_digest;_drop;}
	size : 512;
}

table ue_selector {
	reads {
		ipv4.dstAddr : lpm;
		udp.dstPort  : ternary; /* in most of the cases the mask is 0 */
	}
	actions { _drop; gtp_encapsulate; gtp_decapsulate;}
	size : 10000;
}


