/* includes*/ 

#include "Includes/headers.p4"
#include "Includes/parser.p4"

/* ACTIONS */

action mac_learn() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}
action arp_learn() {
    generate_digest(ARP_RECEIVER, arp_digest);
}
action _nop() {
}
action _nop1(s_mac) {
		modify_field(ethernet.srcAddr, s_mac);
		return egress;
}
action _drop() {
		drop();
}
action forward(s_mac, port) {
	modify_field(ethernet.srcAddr, s_mac);
    modify_field(standard_metadata.egress_port, port);
}
action set_dmac (d_mac){
	modify_field(ethernet.dstAddr, d_mac);
	}
action save_nxt_hop (nexthop) {

	modify_field(local_metadata.nexthop , nexthop);
	modify_field(ipv4.ttl, ipv4.ttl – 1);  
}

action bcast(s_mac) {
	modify_field(ethernet.srcAddr, s_mac);
    modify_field(standard_metadata.egress_port, 100);
}
/* I need to set action send to CP */

/* Tables */ 
table smac {
    reads {
		standard_metadata_metadata.ingress_port : exact;
		/* ingress_metadata.ingress_port : exact; */
        ethernet.srcAddr : exact;
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
    }
    actions {
	forward;
	bcast;
	_drop; 
	_nop; /* return egress */
	/* brodcast and fwd port */
	/*  send to CP */
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
table ipv4_lpm {
	reads {

		ipv4.dstAddr : lpm;
}
	actions {
		save_nxt_hop;
		_nop;
}
size : 65536;
}
table arp_table {
	reads {
			local_metadata.nexthop : exact ;
	}
	actions {
			set_dmac;
	}
}

/* Flow Functions */
control ingress {
    apply(smac);
	apply(dmac); /* _nop1 function just call the egress  flow control incase niether " _drop, forward nor bcast" functions are sselected */ 
	}
control egress{
	apply(arp_select);
		if (ethernet.etherType == 0x0800) {
				apply (ipv4_lpm);
				apply (arp_table);
				apply (dmac);
				}
}
	/* apply ( egress_table ) ; */
