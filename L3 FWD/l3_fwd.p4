/* includes*/ 

#include 'Includes.headers.p4'
#include 'Includes.parser.p4'

/* ACTIONS */

action mac_learn() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}
action _nop() {
}
action _drop() {
    drop();
}

action forward(port) {
    modify_field(standard_metadata.egress_port, port);
}

action nxt_hop (port, s_mac, d_mac ) {
	modify_field(standard_metadata.egress_port, port);
	modify_field(ethernet.srcAddr, s_mac);
	modify_field(ethernet.dstAddr, d_mac);
	modify_field(ipv4.ttl, ipv4.ttl – 1);  
}
action bcast() {
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
	_drop; 
	_nop;
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
		/* send to cp*/
		_nop;
		_drop; /* incase Eth type is diffrent */
	}
}
table ipv4_lpm {
	reads {

		ipv4.dstAddr : lpm;
}
	actions {
		nxt_hop;
}
size : 65536;
}
table egress_table {
	reads {
		ethernet.dstAddr : exact;
	}
`	actions {
		forward; 
		bcast; 
		}
	size : 512;
}
/* Flow Functions */
control ingress {

    apply(smac);
	apply(dmac);
	apply(arp_select);
	/* apply ( egress_table ) ; */
}                                                    /*  why we need two control flows?? */ 
control egress {
	apply ( egress_table ) ;

}