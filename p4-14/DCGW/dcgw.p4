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
action lb_actions (ip_src , ip_dst){

	modify_field(ipv4.srcAddr , ip_src);
	modify_field(ipv4.dstAddr , ip_dst);
	push (vxlan , 100) ;  /* todo : check the value by which we push*/
	/* should I set the DMAC */
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
table lb_selector {
	reads {

		ipv4.dstAddr : exact; /*exact instead of lpm*/ 
}
	actions {
		_nop; /* default, the flow goes directly to ipv4_lpm */
		vxlan_egress ;
		_nop1; /* inorder to set the control flow I used this nop1 to select the Laod Balancer table*/
}
size : 65536;
}
table lb {
	reads{
	ipv4.srcAddr : exact;
	}
	actions{
	lb_actions ;
	}
	}
table l3_fib {
	reads {
			ipv4.dstAddr : lpm;
			/* vlan reads is it optional?? why is it needed?? */
	}
	actions {
			set_next_hop; /* here the action is for already existing outer ethernet header
			should we consider the first stage where the outer field is created ?*/
	}
}

/* Flow Functions */
control ingress {
    apply(smac);
	apply(dmac) {
		_nop {  
					apply (arp_select) ;
					if (ethernet.etherType == 0x0800) {
				      apply (lb_selector) {
						_nop1 {
						apply (lb);
						apply (l3_fib);
						}
						default {
						apply (l3_fib);
						}
				}
			}
				}
				}
				}

control egress {
	
} 