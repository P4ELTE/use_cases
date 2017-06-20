/* includes*/ 

/*#include "Includes/headers.p4"*/
/*#include "Includes/parser.p4"




/* Headers*/ 
/* The Header Declaration */

header_type ethernet_t {
    fields {
        dstAddr   : 48;
        srcAddr   : 48;
        etherType : 16;
    }
}
header_type vlan_t {
fields {
pcp             : 3;
cfi             : 1;
vid             : 12;
ethertype       : 16;
}
}

header_type ipv4_t {
    fields {
        version        : 4 ;
        ihl            : 4 ;
        diffserv       : 8 ;
        totalLen       : 16 ;
        identification : 16 ;
        flags          : 3 ;
        fragOffset     : 13 ;
        ttl            : 8 ;
        protocol       : 8 ;
        hdrChecksum    : 16 ;
        srcAddr        : 32 ;
        dstAddr        : 32 ;
		options        : * ;
		
    }
	length             : (ihl << 2) ;
    max_length         : 60 ;
}
header_type arp_t {
    fields {
        hardware_type : 16;
		protocol_type : 16;
		HLEN          : 8;   /* hardware address length */
		PLEN          : 8;   /* protocol address length */
		OPER          : 16; 
		sender_ha     : 48;  /* ha = hardware address */ 
		sender_ip     : 32;
		target_ha     : 48;
		target_ip     : 32;
    }
}
header_type local_metadata_t {
fields {
nexthop : 16 ;
} }

	   
/* Instances */

header ethernet_t ethernet ;
header vlan_t vlan [2] ; 
header ipv4_t ipv4 ;
header arp_t arp ;
metadata local_metadata_t local_metadata ;


/* Field List */

field_list ipv4_checksum_list {
		ipv4.version;
		ipv4.ihl;
		ipv4.diffserv;
		ipv4.totalLen;
		ipv4.identification;
		ipv4.flags;
		ipv4.fragOffset;
		ipv4.ttl;
		ipv4.protocol;
		ipv4.srcAddr;
		ipv4.dstAddr; 
}

#define MAC_LEARN_RECEIVER 1024
#define ARP_RECEIVER 1024

field_list mac_learn_digest {
    ethernet.srcAddr;
	standard_metadata.ingress_port;

}
field_list arp_digest {
		arp.hardware_type ;
		arp.protocol_type;
		arp.HLEN          ;
		arp.PLEN          ;
		arp.OPER           ;
		arp.sender_ha     ;
		arp.sender_ip    ;
		arp.target_ha    ;
		arp.target_ip     ;
		vlan.vid ;
   
}
/* Checksums */


field_list_calculation ipv4_checksum {
input { ipv4_checksum_list; }
algorithm : csum16;
output_width : 16;
}
calculated_field ipv4.hdrChecksum {
verify ipv4_checksum;
update ipv4_checksum;
}









parser start {
	extract(ethernet) ;
		return select(latest.etherType) {
			0x8100 , 0x9100 :  parse_vlan ;
			0x0806  		: parse_arp ;
			0x0800  		: parse_ipv4 ;
			default		    : ingress ;
			/*default : drop */
}
}
parser parse_vlan {
	extract(vlan[next]) ;
		return select(latest.ethertype) {
			0x8100 , 0x9100 :  parse_vlan ;
			0x0806          : parse_arp ;
			0x0800 			: parse_ipv4 ;
			default         : ingress ;
			
}
}
parser parse_ipv4 {
	extract ( ipv4 ) ;
		return ingress ;
		}
		
parser parse_arp {
	extract ( arp ) ;
		return ingress;
		}

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


action set_dmac (d_mac){
	modify_field(ethernet.dstAddr, d_mac);
	}
action save_nxt_hop (nexthop) {

	modify_field(local_metadata.nexthop , nexthop);
	subtract_from_field(ipv4.ttl , 1); 
}


/* I need to set action send to CP */

/* Tables */ 
table smac {
    reads {
		/*standard_metadata.ingress_port : exact;
		/* ingress_metadata.ingress_port : exact; */
        ethernet.srcAddr : exact ;
		vlan    : valid ; /*check!!!! p4 16*/ /* if vlan is valid than read vid */
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
		vlan.vid : exact ;
    }
    actions {
	forward;
	_drop; 
	_nop; 
	}
    size : 512;
}
/*table vrf_select {
	reads {
	vlan.vid : exact ;
	}
	actions {
	 
	_nop; 
	}/* set the virtual port nbr  * 
} */
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
	apply(dmac) {
		_nop {  apply (vrf_select) ;
				apply (arp_select) ;
		         if (ethernet.etherType == 0x0800) {
				      apply (ipv4_lpm) ;
					  apply ( arp_table) ;
					  apply(dmac) ;
				}
			}
				}
				}
control egress {
	
} 

	/* apply ( egress_table ) ; */
