/* The Header Declaration */

header_type ethernet_t {
    fields {
        dstAddr   : 48;
        srcAddr   : 48;
        etherType : 16;
    }
}

/*outer vlan header */
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

header_type udp_t {
    fields {
        src_port       : 16;
		dst_port       : 16;
		length         : 16;   
		checksum       : 16;   
		data           : * ; /*let it or remove it??*/ 
    }
	max_length         : 20 ;
}
header_type vxlan_t {
	fields{           /* generic vxlan header */ 
		/*flags1    : 4;
		i_bit     : 1;
		flags2    : 3;*/
		RRRRIRRR  : 8; /* flags byte where R for reserved flags and I bit for Vxlan ID */
		reserved1  : 24; 
		vni        : 24 ; /* vxlan network Identifier */
		reserved2  : 8;   /* reserved field should be set to 0s at the transmition */		
	}
}
header_type local_metadata_t {
fields {
nexthop : 16 ;
}}

	   
/* Instances */

header ethernet_t ethernet ;
header vlan_t vlan ; 
header ipv4_t ipv4 ;
header arp_t arp ;
header udp_t udp ;
header vxlan_t vxlan ;
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
		arp.protocol_type ;
		arp.HLEN          ;
		arp.PLEN          ;
		arp.OPER          ;
		arp.sender_ha     ;
		arp.sender_ip     ;
		arp.target_ha     ;
		arp.target_ip     ;
   
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
