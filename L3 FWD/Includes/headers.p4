
/* The Header Declaration */

header_type ethernet_t {
    fields {
        dstAddr   : 48;
        srcAddr   : 48;
        etherType : 16;
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
	Length             : (ihl << 2) ;
    max_length         : 60 ;
}
header_type arp_t {
    fields {
        hardware_type : 16;
		protocol_type : 16;
		HLEN          : 8;   /* hardware address length */
		PLEN          : 8;   /* protocol address length */
		/* operation  OPER   : 16; */
		sender_ha     : 48;  /* ha = hardware address */ 
		sender_ip     : 32;
		target_ha     : 48;
		target_ip     : 32;
    }
}

header_type ingress_metadata_t {
	fields {
/* Inputs */
		ingress_port          : 9; /* Available prior to parsing */
		packet_length         : 16; /* Might not be always available */
		instance_type         : 2; /* Normal, clone, recirculated */
		ingress_global_tstamp : 48;
		parser_status         : 8; /* Parsing Error */
/* Outputs from Ingress Pipeline */
		egress_spec           : 16;
		queue_id              : 9;
}
}	
	   
/* Instances */
header ethernet_t ethernet ;
header ipv4_t ipv4 ;
header arp_t arp ;
metadata ingress_metadata_t ingress_metadata ;
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

field_list mac_learn_digest {
    ethernet.srcAddr;
	standard_metadata.ingress_port;

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

