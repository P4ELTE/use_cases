/* Defines */

#define ETHERTYPE_VLAN         0x8100
#define ETHERTYPE_IPV4         0x0800
#define ETHERTYPE_IPV6         0x86dd
#define ETHERTYPE_ARP          0x0806

/* TODO think of IP fragmantation */

#define IP_PROTOCOL_ICMP              1
#define IP_PROTOCOL_IPV4              4
#define IP_PROTOCOL_TCP               6
#define IP_PROTOCOL_UDP               17
#define IP_PROTOCOL_IPV6              41

#define GTP_UDP_PORT		2152
#define GW_IP				10.0.0.1


/* Header instances */

header ethernet_t ethernet;
header vlanTag_t vlan;
header ipv4_t ipv4;
header ipv4_t innerIpv4;
header arp_t arp;
header icmp_t icmp;
header gtpCommon_t gtp;
header gtpTeid_t gtpTeid;
header gtpv1Optional_t gtpv1Optional;
header gtpv1ExtensionHdr_t gtpv1ExtensionHdr;
header gtpv2Ending_t gtpv2Ending;
header udp_t udp;

/* Metadata instances */ 

metadata gtpMetadata_t gtpMetadata;
metadata arpMetadata_t arpMetadata;

/* Parsing */

parser start {
	return parse_ethernet;
}

parser parse_ethernet {
	extract(ethernet);
	return select(latest.etherType) {
		ETHERTYPE_ARP	: parse_arp;
		ETHERTYPE_IPV4  : parse_ipv4;
		/*ETHERTYPE_VLAN	: parse_vlan;
		ETHERTYPE_IPV6	: parse_ipv6;*/		
		default : ingress;
	}
}

parser parse_ipv4 {
	extract ( ipv4 ) ;
	return select(latest.protocol) {
		IP_PROTOCOL_ICMP	: parse_icmp;
		IP_PROTOCOL_UDP		: parse_udp;
		default	: ingress;
	}
}

parser parse_arp {
	extract ( arp ) ;
	
	set_metadata( arpMetadata.ethSrc, ethernet.srcAddr );
	set_metadata( arpMetadata.senderHA, latest.senderHA );
	set_metadata( arpMetadata.senderIP, latest.senderIP );
	set_metadata( arpMetadata.targetHA, latest.targetHA );
	set_metadata( arpMetadata.targetIP, latest.targetIP );
	return ingress;
}

parser parse_icmp {
	extract( icmp );
	return ingress;
}

parser parse_udp {
	extract( udp );
	return select (latest.dstPort) {
		GTP_UDP_PORT	: parse_gtp;
		default	: ingress;
	}
}

parser parse_gtp {
	extract( gtp );
	return select(latest.version, latest.tFlag) {
		0x2, 0x3, 0x5	: parse_teid;
		0x4 : parse_gtpv2;
		default : ingress; /* TODO: use parse_error instead */
	}
}

parser parse_teid {
	extract( gtpTeid );
	return select( gtp.version, gtp.eFlag, gtp.sFlag, gtp.pnFlag ) {
		0x10 mask 0x18 : parse_gtpv2; /* v2 */
		0x0c mask 0x1c : parse_gtpv1optional; /* v1 + E */
		0x0a mask 0x1a : parse_gtpv1optional; /* v1 + S */
		0x09 mask 0x19 : parse_gtpv1optional; /* v1 + PN */
		default 	: parse_inner;
	}
}

parser parse_gtpv1optional {
	extract( gtpv1Optional );
	return parse_inner; /* TODO: nexthdr should be handled !!! */
}

parser parse_inner {
	extract( innerIpv4 );
	return ingress;
}


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

field_list_calculation ipv4_checksum {
	input { ipv4_checksum_list; }
	algorithm : csum16;
	output_width : 16;
}

calculated_field ipv4.hdrChecksum {
	verify ipv4_checksum;
	update ipv4_checksum;
}

field_list innerIpv4_checksum_list {
        innerIpv4.version;
        innerIpv4.ihl;
        innerIpv4.diffserv;
        innerIpv4.totalLen;
        innerIpv4.identification;
        innerIpv4.flags;
        innerIpv4.fragOffset;
        innerIpv4.ttl;
        innerIpv4.protocol;
        innerIpv4.srcAddr;
        innerIpv4.dstAddr;
}

field_list_calculation innerIpv4_checksum {
    input {
        innerIpv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field innerIpv4.hdrChecksum {
    verify innerIpv4_checksum if (inner_ipv4.ihl == 5);
    update innerIpv4_checksum if (inner_ipv4.ihl == 5);
}
