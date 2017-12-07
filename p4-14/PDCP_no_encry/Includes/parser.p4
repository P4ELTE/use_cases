
parser start {
	extract(ethernet) ;
		return select(latest.etherType) {
		/*	0x8100 , 0x9100 :  parse_vlan ; */
			0x0806  		: parse_arp ;
			0x0800  		: parse_ipv4 ;
			default		    : ingress ;
			/*default : drop */
}
} 
parser parse_arp {
	extract ( arp ) ;
		return ingress;
		}
parser parse_ipv4 {
	extract ( ipv4 ) ;
		return select(latest.protocol) {
			0x11      : parse_udp ;
			default   : ingress ;
		}		
		}

parser parse_udp {
	extract( udp );
	return select (latest.dstPort) {
		2125	: parse_gtp;
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