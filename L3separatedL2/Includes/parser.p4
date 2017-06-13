

parser start {
	extract(ethernet) ;
		return select(latest.etherType) {
			0x0806  : parse_arp ;
			0x0800  : parse_ipv4 ;
			default : ingress ;
			/*default : drop */
}
}
parser parse_ipv4 {
	extract ( ipv4 ) ;
		return ingress
		}
}
parser parse_arp {
	extract ( arp ) ;
		return ingress;
		}
}		