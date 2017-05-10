
#include "header.p4"

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
		return select() {
		default : ingress ;
		}
}
parser parse_arp {
	extract ( arp ) ;
		return select() {
		default : ingress ;
		/* return ingress;*/
		}
}