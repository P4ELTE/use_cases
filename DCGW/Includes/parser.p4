

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
	extract(vlan) ;
		return select(latest.ethertype) {
			0x8100 , 0x9100 :  parse_vlan ;
			0x0806          : parse_arp   ;
			0x0800 			: parse_ipv4  ;
			default         : ingress     ;
			
}
}
parser parse_ipv4 {
	extract ( ipv4 ) ;
		return select(latest.protocol) {
			0x11      : parse_udp ;
			default   : ingress ;
		}		
		}
parser parse_udp {        /* is it correct to make default parse vxlan */
	extract ( udp ) ;
		return  parse_vxlan;
		}		
parser parse_vxlan {
	extract (vxlan);
		return ingress;
		}
parser parse_arp {
	extract ( arp ) ;
		return ingress;
		}