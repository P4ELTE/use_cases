header ethernet_t ethernet ;
header vlan_t vlan ; 
header ipv4_t ipv4 ;
header arp_t arp ;
metadata local_metadata_t local_metadata ;

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