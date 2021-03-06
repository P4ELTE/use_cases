/* The Header Declaration */

/* Ethernet */

header_type ethernet_t {
    fields {
        dstAddr   : 48;
        srcAddr   : 48;
        etherType : 16;
    }
}

/* VLAN */

header_type vlanTag_t {
    fields {
        pcp 		: 3;
        cfi 		: 1;
        vid 		: 12;
        etherType 	: 16;
    }
}

/* IPv4 */

header_type ipv4_t {
    fields {
        version        : 4 ;
        ihl            : 4 ;
        diffserv       : 8 ;
        totalLength    : 16 ;
        identification : 16 ;
        flags          : 3 ;
        fragOffset     : 13 ;
        ttl            : 8 ;
        protocol       : 8 ;
        hdrChecksum    : 16 ;
        srcAddr        : 32 ;
        dstAddr        : 32 ;
		/*options        : *;*/ /* it is not used at the moment */
    }
	/*length             : (ihl << 2) ;
    max_length         : 60 ;*/
}

/* IPv6 */

header_type ipv6_t {
    fields {
        version 		: 4;
        trafficClass 	: 8;
        flowLabel 		: 20;
        payloadLen 		: 16;
        nextHdr 		: 8;
        hopLimit 		: 8;
        srcAddr 		: 128;
        dstAddr 		: 128;
    }
}

/* ICMP - TODO extend to use the rest of the header */

header_type icmp_t {
    fields {
        typeCode 	: 16;
        hdrChecksum : 16;
    }
}

/* ARP for IPV4 and Ethernet - TODO: it could be generalized */

header_type arp_t {
    fields {
        hardwareType : 16;
		protocolType : 16;
		hLen         : 8;   /* hardware address length */
		pLen         : 8;   /* protocol address length */
		oper         : 16; 
		senderHA     : 48;  /* ha = hardware address */ 
		senderIP     : 32;
		targetHA     : 48;
		targetIP     : 32;
    }
}

/* GPRS Tunnelling Protocol (GTP) common part for v1 and v2 */

header_type gtpCommon_t {
	fields {
		version			: 3; /* this should be 1 for GTPv1 and 2 for GTPv2 */
		pFlag			: 1; /* protocolType for GTPv1 and pFlag for GTPv2 */
		tFlag			: 1; /* only used by GTPv2 - teid flag */
		eFlag			: 1; /* only used by GTPv1 - E flag */
		sFlag			: 1; /* only used by GTPv1 - S flag */
		pnFlag			: 1; /* only used by GTPv1 - PN flag */
		messageType		: 8;
		messageLength	: 16;
	}
}

header_type gtpTeid_t {
	fields {
		teid	: 32;
	}
}

/* GPRS Tunnelling Protocol (GTP) v1 */

/* 
This header part exists if any of the E, S, or PN flags are on.
*/

header_type gtpv1Optional_t {
	fields {
		sNumber			: 16;
		pnNumber		: 8;
		nextExtHdrType	: 8;
	}
}

/* Extension header if E flag is on. */

header_type gtpv1ExtensionHdr_t {
	fields {
		plength		: 8; /* length in 4-octet units */
		contents	: *; /* TODO: check if T4P4S supports this */
		nextExtHdrType	: 8;
	}
	length 		: ( plength << 2 );
	max_length 	:  128; /* TODO: ??? */
}


/* GPRS Tunnelling Protocol (GTP) v2 (also known as evolved-GTP or eGTP) */


header_type gtpv2Ending_t {
	fields {
		sNumber			: 24;
		reserved		: 8;
	}
}

/* TCP */

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

/* UDP */

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        plength  : 16;
        checksum : 16;
    }
}

/* Local metadata */

header_type gtpMetadata_t {
	fields {
		teid : 32;
		color : 8;
	}
}

header_type arpMetadata_t {
	fields {
		ethSrc		 : 48;
		senderHA     : 48;  /* ha = hardware address */ 
		senderIP     : 32;
		targetHA     : 48;
		targetIP     : 32;
	}
}

header_type routingMetadata_t {
	fields {
		nhgrp		: 8;
	}
}


