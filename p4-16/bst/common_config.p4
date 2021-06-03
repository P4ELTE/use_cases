
// This P4 file contains only a preamble, it is not meant to be used on its own.

#ifndef _COMMON_CONFIG_P4_
#define _COMMON_CONFIG_P4_

#undef __TARGET_PSA__
#undef __TARGET_V1__

#include <core.p4>

#ifdef __TARGET_TOFINO__
 #if __TARGET_TOFINO__ == 2
  #include <t2na.p4>
 #else
  #include <tna.p4>
 #endif
#else // x86: might be PSA or v1 model, select here
// #define USE_PSA 1
 #ifdef USE_PSA
  #include <psa.p4>
  #define __TARGET_PSA__ 1
 #else
  #include <v1model.p4>
  #define __TARGET_V1__ 1
 #endif
#endif

#include "common/headers.p4"
#include "common/util.p4"

#ifdef __TARGET_V1__
struct mac_learn_digest {
    bit<48>  src_addr;
    PortId_t ingress_port;
}

struct arp_digest {
    bit<32> ip;                // destination (or nexthop)
    bit<48> mac;        // own MAC address to be used as SHA in ARP request
}
#else
struct mac_learn_digest_data {
    bit<48>  src_addr;
    PortId_t ingress_port;
}

struct arp_digest_data {
    bit<32> ip;                // destination (or nexthop)
    bit<48> mac;        // own MAC address to be used as SHA in ARP request
}

#endif

struct ppv_digest_t {
    bit<32> vql4s;
    bit<32> vqcl;
    bit<48> ts;
}

#endif // COMMON_CONFIG
