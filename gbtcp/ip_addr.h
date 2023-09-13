// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_IPADDR_H
#define GBTCP_IPADDR_H

#include "subr.h"

struct ipaddr {
	union {
		be32_t  ipa_4;
		uint8_t ipa_6[IP6ADDR_LEN];
		uint8_t ipa_data[IP6ADDR_LEN];
		be32_t  ipa_data_32[4];
		be32_t  ipa_6_32[4];
		be64_t  ipa_6_64[2];
	};
};

extern struct ipaddr ipaddr_zero;

int ipaddr_is_zero(int, const struct ipaddr *);
int ipaddr_cmp(int af, const struct ipaddr *, const struct ipaddr *);
struct ipaddr *ipaddr_cpy(int, struct ipaddr *, const struct ipaddr *);
int ipaddr_pfx(int, const struct ipaddr *);
int ipaddr_pton(int, struct ipaddr *, const char *);
int ipaddr_aton(be32_t *, const char *);

int ipaddr4_is_loopback(be32_t);
int ipaddr4_is_mcast(be32_t);
int ipaddr4_is_bcast(be32_t);

int ipaddr6_is_mcast(const void *);
int ipaddr6_is_unspecified(const void *);
int ipaddr6_is_solicited_node_mcast(const void *);
int ip6addr_is_link_local(const void *);
int ipaddr6_net_cmp(const uint8_t *, const uint8_t *, int);

#endif // GBTCP_IPADDR_H
