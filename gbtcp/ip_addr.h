#ifndef GBTCP_IP_ADDR_H
#define GBTCP_IP_ADDR_H

#include "subr.h"

struct gt_ip_addr {
	union {
		be32_t  ipa_4;
		uint8_t ipa_6[GT_IP6_ADDR_LEN];
		uint8_t ipa_data[GT_IP6_ADDR_LEN];
		be32_t  ipa_data_32[4];
		be32_t  ipa_6_32[4];
		be64_t  ipa_6_64[2];
	};
};

extern struct gt_ip_addr gt_ip_addr_zero;

int gt_ip_addr_is_zero(int af, const struct gt_ip_addr *a);

int gt_ip_addr_cmp(int af, const struct gt_ip_addr *a,
	const struct gt_ip_addr *b);

struct gt_ip_addr *gt_ip_addr_cpy(int af, struct gt_ip_addr *dst,
	const struct gt_ip_addr *src);

int gt_ip_addr_pfx(int af, const struct gt_ip_addr *a);

int gt_ip_addr_pton(int af, struct gt_ip_addr *dst, const char *src);

int gt_ip_addr_aton(be32_t *dst, const char *src);

int gt_ip_addr4_is_loopback(be32_t ip);

int gt_ip_addr4_is_mcast(be32_t ip);

int gt_ip_addr4_is_bcast(be32_t ip);

int gt_ip_addr6_is_mcast(const void *ip);

int gt_ip_addr6_is_unspecified(const void *ip);
 
int gt_ip_addr6_is_solicited_node_mcast(const void *ip);

int ip6_is_link_local(const void *ip);

int gt_ip_addr6_net_cmp(const uint8_t *a, const uint8_t *b, int len);

#endif /* GBTCP_IP_ADDR_H */
