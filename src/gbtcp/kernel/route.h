// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_ROUTE_H
#define GBTCP_ROUTE_H

#include <gbtcp/kernel/arp.h>
#include <gbtcp/kernel/dev.h>
#include <gbtcp/kernel/ip_addr.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/lptree.h>
#include <gbtcp/kernel/subr.h>

#define EPHEMERAL_PORT_MIN 10000
#define EPHEMERAL_PORT_MAX 65535
#define NEPHEMERAL_PORTS (EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1)

struct route_if_addr {
	struct gt_dlist ria_list;
	struct ipaddr ria_addr;
	int ria_ref_cnt;
	uint16_t ria_ephemeral_port;
};

#define PER_SERVICE(x) x[GT_SERVICE_COUNT_MAX]

struct route_if {
	struct gt_dlist rif_list;
	int rif_index;
	u32 rif_flags;
	int rif_mtu;
	u_char rif_rss_queue_num;
	int rif_n_addrs;
	struct route_if_addr **rif_addrs;
	struct gt_eth_addr rif_hwaddr;
	struct gt_rss rif_rss;
	struct gt_dlist rif_routes;

	u8 rif_dev_io;
	struct dev rif_host_dev;
	struct dev rif_dev[GT_SERVICES_MAX][GT_RSS_NQ_MAX];

	counter64_t rif_rx_pkts;
	counter64_t rif_rx_bytes;
	counter64_t rif_rx_drop;
	counter64_t rif_tx_pkts;
	counter64_t rif_tx_bytes;
	counter64_t rif_tx_drop;

	char rif_name[IFNAMSIZ];
};

struct route_entry {
	int rt_af;
	u_char rt_pfx;
	struct ipaddr rt_dst;
	struct ipaddr rt_via;
	struct route_if *rt_ifp;
	struct route_if_addr *rt_ifa;
};

#define ROUTE_IF_FOREACH(ifp) GT_DLIST_FOREACH(ifp, route_if_head(), rif_list)

#define ROUTE_IF_FOREACH_RCU(ifp) \
	GT_DLIST_FOREACH_RCU(ifp, route_if_head(), rif_list)

int gt_route_init(void);
void route_mod_deinit(void);

struct gt_dlist *route_if_head(void);
struct route_if *route_if_get_by_index(int);
//struct route_if *route_if_get_by_ifname(const char *, int, int);

struct route_if_addr *route_ifaddr_get(int, const struct ipaddr *);
struct route_if_addr *route_ifaddr_get4(be32_t);
int route_ifaddr_add(struct route_if_addr **ifap, struct route_if *ifp,
		     const struct ipaddr *addr);
int route_ifaddr_del(struct route_if *, const struct ipaddr *);

int route_get(int af, struct ipaddr *, struct route_entry *);
int route_get4(be32_t, struct route_entry *);
int route_add(struct route_entry *a);
int gt_route_del(be32_t dst, int pfx);

int route_get_tx_packet(struct route_if *, struct dev_pkt *, int);
void route_transmit(struct route_if *, struct dev_pkt *);

typedef void (*gt_on_dev_f)(u8 is_add, struct route_if *ifp);
int gt_add_on_dev_handler(gt_on_dev_f fn);

#ifdef __linux__
int netlink_link_del(const char *);
int netlink_link_get_flags(int);
int netlink_link_up(int, const char *, int);
#endif

static inline struct ipaddr *
route_get_next_hop(struct route_entry *r)
{
	if (!ipaddr_is_zero(AF_INET, &r->rt_via)) {
		return &r->rt_via;
	} else {
		return &r->rt_dst;
	}
}

static inline be32_t
route_get_next_hop4(struct route_entry *r)
{
	if (r->rt_via.ipa_4) {
		return r->rt_via.ipa_4;
	} else {
		return r->rt_dst.ipa_4;
	}
}

#endif // GBTCP_ROUTE_H
