// GPL v2 license
#ifndef GBTCP_ROUTE_H
#define GBTCP_ROUTE_H

#include "subr.h"
#include "ip_addr.h"
#include "arp.h"
#include "dev.h"
#include "lptree.h"

#define EPHEMERAL_PORT_MIN 10000
#define EPHEMERAL_PORT_MAX 65535
#define NEPHEMERAL_PORTS (EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1)

struct route_mod {
	struct log_scope log_scope;
	struct lptree route_lptree;
	struct mbuf_pool *route_pool;
	struct dlist route_if_head;
	struct route_entry_long *route_default;
	struct dlist route_addr_head;
};

struct route_if_addr {
	struct dlist ria_list;
	struct ipaddr ria_addr;
	int ria_ref_cnt;
	uint16_t ria_ephemeral_port;
};

#define PER_SERVICE(x) x[GT_SERVICE_COUNT_MAX]

struct route_if {
	struct dlist rif_list;
	int rif_index;
	int rif_flags;
	int rif_mtu;
	u_char rif_rss_queue_num;
	int rif_n_addrs;
	struct route_if_addr **rif_addrs;
	struct eth_addr rif_hwaddr;
	u_char rif_rss_key[RSS_KEY_SIZE];
	struct dlist rif_routes;
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

enum route_msg_type {
	ROUTE_MSG_LINK,
	ROUTE_MSG_ADDR,
	ROUTE_MSG_ROUTE
};

enum route_msg_cmd {
	ROUTE_MSG_ADD,
	ROUTE_MSG_DEL,
};

enum route_table {
	ROUTE_TABLE_MAIN,
	ROUTE_TABLE_LOCAL,
};

struct route_entry {
	int rt_af;
	u_char rt_pfx;
	struct ipaddr rt_dst;
	struct ipaddr rt_via;
	struct route_if *rt_ifp;
	struct route_if_addr *rt_ifa;
};

struct route_msg_link {
	int rtml_flags;
	struct eth_addr rtml_hwaddr;
};

struct route_msg_route {
	int rtmr_pfx;
	enum route_table rtmr_table;
	struct ipaddr rtmr_dst;
	struct ipaddr rtmr_via;
};

struct route_msg {
	enum route_msg_cmd rtm_cmd;
	enum route_msg_type rtm_type;
	int rtm_af;
	int rtm_ifindex;
	union {
		struct route_msg_link rtm_link;
		struct ipaddr rtm_addr;
		struct route_msg_route rtm_route;
	};
};

typedef void (*route_msg_f)(struct route_msg *, void *);

#define ROUTE_IF_FOREACH(ifp) \
	DLIST_FOREACH(ifp, route_if_head(), rif_list)

#define ROUTE_IF_FOREACH_RCU(ifp) \
	DLIST_FOREACH_RCU(ifp, route_if_head(), rif_list)

int route_mod_init(void);
void route_mod_deinit(void);

struct dlist *route_if_head(void);
struct route_if *route_if_get_by_index(int);
//struct route_if *route_if_get_by_ifname(const char *, int, int);

struct route_if_addr *route_ifaddr_get(int, const struct ipaddr *);
struct route_if_addr *route_ifaddr_get4(be32_t);

int route_get(int af, struct ipaddr *, struct route_entry *);
int route_get4(be32_t, struct route_entry *);

int route_get_tx_packet(struct route_if *, struct dev_pkt *, int);
void route_transmit(struct route_if *, struct dev_pkt *);

int route_open(void);
int route_read(int, route_msg_f, void *);
int route_dump(route_msg_f, void *);

#ifdef __linux__
int netlink_veth_add(const char *, const char *);
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
