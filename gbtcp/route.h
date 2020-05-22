// GPL2 license
#ifndef GBTCP_ROUTE_H
#define GBTCP_ROUTE_H

#include "subr.h"
#include "arp.h"
#include "dev.h"
#include "lptree.h"

#define EPHEMERAL_PORT_MIN 10000
#define EPHEMERAL_PORT_MAX 65535
#define NEPHEMERAL_PORTS (EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1)

#define ROUTE_IFNAME_NM 0 // pipe1{0
#define ROUTE_IFNAME_OS 1 // pipe1

struct log;

struct route_entry_long {
	struct lptree_rule rtl_rule;
	struct dlist rtl_list;
	int rtl_af;
	struct route_if *rtl_ifp;
	struct ipaddr rtl_via;
	int rtl_nsrcs;
	struct route_if_addr **rtl_srcs;
};

struct route_mod {
	struct log_scope log_scope;
	struct lptree route_lptree;
	struct mbuf_pool route_pool;
	struct dlist route_if_head;
	struct route_entry_long route_default;
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
	u_char rif_rss_nq;
	int rif_naddrs;
	int rif_name_len[2];
	struct route_if_addr **rif_addrs;
	struct ethaddr rif_hwaddr;
	u_char rif_rss_key[RSS_KEY_SIZE];
	struct dlist rif_routes;
	struct dev rif_host_dev;
	struct dlist PER_SERVICE(rif_txq);
	uint64_t rif_cnt_rx_pkts;
	uint64_t rif_cnt_rx_bytes;
	uint64_t rif_cnt_rx_drop;
	uint64_t rif_cnt_tx_pkts;
	uint64_t rif_cnt_tx_bytes;
	uint64_t rif_cnt_tx_drop;
	struct dev PER_SERVICE(rif_dev)[GT_RSS_NQ_MAX];
	char rif_name[NM_IFNAMSIZ];
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
	u_int rt_pfx;
	struct ipaddr rt_dst;
	struct ipaddr rt_via;
	struct route_if *rt_ifp;
	struct route_if_addr *rt_ifa;
};

struct route_msg_link {
	int rtml_flags;
	struct ethaddr rtml_hwaddr;
	char rtml_name[IFNAMSIZ];
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
	int rtm_if_idx;
	union {
		struct route_msg_link rtm_link;
		struct ipaddr rtm_addr;
		struct route_msg_route rtm_route;
	};
};

typedef void (*route_msg_f)(struct route_msg *);

#define ROUTE_IF_FOREACH(ifp) \
	DLIST_FOREACH(ifp, route_if_head(), rif_list)

int route_mod_init(struct log *, void **);
int route_mod_attach(struct log *, void *);
void route_mod_deinit(struct log *, void *);
void route_mod_detach(struct log *);

struct dlist *route_if_head();
struct route_if *route_if_get_by_ifindex(int);
struct route_if *route_if_get_by_ifname(const char *, int, int);

struct route_if_addr *route_ifaddr_get(int, const struct ipaddr *);
struct route_if_addr *route_ifaddr_get4(be32_t);

int route_get(int af, struct ipaddr *, struct route_entry *);
int route_get4(be32_t, struct route_entry *);

// ???????
int route_if_not_empty_txr(struct route_if *, struct dev_pkt *);
void route_if_rxr_next(struct route_if *, struct netmap_ring *);
void route_if_tx(struct route_if *, struct dev_pkt *);
int route_if_calc_rss_qid(struct route_if *, struct sock_tuple *);

int route_open(struct route_mod *, struct log *);
int route_read(int, route_msg_f);
int route_dump(route_msg_f);

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
