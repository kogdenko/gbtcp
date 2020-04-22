#ifndef GBTCP_ROUTE_H
#define GBTCP_ROUTE_H

#include "subr.h"
#include "arp.h"
#include "dev.h"

#define GT_EPHEMERAL_PORT_MIN 10000
#define GT_EPHEMERAL_PORT_MAX 65535
#define GT_NR_EPHEMERAL_PORTS \
	(GT_EPHEMERAL_PORT_MAX - GT_EPHEMERAL_PORT_MIN + 1)

#define GT_ROUTE_IF_NAME_NETMAP 0 // pipe1{0
#define GT_ROUTE_IF_NAME_OS 1 // pipe1

struct log;

#define ROUTE_LOG_MSG_FOREACH(x) \
	x(if_add) \
	x(if_del) \
	x(ifaddr_add) \
	x(ifaddr_del) \
	x(add) \
	x(del) \
	x(mon_start) \
	x(read) \
	x(rtnl_handler) \
	x(handle_link) \
	x(handle_addr) \
	x(handle_route) \

struct route_mod {
	struct log_scope log_scope;
	ROUTE_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
};

struct gt_route_if_addr {
	struct dlist ria_list;
	struct ipaddr ria_addr;
	int ria_ref_cnt;
	uint16_t ria_cur_ephemeral_port;
};

struct gt_route_if {
	struct dlist rif_list;
	int rif_idx;
	int rif_flags;
	int rif_is_pipe;
	int rif_mtu;
	int rif_nr_addrs;
	int rif_name_len[2];
	struct dlist rif_txq;
	struct gt_route_if_addr **rif_addrs;
	struct ethaddr rif_hwaddr;
	struct dlist rif_routes;
	struct gt_dev rif_dev;
	uint64_t rif_cnt_rx_pkts;
	uint64_t rif_cnt_rx_bytes;
	uint64_t rif_cnt_rx_drop;
	uint64_t rif_cnt_tx_pkts;
	uint64_t rif_cnt_tx_bytes;
	uint64_t rif_cnt_tx_drop;
	char rif_name[NM_IFNAMSIZ];
};

enum gt_route_msg_type {
	GT_ROUTE_MSG_LINK,
	GT_ROUTE_MSG_ADDR,
	GT_ROUTE_MSG_ROUTE
};

enum gt_route_msg_cmd {
	GT_ROUTE_MSG_ADD,
	GT_ROUTE_MSG_DEL,
};

enum gt_route_table {
	GT_ROUTE_TABLE_MAIN,
	GT_ROUTE_TABLE_LOCAL,
};

struct gt_route_entry {
	int rt_af;
	unsigned int rt_pfx;
	struct ipaddr rt_dst;
	struct ipaddr rt_via;
	struct gt_route_if *rt_ifp;
	struct gt_route_if_addr *rt_ifa;
};

struct gt_route_msg_link {
	int rtml_flags;
	struct ethaddr rtml_hwaddr;
	char rtml_name[IFNAMSIZ];
};

struct gt_route_msg_route {
	int rtmr_pfx;
	enum gt_route_table rtmr_table;
	struct ipaddr rtmr_dst;
	struct ipaddr rtmr_via;
};

struct gt_route_msg {
	enum gt_route_msg_cmd rtm_cmd;
	enum gt_route_msg_type rtm_type;
	int rtm_af;
	int rtm_if_idx;
	union {
		struct gt_route_msg_link rtm_link;
		struct ipaddr rtm_addr;
		struct gt_route_msg_route rtm_route;
	};
};

typedef void (*gt_route_msg_f)(struct gt_route_msg *msg);

extern struct dlist gt_route_if_head;
extern int gt_route_rss_q_id;
extern int gt_route_rss_q_cnt;
extern int gt_route_port_pairity;
extern uint8_t gt_route_rss_key[RSSKEYSIZ];
extern int (*gt_route_if_set_link_status_fn)(struct log *log,
	struct gt_route_if *ifp, int add);
extern int (*gt_route_if_not_empty_txr_fn)(struct gt_route_if *ifp,
	struct gt_dev_pkt *pkt);
extern void (*gt_route_if_tx_fn)(struct gt_route_if *ifp,
	struct gt_dev_pkt *pkt);

#define GT_ROUTE_IF_FOREACH(ifp) \
	DLIST_FOREACH(ifp, &gt_route_if_head, rif_list)

#define GT_ROUTE_IF_FOREACH_SAFE(ifp, tmp) \
	DLIST_FOREACH_SAFE(ifp, &gt_route_if_head, rif_list, tmp)

int route_mod_init(struct log *, void **);
int route_mod_attach(struct log *, void *);
void route_mod_deinit(struct log *, void *);
void route_mod_detach(struct log *);

void gt_route_mod_clean(struct log *log);

struct gt_route_if *gt_route_if_get_by_idx(int if_idx);

struct gt_route_if *gt_route_if_get_by_name(const char *if_name,
	int if_name_len, int if_name_type);

struct gt_route_if_addr *route_ifaddr_get(int af,
	const struct ipaddr *a);

struct gt_route_if_addr *gt_route_if_addr_get4(be32_t a4);

int gt_route_get(int af, struct ipaddr *pref_src,
	struct gt_route_entry *route);

int gt_route_get4(be32_t pref_src, struct gt_route_entry *route);

int gt_route_if_not_empty_txr(struct gt_route_if *ifp, struct gt_dev_pkt *pkt);

void gt_route_if_rxr_next(struct gt_route_if *ifp, struct netmap_ring *rxr);

void gt_route_if_tx(struct gt_route_if *ifp, struct gt_dev_pkt *pkt);

int gt_route_if_tx3(struct gt_route_if *ifp, void *data, int len);

int gt_route_read(int fd, gt_route_msg_f fn);

int route_open(struct route_mod *, struct log *);

int gt_route_dump(gt_route_msg_f fn);

static inline struct ipaddr *
gt_route_get_next_hop(struct gt_route_entry *r)
{
	if (!ipaddr_is_zero(AF_INET, &r->rt_via)) {
		return &r->rt_via;
	} else {
		return &r->rt_dst;
	}
}

static inline be32_t
gt_route_get_next_hop4(struct gt_route_entry *r)
{
	if (r->rt_via.ipa_4) {
		return r->rt_via.ipa_4;
	} else {
		return r->rt_dst.ipa_4;
	}
}

#endif /* GBTCP_ROUTE_H */
