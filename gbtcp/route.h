/* GPL2 license */
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

struct gt_route_entry_long {
	struct lprule rtl_rule;
	struct dlist rtl_list;
	int rtl_af;
	struct route_if *rtl_ifp;
	struct ipaddr rtl_via;
	int rtl_nr_saddrs;
	struct gt_route_if_addr **rtl_saddrs;
};

struct route_mod {
	struct log_scope log_scope;
	u_char route_rss_key[RSS_KEY_SIZE];
	struct lptree route_lptree;
	struct mbuf_pool route_pool;
	struct dlist route_if_head;
	struct gt_route_entry_long route_default;
	struct dlist route_addr_head;
};

struct gt_route_if_addr {
	struct dlist ria_list;
	struct ipaddr ria_addr;
	int ria_ref_cnt;
	uint16_t ria_cur_ephemeral_port;
};

struct route_if {
	struct dlist rif_list;
	int rifindex;
	int rifflags;
	int rif_is_pipe;
	int rif_mtu;
	int rif_nr_addrs;
	int rifname_len[2];
	struct gt_route_if_addr **rif_addrs;
	struct ethaddr rif_hwaddr;
	struct dlist rif_routes;
	struct dev rif_host_dev;
	struct dev rif_dev[GT_SERVICE_COUNT_MAX];
	struct dlist rif_txq[GT_SERVICE_COUNT_MAX];
	uint64_t rif_cnt_rx_pkts;
	uint64_t rif_cnt_rx_bytes;
	uint64_t rif_cnt_rx_drop;
	uint64_t rif_cnt_tx_pkts;
	uint64_t rif_cnt_tx_bytes;
	uint64_t rif_cnt_tx_drop;
	char rifname[NM_IFNAMSIZ];
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
	struct route_if *rt_ifp;
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

int route_mod_init(struct log *, void **);
int route_mod_attach(struct log *, void *);
int route_proc_init(struct log *, struct proc *);
void route_mod_deinit(struct log *, void *);
void route_mod_detach(struct log *);

void gt_route_mod_clean(struct log *log);

struct route_if *gt_route_if_get_by_idx(int if_idx);

struct route_if *gt_route_if_get_by_name(const char *if_name,
	int if_name_len, int if_name_type);

struct gt_route_if_addr *route_ifaddr_get(int af,
	const struct ipaddr *a);

void route_set_rss_qid(struct log *);
int route_calc_rss_qid(struct sock_tuple *, int);

struct gt_route_if_addr *gt_route_if_addr_get4(be32_t a4);

int gt_route_get(int af, struct ipaddr *pref_src,
	struct gt_route_entry *route);

int gt_route_get4(be32_t pref_src, struct gt_route_entry *route);

int gt_route_if_not_empty_txr(struct route_if *ifp, struct dev_pkt *pkt);

void gt_route_if_rxr_next(struct route_if *ifp, struct netmap_ring *rxr);

void gt_route_if_tx(struct route_if *ifp, struct dev_pkt *pkt);

int gt_route_if_tx3(struct route_if *ifp, void *data, int len);

int gt_route_read(int fd, gt_route_msg_f fn);

int route_open(struct route_mod *, struct log *);

int route_dump(gt_route_msg_f fn);



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
