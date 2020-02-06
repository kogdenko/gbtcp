#include "arp.h"
#include "log.h"
#include "sys.h"
#include "timer.h"
#include "htable.h"
#include "inet.h"
#include "route.h"
#include "ctl.h"
#include "strbuf.h"
#include "route.h"

#define GT_ARP_REACHABLE_TIME (30 * GT_SEC)
#define GT_ARP_RETRANS_TIMER GT_SEC
#define GT_ARP_MAX_UNICAST_SOLICIT 3
#define GT_ARP_MIN_RANDOM_FACTOR 0.5
#define GT_ARP_MAX_RANDOM_FACTOR 1.5

#define ARP_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(mod_deinit) \
	x(alloc) \
	x(del) \
	x(probe_timeout) \
	x(set_state) \
	x(resolve) \
	x(update) \
	x(add) \

enum gt_arp_state {
	GT_ARP_NONE = 0,
	GT_ARP_INCOMPLETE,
	GT_ARP_REACHABLE,
	GT_ARP_STALE,
	GT_ARP_PROBE
};

struct gt_arp_entry {
	struct gt_mbuf ae_mbuf;
#define ae_list ae_mbuf.mb_list
	be32_t ae_next_hop;
	short ae_state;
	short ae_admin;
	short ae_nprobes;
	gt_time_t ae_confirmed;
	struct gt_timer ae_timer;
	struct gt_eth_addr ae_addr;
	struct gt_dev_pkt *ae_incq;
};

static struct gt_mbuf_pool *gt_arp_entry_pool;
static struct gt_mbuf_pool *gt_arp_pkt_pool;
static gt_htable_t gt_arp_htable;
static gt_time_t gt_arp_reachable_time;
static struct gt_timer gt_arp_timer_calc_reachable_time;
static struct gt_log_scope this_log;
ARP_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static void gt_arp_probe_timeout(struct gt_timer *timer);

static void gt_arp_calc_reachable_time_timeout(struct gt_timer *timer);

static void gt_arp_entry_del(struct gt_log *log, struct gt_arp_entry *e);

static const char *
gt_arp_state_str(int state)
{
	switch (state) {
	case GT_ARP_NONE: return "NONE";
	case GT_ARP_INCOMPLETE: return "INCOMPLETE";
	case GT_ARP_REACHABLE: return "REACHABLE";
	case GT_ARP_STALE: return "STALE";
	case GT_ARP_PROBE: return "PROBE";
	default: return "???";
	}
}

static inline void
gt_arp_set_eth_hdr(struct gt_arp_entry *e, struct gt_route_if *ifp,
	uint8_t *data)
{
	struct gt_eth_hdr *eh;

	eh = (struct gt_eth_hdr *)data;
	eh->ethh_type = GT_ETH_TYPE_IP4_BE;
	eh->ethh_saddr = ifp->rif_hwaddr;
	eh->ethh_daddr = e->ae_addr;
}

static void
gt_arp_entry_add_incomplete(struct gt_log *log, struct gt_arp_entry *e,
	struct gt_dev_pkt *pkt)
{
	int rc;
	struct gt_dev_pkt *cp;

	if (e->ae_incq != NULL) {
		cp = e->ae_incq;
		e->ae_incq = NULL;
		gt_arps.arps_dropped++;
	} else {
		rc = gt_mbuf_alloc(log, gt_arp_pkt_pool,
		                   (struct gt_mbuf **)&cp);
		if (rc) {
			gt_arps.arps_dropped++;
			return;
		}
	}
	if (cp != NULL) {
		cp->pkt_len = pkt->pkt_len;
		cp->pkt_data = (uint8_t *)cp + sizeof(*cp);
		GT_PKT_COPY(cp->pkt_data, pkt->pkt_data, pkt->pkt_len);
		e->ae_incq = cp;
	}
}

static void
arp_txincq(struct gt_arp_entry *e)
{
	int rc;
	be32_t next_hop;
	struct gt_ip4_hdr *ip4_h;
	struct gt_route_entry route;
	struct gt_dev_pkt pkt, *x;

	x = e->ae_incq;
	e->ae_incq = NULL;
	if (x == NULL) {
		return;
	}
	ip4_h = (struct gt_ip4_hdr *)(((struct gt_eth_hdr *)x->pkt_data) + 1);
	route.rt_dst.ipa_4 = ip4_h->ip4h_daddr;
	rc = gt_route_get(AF_INET, NULL, &route);
	if (rc) {
		goto drop;
	}
	next_hop = gt_route_get_next_hop4(&route);
	if (e->ae_next_hop != next_hop) {
drop:
		gt_mbuf_free(&x->pkt_mbuf);
		gt_arps.arps_dropped++;
		return;
	}
	rc = gt_route_if_not_empty_txr(route.rt_ifp, &pkt);
	if (rc) {
		route.rt_ifp->rif_cnt_tx_drop++;
	} else {
		GT_PKT_COPY(pkt.pkt_data, x->pkt_data, x->pkt_len);
		pkt.pkt_len = x->pkt_len;
		gt_arp_set_eth_hdr(e, route.rt_ifp, pkt.pkt_data);
		gt_route_if_tx(route.rt_ifp, &pkt);
	}
	gt_mbuf_free(&x->pkt_mbuf);
}

static int
gt_arp_fill_probe4(struct gt_eth_hdr *eh, be32_t sip, be32_t dip)
{
	struct gt_arp_hdr *arp_h;

	arp_h = (struct gt_arp_hdr *)(eh + 1);
	eh->ethh_type = GT_ETH_TYPE_ARP_BE;
	memset(&eh->ethh_daddr, 0xff, sizeof(eh->ethh_daddr));
	arp_h->arph_hrd = GT_ARP_HRD_ETH_BE;
	arp_h->arph_pro = GT_ETH_TYPE_IP4_BE;
	arp_h->arph_hlen = GT_ETH_ADDR_LEN;
	arp_h->arph_plen = 4;
	arp_h->arph_op = GT_ARP_OP_REQUEST_BE;
	arp_h->arph_data.arpip_sha = eh->ethh_saddr;
	arp_h->arph_data.arpip_tha = eh->ethh_daddr;
	arp_h->arph_data.arpip_tip = dip;
	arp_h->arph_data.arpip_sip = sip;
	return sizeof(*eh) + sizeof(*arp_h);
}

static void
gt_arp_tx_probe(struct gt_arp_entry *e)
{
	int rc, len;
	struct gt_eth_hdr *eh;
	struct gt_route_entry route;
	struct gt_dev_pkt pkt;

	if (gt_timer_is_running(&e->ae_timer)) {
		return;
	}
	e->ae_nprobes++;
	gt_timer_set(&e->ae_timer, GT_ARP_RETRANS_TIMER, gt_arp_probe_timeout);
	route.rt_dst.ipa_4 = e->ae_next_hop;
	rc = gt_route_get(AF_INET, NULL, &route);
	if (rc) {
		return;
	}
	rc = gt_route_if_not_empty_txr(route.rt_ifp, &pkt);
	if (rc) {
		route.rt_ifp->rif_cnt_tx_drop++;
		return;
	}
	eh = (struct gt_eth_hdr *)pkt.pkt_data;
	eh->ethh_saddr = route.rt_ifp->rif_hwaddr;
	if (AF_INET == AF_INET) {
		len = gt_arp_fill_probe4(eh, route.rt_ifa->ria_addr.ipa_4,
		                         e->ae_next_hop);
	} else {
		GT_BUG;
	}
	pkt.pkt_len = len;
	gt_route_if_tx(route.rt_ifp, &pkt);
	gt_arps.arps_txrequests++;
}

static uint32_t
gt_arp_hash(void *ep)
{
	uint32_t h;
	struct gt_arp_entry *e;

	e = ep;
	h = gt_custom_hash32(e->ae_next_hop, 0);
	return h;
}

static void
gt_arp_timer_set_calc_reachable_time()
{
	gt_timer_set(&gt_arp_timer_calc_reachable_time,
	             2 * 60 * 60 * GT_SEC, // 2 Hours
	             gt_arp_calc_reachable_time_timeout);
}

static gt_time_t
gt_arp_calc_reachable_time()
{
	double x, min, max;

	min = GT_ARP_REACHABLE_TIME * GT_ARP_MIN_RANDOM_FACTOR;
	max = GT_ARP_REACHABLE_TIME * GT_ARP_MAX_RANDOM_FACTOR;
	x = gt_rand64();
	x = min + (max - min) * x / UINT64_MAX;
	GT_ASSERT(x >= min);
	GT_ASSERT(x <= max);
	return x;
}

static void
gt_arp_calc_reachable_time_timeout(struct gt_timer *timer)
{
	gt_arp_reachable_time = gt_arp_calc_reachable_time();
	gt_arp_timer_set_calc_reachable_time();
}

static int
gt_arp_ctl_add(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc;
	struct gt_ip_addr next_hop;
	struct gt_eth_addr addr;
	char next_hop_buf[64];
	char addr_buf[64];

	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%64[^,],%64[^,]", next_hop_buf, addr_buf);
	if (rc != 2) {
		return -EINVAL;
	}
	rc = gt_ip_addr_pton(AF_INET, &next_hop, next_hop_buf);
	if (rc) {
		return rc;
	}
	rc = gt_eth_addr_aton(&addr, addr_buf);
	if (rc) {
		return rc;
	}
	rc = gt_arp_add(next_hop.ipa_4, &addr);
	return rc;
}

static int
gt_arp_ctl_list_next(void *udata, int id)
{
	int mbuf_id;
	struct gt_mbuf *mbuf;

	mbuf = gt_mbuf_next(gt_arp_entry_pool, id);
	if (mbuf == NULL) {
		return -EINVAL;
	} else {
		mbuf_id = gt_mbuf_get_id(gt_arp_entry_pool, mbuf);
		return mbuf_id;
	}
}

static int
gt_arp_ctl_list(void *udata, int id, const char *new, struct gt_strbuf *out)
{
	const char *str;
	struct gt_arp_entry *e;

	e = (struct gt_arp_entry *)gt_mbuf_get(gt_arp_entry_pool, id);
	if (e == NULL) {
		return -EINVAL;
	}
	gt_strbuf_add_ip_addr(out, AF_INET, &e->ae_next_hop);
	gt_strbuf_add_ch(out, ',');
	gt_strbuf_add_eth_addr(out, &e->ae_addr);
	gt_strbuf_add_ch(out, ',');
	str = gt_arp_state_str(e->ae_state);
	gt_strbuf_add_str(out, str);
	return 0;
}

int
gt_arp_mod_init()
{
	int rc;
	struct gt_log *log;

	gt_log_scope_init(&this_log, "arp");
	ARP_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	rc = gt_htable_create(log, &gt_arp_htable, 32, gt_arp_hash);
	if (rc) {
		return rc;
	}
	rc = gt_mbuf_pool_new(log, &gt_arp_entry_pool,
	                      sizeof(struct gt_arp_entry));
	if (rc) {
		gt_htable_free(&gt_arp_htable);
		return rc;
	}
	rc = gt_mbuf_pool_new(log, &gt_arp_pkt_pool, GT_DEV_PKT_SIZE);
	if (rc) {
		gt_mbuf_pool_del(gt_arp_entry_pool);
		gt_htable_free(&gt_arp_htable);
		return rc;
	}
	gt_arp_reachable_time = gt_arp_calc_reachable_time();
	gt_timer_init(&gt_arp_timer_calc_reachable_time);
	gt_arp_timer_set_calc_reachable_time();
	gt_ctl_add(log, "arp.add", GT_CTL_WR,
	           NULL, NULL, gt_arp_ctl_add);
	gt_ctl_add_list(log, ".arp.list", GT_CTL_RD, NULL,
	                gt_arp_ctl_list_next, gt_arp_ctl_list);
	return 0;
}

void
gt_arp_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_ctl_del(log, "arp.add");
	gt_ctl_del(log, "arp.list");
	gt_htable_free(&gt_arp_htable);
	gt_mbuf_pool_del(gt_arp_pkt_pool);
	gt_mbuf_pool_del(gt_arp_entry_pool);
	gt_timer_del(&gt_arp_timer_calc_reachable_time);
	gt_log_scope_deinit(log, &this_log);
}

static inline void
gt_arp_set_state(struct gt_log *log, struct gt_arp_entry *e, int state)
{
	log = GT_LOG_TRACE(log, set_state);
	GT_LOGF(log, LOG_INFO, 0, "hit; state=%s->%s, next_hop=%s",
	        gt_arp_state_str(e->ae_state), gt_arp_state_str(state),
	        gt_log_add_ip_addr(AF_INET, &e->ae_next_hop));
	e->ae_state = state;
	if (state == GT_ARP_REACHABLE) {
		gt_timer_del(&e->ae_timer);
		e->ae_confirmed = gt_nsec;
		e->ae_nprobes = 0;
	}
}

static int
gt_arp_entry_alloc(struct gt_log *log, struct gt_arp_entry **ep,
	be32_t next_hop)
{
	int rc;
	struct gt_arp_entry *e;

	log = GT_LOG_TRACE(log, alloc);
	rc = gt_mbuf_alloc(log, gt_arp_entry_pool, (struct gt_mbuf **)ep);
	if (rc) {
		return rc;
	}
	e = *ep;
	e->ae_nprobes = 0;
	e->ae_incq = NULL;
	e->ae_state = 0;
	e->ae_admin = 0;
	gt_timer_init(&e->ae_timer);
	e->ae_next_hop = next_hop;
	gt_htable_add(&gt_arp_htable, (struct dllist *)e);
	return 0;
}

static void
gt_arp_entry_del(struct gt_log *log,struct gt_arp_entry *e)
{
	log = GT_LOG_TRACE(log, del);
	gt_htable_del(&gt_arp_htable, (struct dllist *)e);
	gt_timer_del(&e->ae_timer);
	gt_arp_set_state(log, e, GT_ARP_NONE);
	gt_mbuf_free(&e->ae_incq->pkt_mbuf);
	gt_mbuf_free(&e->ae_mbuf);
}



static struct gt_arp_entry *
gt_arp_entry_get(be32_t next_hop)
{
	uint32_t hash;
	struct dllist *bucket;
	struct gt_arp_entry *e;

	hash = gt_custom_hash32(next_hop, 0);
	bucket = gt_htable_bucket(&gt_arp_htable, hash);
	DLLIST_FOREACH(e, bucket, ae_list) {
		if (e->ae_next_hop == next_hop) {
			return e;
		}
	}
	return NULL;
}

static int
gt_arp_is_probeing(int state)
{
	return state == GT_ARP_INCOMPLETE || state == GT_ARP_PROBE;
}

static void
gt_arp_probe_timeout(struct gt_timer *timer)
{
	struct gt_log *log;
	struct gt_arp_entry *e;

	gt_arps.arps_timeouts++;
	e = container_of(timer, struct gt_arp_entry, ae_timer);
	if (!gt_arp_is_probeing(e->ae_state)) {
		return;
	}
	if (e->ae_nprobes >= GT_ARP_MAX_UNICAST_SOLICIT) {
		log = GT_LOG_TRACE1(probe_timeout);
		gt_arp_entry_del(log, e);
	} else {
		gt_arp_tx_probe(e);
	}
}

static int
gt_arp_entry_is_reachable_timeouted(struct gt_arp_entry *e)
{
	if (e->ae_state != GT_ARP_REACHABLE) {
		return 0;
	}
	if (e->ae_admin) {
		return 0;
	}
	return gt_nsec - e->ae_confirmed > gt_arp_reachable_time;
}

void
gt_arp_resolve(struct gt_route_if *ifp, be32_t next_hop,
	struct gt_dev_pkt *pkt)
{
	int rc;
	uint32_t hash;
	struct dllist *bucket;
	struct gt_log *log;
	struct gt_arp_entry *e, *tmp;

	log = GT_LOG_TRACE1(resolve);
	hash = gt_custom_hash32(next_hop, 0);
	bucket = gt_htable_bucket(&gt_arp_htable, hash);
	DLLIST_FOREACH_SAFE(e, bucket, ae_list, tmp) {
		if (gt_arp_entry_is_reachable_timeouted(e)) {
			gt_arp_set_state(log, e, GT_ARP_STALE);
		}
		if (e->ae_next_hop != next_hop) {
			if (e->ae_state == GT_ARP_STALE) {
				gt_arp_entry_del(log, e);
			}
		} else {
			if (e->ae_state == GT_ARP_INCOMPLETE) {
				gt_arp_entry_add_incomplete(log, e, pkt);
				return;
			}
			GT_ASSERT(e->ae_incq == NULL);
			gt_arp_set_eth_hdr(e, ifp, pkt->pkt_data);
			gt_route_if_tx(ifp, pkt);
			if (e->ae_state == GT_ARP_STALE) {
				gt_arp_set_state(log, e, GT_ARP_PROBE);
				gt_arp_tx_probe(e);
			}
			return;
		}
	}
	rc = gt_arp_entry_alloc(log, &e, next_hop);
	if (rc == 0) {
		gt_arp_set_state(log, e, GT_ARP_INCOMPLETE);
		gt_arp_entry_add_incomplete(log, e, pkt);
		gt_arp_tx_probe(e);
	}
}

void
gt_arp_update(struct gt_arp_advert_msg *msg)
{
	int rc, same_addr;
	struct gt_log *log;
	struct gt_arp_entry *e;

	log = GT_LOG_TRACE1(update);
	GT_LOGF(log, LOG_INFO, 0, "hit; next_hop=%s",
	        gt_log_add_ip_addr(AF_INET, &msg->arpam_next_hop));
	// RFC-4861
	// 7.2.5.  Receipt of Neighbor Advertisements
	// Appendix C: State Machine for the Reachability State
	if (!gt_eth_addr_is_ucast(msg->arpam_addr.etha_bytes)) {
		return;
	}
	e = gt_arp_entry_get(msg->arpam_next_hop);
	if (e == NULL) {
		if (msg->arpam_advert == 0) {
			rc = gt_arp_entry_alloc(log, &e, msg->arpam_next_hop);
			if (rc == 0) {
				e->ae_addr = msg->arpam_addr;
				gt_arp_set_state(log, e, GT_ARP_STALE);
			}
		}
		return;
	}
	same_addr = !memcmp(&e->ae_addr, &msg->arpam_addr,
	                    sizeof(msg->arpam_addr));
	if (gt_arp_entry_is_reachable_timeouted(e)) {
		gt_arp_set_state(log, e, GT_ARP_STALE);
	}
	if (msg->arpam_advert == 0) {
		if (e->ae_state == GT_ARP_INCOMPLETE) {
			e->ae_addr = msg->arpam_addr;
			arp_txincq(e);
			same_addr = 0;
		}
		if (same_addr == 0) {
			e->ae_addr = msg->arpam_addr;
			gt_arp_set_state(log, e, GT_ARP_STALE);
		}
	} else if (e->ae_state == GT_ARP_INCOMPLETE) {
		e->ae_addr = msg->arpam_addr;
		arp_txincq(e);
		if (msg->arpam_solicited) {
			gt_arp_set_state(log, e, GT_ARP_REACHABLE);
		} else {
			gt_arp_set_state(log, e, GT_ARP_STALE);
		}
	} else if (msg->arpam_override == 0) {
		if (same_addr) {
			if (msg->arpam_solicited) {
				gt_arp_set_state(log, e, GT_ARP_REACHABLE);
			}
		} else {
			if (e->ae_state == GT_ARP_REACHABLE) {
				gt_arp_set_state(log, e, GT_ARP_STALE);
			}
		}
	} else {
		e->ae_addr = msg->arpam_addr;
		if (msg->arpam_solicited) {
			gt_arp_set_state(log, e, GT_ARP_REACHABLE);
		} else {
			// override == 1 && solicited == 0
			if (same_addr == 0) {
				gt_arp_set_state(log, e, GT_ARP_STALE);
			}
		}
	}
}

int
gt_arp_add(be32_t next_hop, struct gt_eth_addr *addr)
{
	int rc;
	struct gt_log *log;
	struct gt_arp_entry *e;

	log = GT_LOG_TRACE1(add);
	e = gt_arp_entry_get(next_hop);
	if (e != NULL) {
		return -EEXIST;
	}
	rc = gt_arp_entry_alloc(log, &e, next_hop);
	if (rc == 0) {
		e->ae_admin = 1;
		e->ae_addr = *addr;
		gt_arp_set_state(log, e, GT_ARP_REACHABLE);
		arp_txincq(e);
	}
	return rc;
}

void
gt_arp_reply(struct gt_route_if *ifp, struct gt_arp_hdr *in_arp_h)
{
	int rc;
	struct gt_eth_hdr *eh;
	struct gt_arp_hdr *arp_h;
	struct gt_dev_pkt pkt;

	rc = gt_route_if_not_empty_txr(ifp, &pkt);
	if (rc) {
		ifp->rif_cnt_tx_drop++;
		gt_arps.arps_txrepliesdropped++;
		return;
	}
	pkt.pkt_len = sizeof(*eh) + sizeof(*arp_h);
	eh = (struct gt_eth_hdr *)pkt.pkt_data;
	arp_h = (struct gt_arp_hdr *)(eh + 1);
	eh->ethh_type = GT_ETH_TYPE_ARP_BE;
	eh->ethh_saddr = ifp->rif_hwaddr;
	eh->ethh_daddr = in_arp_h->arph_data.arpip_sha;
	arp_h->arph_hrd = GT_ARP_HRD_ETH_BE;
	arp_h->arph_pro = GT_ETH_TYPE_IP4_BE;
	arp_h->arph_hlen = sizeof(struct gt_eth_addr);
	arp_h->arph_plen = sizeof(be32_t);
	arp_h->arph_op = GT_ARP_OP_REPLY_BE;
	arp_h->arph_data.arpip_sha = ifp->rif_hwaddr;
	arp_h->arph_data.arpip_sip = in_arp_h->arph_data.arpip_tip;
	arp_h->arph_data.arpip_tha = in_arp_h->arph_data.arpip_sha;
	arp_h->arph_data.arpip_tip = in_arp_h->arph_data.arpip_sip;
	gt_arps.arps_txreplies++;
	gt_route_if_tx(ifp, &pkt);
}
