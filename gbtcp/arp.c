#include "internals.h"

#define GT_ARP_REACHABLE_TIME (30 * NANOSECONDS_SECOND)
#define GT_ARP_RETRANS_TIMER NANOSECONDS_SECOND
#define GT_ARP_MAX_UNICAST_SOLICIT 3
#define GT_ARP_MIN_RANDOM_FACTOR 0.5
#define GT_ARP_MAX_RANDOM_FACTOR 1.5

struct arp_mod {
	struct log_scope log_scope;
};

enum gt_arp_state {
	ARP_NONE = 0,
	ARP_INCOMPLETE,
	ARP_REACHABLE,
	ARP_STALE,
	ARP_PROBE
};

struct arp_entry {
	struct mbuf ae_mbuf;
#define ae_list ae_mbuf.mb_list
	struct htable_bucket *ae_bucket;
	be32_t ae_next_hop;
	short ae_state;
	short ae_admin;
	short ae_nprobes;
	uint64_t ae_confirmed;
	struct timer ae_timer;
	struct ethaddr ae_addr;
	struct dev_pkt *ae_incomplete_q;
};

static struct htable gt_arp_htable;
static uint64_t gt_arp_reachable_time;
static struct timer gt_arp_timer_calc_reachable_time;
static struct arp_mod *curmod;

static void gt_arp_probe_timeout(struct timer *timer);

static void gt_arp_calc_reachable_time_timeout(struct timer *timer);

static void gt_arp_entry_del(struct log *log, struct arp_entry *e);

static const char *
arp_state_str(int state)
{
	switch (state) {
	case ARP_NONE: return "NONE";
	case ARP_INCOMPLETE: return "INCOMPLETE";
	case ARP_REACHABLE: return "REACHABLE";
	case ARP_STALE: return "STALE";
	case ARP_PROBE: return "PROBE";
	default: return "???";
	}
}

static inline void
gt_arp_set_eth_hdr(struct arp_entry *e, struct route_if *ifp,
	uint8_t *data)
{
	struct gt_eth_hdr *eh;

	eh = (struct gt_eth_hdr *)data;
	eh->ethh_type = GT_ETH_TYPE_IP4_BE;
	eh->ethh_saddr = ifp->rif_hwaddr;
	eh->ethh_daddr = e->ae_addr;
}

static void
gt_arp_entry_add_incomplete(struct log *log, struct arp_entry *e,
	struct dev_pkt *pkt)
{
	int rc;
	struct dev_pkt *cp;

	if (e->ae_incomplete_q != NULL) {
		cp = e->ae_incomplete_q;
		e->ae_incomplete_q = NULL;
		arps.arps_dropped++;
	} else {
		rc = mbuf_alloc(log, &current->p_arp_incomplete_pool,
		                (struct mbuf **)&cp);
		if (rc) {
			arps.arps_dropped++;
			return;
		}
	}
	if (cp != NULL) {
		cp->pkt_len = pkt->pkt_len;
		cp->pkt_data = (uint8_t *)cp + sizeof(*cp);
		GT_PKT_COPY(cp->pkt_data, pkt->pkt_data, pkt->pkt_len);
		e->ae_incomplete_q = cp;
	}
}

static void
arp_tx_incomplete_q(struct arp_entry *e)
{
	int rc;
	be32_t next_hop;
	struct gt_ip4_hdr *ip4_h;
	struct route_entry route;
	struct dev_pkt pkt, *x;

	x = e->ae_incomplete_q;
	e->ae_incomplete_q = NULL;
	if (x == NULL) {
		return;
	}
	ip4_h = (struct gt_ip4_hdr *)(((struct gt_eth_hdr *)x->pkt_data) + 1);
	route.rt_dst.ipa_4 = ip4_h->ip4h_daddr;
	rc = route_get(AF_INET, NULL, &route);
	if (rc) {
		goto drop;
	}
	next_hop = route_get_next_hop4(&route);
	if (e->ae_next_hop != next_hop) {
drop:
		mbuf_free(&x->pkt_mbuf);
		arps.arps_dropped++;
		return;
	}
	rc = route_if_not_empty_txr(route.rt_ifp, &pkt);
	if (rc) {
		route.rt_ifp->rif_cnt_tx_drop++;
	} else {
		GT_PKT_COPY(pkt.pkt_data, x->pkt_data, x->pkt_len);
		pkt.pkt_len = x->pkt_len;
		gt_arp_set_eth_hdr(e, route.rt_ifp, pkt.pkt_data);
		route_if_tx(route.rt_ifp, &pkt);
	}
	mbuf_free(&x->pkt_mbuf);
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
	arp_h->arph_hlen = ETHADDR_LEN;
	arp_h->arph_plen = 4;
	arp_h->arph_op = GT_ARP_OP_REQUEST_BE;
	arp_h->arph_data.arpip_sha = eh->ethh_saddr;
	arp_h->arph_data.arpip_tha = eh->ethh_daddr;
	arp_h->arph_data.arpip_tip = dip;
	arp_h->arph_data.arpip_sip = sip;
	return sizeof(*eh) + sizeof(*arp_h);
}

static void
gt_arp_tx_probe(struct arp_entry *e)
{
	int rc, len;
	struct gt_eth_hdr *eh;
	struct route_entry route;
	struct dev_pkt pkt;

	if (timer_is_running(&e->ae_timer)) {
		return;
	}
	e->ae_nprobes++;
	timer_set(&e->ae_timer, GT_ARP_RETRANS_TIMER, gt_arp_probe_timeout);
	route.rt_dst.ipa_4 = e->ae_next_hop;
	rc = route_get(AF_INET, NULL, &route);
	if (rc) {
		return;
	}
	rc = route_if_not_empty_txr(route.rt_ifp, &pkt);
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
		BUG;
	}
	pkt.pkt_len = len;
	route_if_tx(route.rt_ifp, &pkt);
	arps.arps_txrequests++;
}

static uint32_t
arp_entry_hash(void *ep)
{
	uint32_t h;
	struct arp_entry *e;

	e = ep;
	h = custom_hash32(e->ae_next_hop, 0);
	return h;
}

static void
gt_arp_timer_set_calc_reachable_time()
{
	timer_set(&gt_arp_timer_calc_reachable_time,
	          2 * NANOSECONDS_HOUR,
	          gt_arp_calc_reachable_time_timeout);
}

static uint64_t
gt_arp_calc_reachable_time()
{
	double x, min, max;

	min = GT_ARP_REACHABLE_TIME * GT_ARP_MIN_RANDOM_FACTOR;
	max = GT_ARP_REACHABLE_TIME * GT_ARP_MAX_RANDOM_FACTOR;
	x = rand64();
	x = min + (max - min) * x / UINT64_MAX;
	ASSERT(x >= min);
	ASSERT(x <= max);
	return x;
}

static void
gt_arp_calc_reachable_time_timeout(struct timer *timer)
{
	gt_arp_reachable_time = gt_arp_calc_reachable_time();
	gt_arp_timer_set_calc_reachable_time();
}

static int
sysctl_arp_add(struct log *log, struct sysctl_conn *cp,
	void *udata, const char *new, struct strbuf *out)
{
	int rc;
	struct ipaddr next_hop;
	struct ethaddr addr;
	char next_hop_buf[64];
	char addr_buf[64];

	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%64[^,],%64[^,]", next_hop_buf, addr_buf);
	if (rc != 2) {
		return -EINVAL;
	}
	rc = ipaddr_pton(AF_INET, &next_hop, next_hop_buf);
	if (rc) {
		return rc;
	}
	rc = ethaddr_aton(&addr, addr_buf);
	if (rc) {
		return rc;
	}
	rc = gt_arp_add(next_hop.ipa_4, &addr);
	return rc;
}

#if 0
static int
gt_arp_ctl_list_next(void *udata, int id)
{
	int mbuf_id;
	struct mbuf *mbuf;

	mbuf = mbuf_next(gt_arp_entry_pool, id);
	if (mbuf == NULL) {
		return -EINVAL;
	} else {
		mbuf_id = mbuf_get_id(gt_arp_entry_pool, mbuf);
		return mbuf_id;
	}
}

static int
gt_arp_ctl_list(void *udata, int id, const char *new, struct strbuf *out)
{
	const char *str;
	struct arp_entry *e;

	e = (struct arp_entry *)mbuf_get(gt_arp_entry_pool, id);
	if (e == NULL) {
		return -EINVAL;
	}
	strbuf_add_ipaddr(out, AF_INET, &e->ae_next_hop);
	strbuf_add_ch(out, ',');
	strbuf_add_ethaddr(out, &e->ae_addr);
	strbuf_add_ch(out, ',');
	str = arp_state_str(e->ae_state);
	strbuf_add_str(out, str);
	return 0;
}
#endif

int
arp_mod_init(struct log *log, void **pp)
{
	int rc;
	struct arp_mod *mod;

	LOG_TRACE(log);
	rc = shm_malloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "arp");
	sysctl_add(log, "arp.add", SYSCTL_WR, NULL, NULL, sysctl_arp_add);
//	sysctl_add_list(log, "arp.list", SYSCTL_RD, NULL,
//	                gt_arp_ctl_list_next, gt_arp_ctl_list);
	return 0;
}

int
arp_mod_attach(struct log *log, void *raw_mod)
{
	int rc;

	LOG_TRACE(log);
	curmod = raw_mod;
	rc = htable_init(log, &gt_arp_htable, 32, arp_entry_hash,
	                 0, field_off(struct arp_entry, ae_bucket));
	if (rc) {
		return rc;
	}
	gt_arp_reachable_time = gt_arp_calc_reachable_time();
	timer_init(&gt_arp_timer_calc_reachable_time);
	gt_arp_timer_set_calc_reachable_time();
	return 0;
}

int
arp_mod_service_init(struct log *log, struct proc *p)
{
	mbuf_pool_init(&p->p_arp_entry_pool, sizeof(struct arp_entry));
	mbuf_pool_init(&p->p_arp_incomplete_pool, DEV_PKT_SIZE_MAX);
	return 0;
}

void
arp_mod_deinit(struct log *log, void *raw_mod)
{
	struct arp_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	sysctl_del(log, "arp.add");
	sysctl_del(log, "arp.list");
	htable_deinit(&gt_arp_htable);
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
arp_mod_detach(struct log *log)
{
//	mbuf_pool_deinit(&current->p_arp_pkt_pool);
//	mbuf_pool_deinit(&current->p_arp_entry_pool);
//	timer_del(&gt_arp_timer_calc_reachable_time);
	curmod = NULL;
}

void
arp_mod_service_deinit(struct log *log, struct proc *s)
{

}


static inline void
arp_set_state(struct log *log, struct arp_entry *e, int state)
{
	LOG_TRACE(log);
	LOGF(log, LOG_INFO, 0, "hit; state=%s->%s, next_hop=%s",
	     arp_state_str(e->ae_state), arp_state_str(state),
	     log_add_ipaddr(AF_INET, &e->ae_next_hop));
	e->ae_state = state;
	if (state == ARP_REACHABLE) {
		timer_del(&e->ae_timer);
		e->ae_confirmed = nanoseconds;
		e->ae_nprobes = 0;
	}
}

static int
gt_arp_entry_alloc(struct log *log, struct arp_entry **ep,
	be32_t next_hop)
{
	int rc;
	uint32_t h;
	struct arp_entry *e;
	struct htable_bucket *b;

	LOG_TRACE(log);
	rc = mbuf_alloc(log, &current->p_arp_entry_pool, (struct mbuf **)ep);
	if (rc) {
		return rc;
	}
	e = *ep;
	e->ae_nprobes = 0;
	e->ae_incomplete_q = NULL;
	e->ae_state = 0;
	e->ae_admin = 0;
	timer_init(&e->ae_timer);
	e->ae_next_hop = next_hop;
	h = arp_entry_hash(e);
	b = htable_bucket_get(&gt_arp_htable, h);
	htable_add(&gt_arp_htable, b, (htable_entry_t *)e);
	return 0;
}

static void
gt_arp_entry_del(struct log *log,struct arp_entry *e)
{
	LOG_TRACE(log);
	htable_del(&gt_arp_htable, (htable_entry_t *)e);
	timer_del(&e->ae_timer);
	arp_set_state(log, e, ARP_NONE);
	mbuf_free(&e->ae_incomplete_q->pkt_mbuf);
	mbuf_free(&e->ae_mbuf);
}

static struct arp_entry *
gt_arp_entry_get(be32_t next_hop)
{
	uint32_t h;
	struct htable_bucket *b;
	struct arp_entry *e;

	h = custom_hash32(next_hop, 0);
	b = htable_bucket_get(&gt_arp_htable, h);
	DLIST_FOREACH(e, &b->htb_head, ae_list) {
		if (e->ae_next_hop == next_hop) {
			return e;
		}
	}
	return NULL;
}

static int
gt_arp_is_probeing(int state)
{
	return state == ARP_INCOMPLETE || state == ARP_PROBE;
}

static void
gt_arp_probe_timeout(struct timer *timer)
{
	struct log *log;
	struct arp_entry *e;

	arps.arps_timeouts++;
	e = container_of(timer, struct arp_entry, ae_timer);
	if (!gt_arp_is_probeing(e->ae_state)) {
		return;
	}
	if (e->ae_nprobes >= GT_ARP_MAX_UNICAST_SOLICIT) {
		log = log_trace0();
		gt_arp_entry_del(log, e);
	} else {
		gt_arp_tx_probe(e);
	}
}

static int
arp_entry_is_reachable_timeouted(struct arp_entry *e)
{
	if (e->ae_state != ARP_REACHABLE) {
		return 0;
	}
	if (e->ae_admin) {
		return 0;
	}
	return nanoseconds - e->ae_confirmed > gt_arp_reachable_time;
}

void
gt_arp_resolve(struct route_if *ifp, be32_t next_hop,
	struct dev_pkt *pkt)
{
	int rc;
	uint32_t h;
	struct htable_bucket *b;
	struct log *log;
	struct arp_entry *e, *tmp;

	log = log_trace0();
	h = custom_hash32(next_hop, 0);
	b = htable_bucket_get(&gt_arp_htable, h);
	DLIST_FOREACH_SAFE(e, &b->htb_head, ae_list, tmp) {
		if (arp_entry_is_reachable_timeouted(e)) {
			arp_set_state(log, e, ARP_STALE);
		}
		if (e->ae_next_hop != next_hop) {
			if (e->ae_state == ARP_STALE) {
				gt_arp_entry_del(log, e);
			}
		} else {
			if (e->ae_state == ARP_INCOMPLETE) {
				gt_arp_entry_add_incomplete(log, e, pkt);
				return;
			}
			ASSERT(e->ae_incomplete_q == NULL);
			gt_arp_set_eth_hdr(e, ifp, pkt->pkt_data);
			route_if_tx(ifp, pkt);
			if (e->ae_state == ARP_STALE) {
				arp_set_state(log, e, ARP_PROBE);
				gt_arp_tx_probe(e);
			}
			return;
		}
	}
	rc = gt_arp_entry_alloc(log, &e, next_hop);
	if (rc == 0) {
		arp_set_state(log, e, ARP_INCOMPLETE);
		gt_arp_entry_add_incomplete(log, e, pkt);
		gt_arp_tx_probe(e);
	}
}

void
gt_arp_update(struct gt_arp_advert_msg *msg)
{
	int rc, same_addr;
	struct log *log;
	struct arp_entry *e;

	log = log_trace0();
	LOGF(log, LOG_INFO, 0, "hit; next_hop=%s",
	     log_add_ipaddr(AF_INET, &msg->arpam_next_hop));
	// RFC-4861
	// 7.2.5.  Receipt of Neighbor Advertisements
	// Appendix C: State Machine for the Reachability State
	if (!ethaddr_is_ucast(msg->arpam_addr.etha_bytes)) {
		return;
	}
	e = gt_arp_entry_get(msg->arpam_next_hop);
	if (e == NULL) {
		if (msg->arpam_advert == 0) {
			rc = gt_arp_entry_alloc(log, &e, msg->arpam_next_hop);
			if (rc == 0) {
				e->ae_addr = msg->arpam_addr;
				arp_set_state(log, e, ARP_STALE);
			}
		}
		return;
	}
	same_addr = !memcmp(&e->ae_addr, &msg->arpam_addr,
	                    sizeof(msg->arpam_addr));
	if (arp_entry_is_reachable_timeouted(e)) {
		arp_set_state(log, e, ARP_STALE);
	}
	if (msg->arpam_advert == 0) {
		if (e->ae_state == ARP_INCOMPLETE) {
			e->ae_addr = msg->arpam_addr;
			arp_tx_incomplete_q(e);
			same_addr = 0;
		}
		if (same_addr == 0) {
			e->ae_addr = msg->arpam_addr;
			arp_set_state(log, e, ARP_STALE);
		}
	} else if (e->ae_state == ARP_INCOMPLETE) {
		e->ae_addr = msg->arpam_addr;
		arp_tx_incomplete_q(e);
		if (msg->arpam_solicited) {
			arp_set_state(log, e, ARP_REACHABLE);
		} else {
			arp_set_state(log, e, ARP_STALE);
		}
	} else if (msg->arpam_override == 0) {
		if (same_addr) {
			if (msg->arpam_solicited) {
				arp_set_state(log, e, ARP_REACHABLE);
			}
		} else {
			if (e->ae_state == ARP_REACHABLE) {
				arp_set_state(log, e, ARP_STALE);
			}
		}
	} else {
		e->ae_addr = msg->arpam_addr;
		if (msg->arpam_solicited) {
			arp_set_state(log, e, ARP_REACHABLE);
		} else {
			// override == 1 && solicited == 0
			if (same_addr == 0) {
				arp_set_state(log, e, ARP_STALE);
			}
		}
	}
}

int
gt_arp_add(be32_t next_hop, struct ethaddr *addr)
{
	int rc;
	struct log *log;
	struct arp_entry *e;

	log = log_trace0();
	e = gt_arp_entry_get(next_hop);
	if (e != NULL) {
		return -EEXIST;
	}
	rc = gt_arp_entry_alloc(log, &e, next_hop);
	if (rc == 0) {
		e->ae_admin = 1;
		e->ae_addr = *addr;
		arp_set_state(log, e, ARP_REACHABLE);
		arp_tx_incomplete_q(e);
	}
	return rc;
}

void
gt_arp_reply(struct route_if *ifp, struct gt_arp_hdr *in_arp_h)
{
	int rc;
	struct gt_eth_hdr *eh;
	struct gt_arp_hdr *arp_h;
	struct dev_pkt pkt;

	rc = route_if_not_empty_txr(ifp, &pkt);
	if (rc) {
		ifp->rif_cnt_tx_drop++;
		arps.arps_txrepliesdropped++;
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
	arp_h->arph_hlen = sizeof(struct ethaddr);
	arp_h->arph_plen = sizeof(be32_t);
	arp_h->arph_op = GT_ARP_OP_REPLY_BE;
	arp_h->arph_data.arpip_sha = ifp->rif_hwaddr;
	arp_h->arph_data.arpip_sip = in_arp_h->arph_data.arpip_tip;
	arp_h->arph_data.arpip_tha = in_arp_h->arph_data.arpip_sha;
	arp_h->arph_data.arpip_tip = in_arp_h->arph_data.arpip_sip;
	arps.arps_txreplies++;
	route_if_tx(ifp, &pkt);
}
