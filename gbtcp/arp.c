// gpl2
#include "internals.h"

#define CURMOD arp

#define ARP_REACHABLE_TIME (30 * NSEC_SEC)
#define ARP_RETRANS_TIMER NSEC_SEC
#define ARP_MAX_UNICAST_SOLICIT 3
#define ARP_MIN_RANDOM_FACTOR 0.5
#define ARP_MAX_RANDOM_FACTOR 1.5

#define arps current->p_arps

struct arp_mod {
	struct log_scope log_scope;
	struct htable arp_htable;
	uint64_t arp_reachable_time;
};

enum arp_state {
	ARP_NONE = 0,
	ARP_INCOMPLETE,
	ARP_REACHABLE,
	ARP_STALE,
	ARP_PROBE
};

struct arp_entry {
	struct mbuf ae_mbuf;
#define ae_list ae_mbuf.mb_list
	be32_t ae_next_hop;
	short ae_state;
	short ae_admin;
	short ae_n_probes;
	uint64_t ae_confirmed;
	struct timer ae_timer;
	struct eth_addr ae_addr;
	struct dev_pkt *ae_incomplete_q;
};

const char *
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
arp_set_eh(struct arp_entry *e, struct route_if *ifp, u_char *data)
{
	struct eth_hdr *eh;

	eh = (struct eth_hdr *)data;
	eh->eh_type = ETH_TYPE_IP4_BE;
	eh->eh_saddr = ifp->rif_hwaddr;
	eh->eh_daddr = e->ae_addr;
}

static void
arp_entry_add_incomplete(struct arp_entry *e, struct dev_pkt *pkt)
{
	int rc;
	struct dev_pkt *cp;

	if (e->ae_incomplete_q != NULL) {
		cp = e->ae_incomplete_q;
		e->ae_incomplete_q = NULL;
		arps.arps_dropped++;
	} else {
		rc = mbuf_alloc(current->p_arp_incomplete_pool,
		                (struct mbuf **)&cp);
		if (rc) {
			arps.arps_dropped++;
			return;
		}
	}
	cp->pkt_len = pkt->pkt_len;
	cp->pkt_data = (uint8_t *)cp + sizeof(*cp);
	DEV_PKT_COPY(cp->pkt_data, pkt->pkt_data, pkt->pkt_len);
	e->ae_incomplete_q = cp;
}

static void
arp_tx_incomplete_q(struct arp_entry *e)
{
	int rc;
	be32_t next_hop;
	struct ip4_hdr *ih;
	struct route_entry route;
	struct dev_pkt pkt, *x;

	x = e->ae_incomplete_q;
	e->ae_incomplete_q = NULL;
	if (x == NULL) {
		return;
	}
	ih = (struct ip4_hdr *)(((struct eth_hdr *)x->pkt_data) + 1);
	route.rt_dst.ipa_4 = ih->ih_daddr;
	rc = route_get(AF_INET, NULL, &route);
	if (rc) {
		goto err;
	}
	next_hop = route_get_next_hop4(&route);
	if (e->ae_next_hop != next_hop) {
		goto err;
	}
	rc = route_get_tx_packet(route.rt_ifp, &pkt, TX_CAN_REDIRECT);
	if (rc) {
		counter64_inc(&route.rt_ifp->rif_tx_drop);
		goto err;
	} else {
		DEV_PKT_COPY(pkt.pkt_data, x->pkt_data, x->pkt_len);
		pkt.pkt_len = x->pkt_len;
		arp_set_eh(e, route.rt_ifp, pkt.pkt_data);
		route_transmit(route.rt_ifp, &pkt);
	}
	mbuf_free(&x->pkt_mbuf);
	return;
err:
	mbuf_free(&x->pkt_mbuf);
	arps.arps_dropped++;
}

static int
arp_fill_probe4(struct eth_hdr *eh, be32_t sip, be32_t dip)
{
	struct arp_hdr *ah;

	ah = (struct arp_hdr *)(eh + 1);
	eh->eh_type = ETH_TYPE_ARP_BE;
	memset(&eh->eh_daddr, 0xff, sizeof(eh->eh_daddr));
	ah->ah_hrd = ARP_HRD_ETH_BE;
	ah->ah_pro = ETH_TYPE_IP4_BE;
	ah->ah_hlen = ETHADDR_LEN;
	ah->ah_plen = 4;
	ah->ah_op = ARP_OP_REQUEST_BE;
	ah->ah_data.aip_sha = eh->eh_saddr;
	ah->ah_data.aip_tha = eh->eh_daddr;
	ah->ah_data.aip_tip = dip;
	ah->ah_data.aip_sip = sip;
	return sizeof(*eh) + sizeof(*ah);
}

static void
arp_probe(struct arp_entry *e)
{
	int rc, len;
	struct eth_hdr *eh;
	struct route_entry route;
	struct dev_pkt pkt;

	if (timer_is_running(&e->ae_timer)) {
		return;
	}
	e->ae_n_probes++;
	timer_set(&e->ae_timer, ARP_RETRANS_TIMER, 0);
	route.rt_dst.ipa_4 = e->ae_next_hop;
	rc = route_get(AF_INET, NULL, &route);
	if (rc) {
		return;
	}
	rc = route_get_tx_packet(route.rt_ifp, &pkt, TX_CAN_REDIRECT);
	if (rc) {
		counter64_inc(&route.rt_ifp->rif_tx_drop);
		return;
	}
	eh = (struct eth_hdr *)pkt.pkt_data;
	eh->eh_saddr = route.rt_ifp->rif_hwaddr;
	if (AF_INET == AF_INET) {
		len = arp_fill_probe4(eh, route.rt_ifa->ria_addr.ipa_4, e->ae_next_hop);
	} else {
		dev_put_tx_packet(&pkt);
		assert(0);
	}
	pkt.pkt_len = len;
	route_transmit(route.rt_ifp, &pkt);
	arps.arps_txrequests++;
}

static uint32_t
arp_hash(uint32_t key)
{
	uint32_t hash_val;

	// Linux algorithm
	hash_val = key;
	hash_val ^= (hash_val >> 16);
	hash_val ^= (hash_val >> 8);
	hash_val ^= (hash_val >> 4);
	return hash_val;
}

static uint32_t
arp_entry_hash(void *udata)
{
	return arp_hash(((struct arp_entry *)udata)->ae_next_hop);
}

static uint64_t
arp_calc_reachable_time(void)
{
	double x, min, max;

	min = ARP_REACHABLE_TIME * ARP_MIN_RANDOM_FACTOR;
	max = ARP_REACHABLE_TIME * ARP_MAX_RANDOM_FACTOR;
	x = rand64();
	x = min + (max - min) * x / UINT64_MAX;
	assert(x >= min);
	assert(x <= max);
	return x;
}

static int
sysctl_arp_add(struct sysctl_conn *cp, void *udata, const char *new, struct strbuf *out)
{
	int rc;
	struct ipaddr next_hop;
	struct eth_addr addr;
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
	rc = eth_addr_aton(&addr, addr_buf);
	if (rc) {
		return rc;
	}
	rc = arp_add(next_hop.ipa_4, &addr);
	return rc;
}

static int
sysctl_arp_del(struct sysctl_conn *cp, void *udata, const char *new, struct strbuf *out)
{
	int rc;
	struct ipaddr next_hop;

	if (new == NULL) {
		return 0;
	}
	rc = ipaddr_pton(AF_INET, &next_hop, new);
	if (rc) {
		return rc;
	}
	rc = arp_del(next_hop.ipa_4);
	return rc;
}

static void
sysctl_arp_entry(void *udata, const char *new, struct strbuf *out)
{
	const char *s;
	struct arp_entry *e;

	e = udata;
	strbuf_add_ipaddr(out, AF_INET, &e->ae_next_hop);
	strbuf_add_ch(out, ',');
	strbuf_add_eth_addr(out, &e->ae_addr);
	strbuf_add_ch(out, ',');
	s = arp_state_str(e->ae_state);
	strbuf_add_str(out, s);
}

int
arp_mod_init(void)
{
	int rc;

	rc = curmod_init();
	if (rc) {
		return rc;
	}
	rc = htable_init(&curmod->arp_htable, 32, arp_entry_hash, HTABLE_SHARED|HTABLE_POWOF2);
	if (rc) {
		curmod_deinit();
		return rc;
	}
	sysctl_add_htable_list(GT_SYSCTL_ARP_LIST, SYSCTL_RD, &curmod->arp_htable,
		sysctl_arp_entry);
	sysctl_add(GT_SYSCTL_ARP_ADD, SYSCTL_WR, NULL, NULL, sysctl_arp_add);
	sysctl_add(GT_SYSCTL_ARP_DEL, SYSCTL_WR, NULL, NULL, sysctl_arp_del);
	curmod->arp_reachable_time = arp_calc_reachable_time();
	return 0;
}

void
arp_mod_deinit(void)
{
	htable_deinit(&curmod->arp_htable);
	curmod_deinit();
}

int
service_init_arp(struct service *s)
{
	int rc;

	if (s->p_arp_entry_pool == NULL) {
		rc = mbuf_pool_alloc(&s->p_arp_entry_pool, s->p_sid,
			PAGE_SIZE, sizeof(struct arp_entry), 0);
		if (rc) {
			return rc;
		}
	}
	rc = 0;
	if (s->p_arp_incomplete_pool == NULL) {
		rc = mbuf_pool_alloc(&s->p_arp_incomplete_pool, s->p_sid,
			10 * PAGE_SIZE, DEV_PKT_SIZE_MAX, 0);
		if (rc) {
			service_deinit_arp(s);
		}
	}
	return rc;
}

void
service_deinit_arp(struct service *s)
{
	mbuf_pool_free(s->p_arp_entry_pool);
	s->p_arp_entry_pool = NULL;
	mbuf_pool_free(s->p_arp_incomplete_pool);
	s->p_arp_incomplete_pool = NULL;
}

static inline void
arp_set_state(struct arp_entry *e, int state)
{
	INFO(0, "hit; state=%s->%s, next_hop=%s",
		arp_state_str(e->ae_state), arp_state_str(state),
		log_add_ipaddr(AF_INET, &e->ae_next_hop));
	WRITE_ONCE(e->ae_state, state);
	if (state == ARP_REACHABLE) {
		timer_del(&e->ae_timer);
		e->ae_confirmed = shared_ns();
		e->ae_n_probes = 0;
	}
}

static int
arp_entry_add(struct arp_entry **ep, struct htable_bucket *b, be32_t next_hop,
	int admin, const struct eth_addr *addr)
{
	int rc;
	struct arp_entry *e;

	rc = mbuf_alloc(current->p_arp_entry_pool, (struct mbuf **)ep);
	if (rc) {
		return rc;
	}
	e = *ep;
	e->ae_n_probes = 0;
	e->ae_incomplete_q = NULL;
	e->ae_state = ARP_NONE;
	e->ae_admin = admin;
	if (addr != NULL) {
		e->ae_addr = *addr;
	}
	timer_init(&e->ae_timer);
	e->ae_next_hop = next_hop;
	dlist_insert_tail_rcu(&b->htb_head, &e->ae_list);
	return 0;
}

static void
arp_entry_del(struct arp_entry *e)
{
	dlist_remove_rcu(&e->ae_list);
	timer_del(&e->ae_timer);
	arp_set_state(e, ARP_NONE);
	mbuf_free(&e->ae_incomplete_q->pkt_mbuf);
	mbuf_free_rcu(&e->ae_mbuf);
}

static struct arp_entry *
arp_entry_get(struct htable_bucket *b, be32_t next_hop)
{
	struct arp_entry *e;

	DLIST_FOREACH(e, &b->htb_head, ae_list) {
		if (e->ae_next_hop == next_hop) {
			return e;
		}
	}
	return NULL;
}

void
arp_mod_timer(struct timer *timer, u_char fn_id)
{
	uint32_t h;
	struct arp_entry *e;
	struct htable_bucket *b;

	arps.arps_timeouts++;
	e = container_of(timer, struct arp_entry, ae_timer);
	h = arp_entry_hash(e);
	b = htable_bucket_get(&curmod->arp_htable, h);
	HTABLE_BUCKET_LOCK(b);
	if (e->ae_state == ARP_INCOMPLETE || e->ae_state == ARP_PROBE) {
		if (e->ae_n_probes >= ARP_MAX_UNICAST_SOLICIT) {
			arp_entry_del(e);
		} else {
			arp_probe(e);
		}
	}
	HTABLE_BUCKET_UNLOCK(b);
}

static int
arp_is_reachable_timeouted(struct arp_entry *e)
{
	uint64_t t;

	if (READ_ONCE(e->ae_admin)) {
		return 0;
	}
	t = shared_ns();
	return t - e->ae_confirmed > curmod->arp_reachable_time;
}

void
arp_resolve_slow(struct route_if *ifp, struct htable_bucket *b,
	be32_t next_hop, struct dev_pkt *pkt)
{
	int rc;
	struct arp_entry *e, *tmp;	

	DLIST_FOREACH_SAFE(e, &b->htb_head, ae_list, tmp) {
		if (e->ae_state == ARP_REACHABLE &&
		    arp_is_reachable_timeouted(e)) {
			arp_set_state(e, ARP_STALE);
		}
		if (e->ae_next_hop != next_hop) {
			if (e->ae_state == ARP_STALE) {
				arp_entry_del(e);
			}
		} else {
			if (e->ae_state == ARP_INCOMPLETE) {
				arp_entry_add_incomplete(e, pkt);
				return;
			}
			assert(e->ae_incomplete_q == NULL);
			arp_set_eh(e, ifp, pkt->pkt_data);
			route_transmit(ifp, pkt);
			if (e->ae_state == ARP_STALE) {
				arp_set_state(e, ARP_PROBE);
				arp_probe(e);
			}
			return;
		}
	}
	rc = arp_entry_add(&e, b, next_hop, 0, NULL);
	if (rc == 0) {
		arp_set_state(e, ARP_INCOMPLETE);
		arp_entry_add_incomplete(e, pkt);
		arp_probe(e);
	}
}

void
arp_resolve(struct route_entry *r, struct dev_pkt *pkt)
{
	int state;
	uint32_t h;
	be32_t next_hop;
	struct route_if *ifp;
	struct htable_bucket *b;
	struct arp_entry *e;

	ifp = r->rt_ifp;
	next_hop = route_get_next_hop4(r);
	h = arp_hash(next_hop);
	b = htable_bucket_get(&curmod->arp_htable, h);
	// Fast path
	DLIST_FOREACH_RCU(e, &b->htb_head, ae_list) {
		state = READ_ONCE(e->ae_state);
		if (state == ARP_REACHABLE &&
		    arp_is_reachable_timeouted(e)) {
			break;
		}
		if (e->ae_next_hop != next_hop) {
			if (state == ARP_STALE) {
				break;
			}
		} else if (state == ARP_REACHABLE ||
		           state == ARP_PROBE) {
			arp_set_eh(e, ifp, pkt->pkt_data);
			route_transmit(ifp, pkt);
			return;
		} else {
			break;
		}
	}
	HTABLE_BUCKET_LOCK(b);
	arp_resolve_slow(ifp, b, next_hop, pkt);
	HTABLE_BUCKET_UNLOCK(b);
}

// RFC-4861
// 7.2.5.  Receipt of Neighbor Advertisements
// Appendix C: State Machine for the Reachability State
void
arp_update_locked(struct arp_advert *adv, struct htable_bucket *b)
{
	int rc, same_addr;
	struct arp_entry *e;

	e = arp_entry_get(b, adv->arpa_next_hop);
	if (e == NULL) {
		if (adv->arpa_advert == 0) {
			rc = arp_entry_add(&e, b, adv->arpa_next_hop,
			                   0, &adv->arpa_addr);
			if (rc == 0) {
				arp_set_state(e, ARP_STALE);
			}
		}
		return;
	}
	same_addr = !memcmp(&e->ae_addr, &adv->arpa_addr,
	                    sizeof(adv->arpa_addr));
	if (e->ae_state == ARP_REACHABLE && arp_is_reachable_timeouted(e)) {
		arp_set_state(e, ARP_STALE);
	}
	if (adv->arpa_advert == 0) {
		if (e->ae_state == ARP_INCOMPLETE) {
			e->ae_addr = adv->arpa_addr;
			arp_tx_incomplete_q(e);
			same_addr = 0;
		}
		if (same_addr == 0) {
			e->ae_addr = adv->arpa_addr;
			arp_set_state(e, ARP_STALE);
		}
	} else if (e->ae_state == ARP_INCOMPLETE) {
		e->ae_addr = adv->arpa_addr;
		arp_tx_incomplete_q(e);
		if (adv->arpa_solicited) {
			arp_set_state(e, ARP_REACHABLE);
		} else {
			arp_set_state(e, ARP_STALE);
		}
	} else if (adv->arpa_override == 0) {
		if (same_addr) {
			if (adv->arpa_solicited) {
				arp_set_state(e, ARP_REACHABLE);
			}
		} else {
			if (e->ae_state == ARP_REACHABLE) {
				arp_set_state(e, ARP_STALE);
			}
		}
	} else {
		e->ae_addr = adv->arpa_addr;
		if (adv->arpa_solicited) {
			arp_set_state(e, ARP_REACHABLE);
		} else {
			// override == 1 && solicited == 0
			if (same_addr == 0) {
				arp_set_state(e, ARP_STALE);
			}
		}
	}

}

void
arp_update(struct arp_advert *adv)
{
	uint32_t h;
	struct htable_bucket *b;

	INFO(0, "hit; next_hop=%s", log_add_ipaddr(AF_INET, &adv->arpa_next_hop));
	if (!eth_addr_is_ucast(adv->arpa_addr.ea_bytes)) {
		return;
	}
	h = arp_hash(adv->arpa_next_hop);
	b = htable_bucket_get(&curmod->arp_htable, h);
	HTABLE_BUCKET_LOCK(b);
	arp_update_locked(adv, b);
	HTABLE_BUCKET_UNLOCK(b);
}

int
arp_add(be32_t next_hop, struct eth_addr *addr)
{
	int rc;
	uint32_t h;
	struct htable_bucket *b;
	struct arp_entry *e;

	rc = 0;
	h = arp_hash(next_hop);
	b = htable_bucket_get(&curmod->arp_htable, h);
	HTABLE_BUCKET_LOCK(b);
	e = arp_entry_get(b, next_hop);
	if (e != NULL) {
		WRITE_ONCE(e->ae_admin, 1);
	} else {
		rc = arp_entry_add(&e, b, next_hop, 1, addr);
		if (rc == 0) {
			arp_set_state(e, ARP_REACHABLE);
			arp_tx_incomplete_q(e);
		}
	}
	HTABLE_BUCKET_UNLOCK(b);
	return rc;
}

int
arp_del(be32_t next_hop)
{
	int rc;
	uint32_t h;
	struct htable_bucket *b;
	struct arp_entry *e;

	h = arp_hash(next_hop);
	b = htable_bucket_get(&curmod->arp_htable, h);
	HTABLE_BUCKET_LOCK(b);
	e = arp_entry_get(b, next_hop);
	if (e == NULL) {
		rc = -ENOENT;
	} else {
		rc = 0;
		arp_entry_del(e);
	}
	HTABLE_BUCKET_UNLOCK(b);
	return rc;
}

void
arp_reply(struct route_if *ifp, struct arp_hdr *ah)
{
	int rc;
	struct eth_hdr *eh_rpl;
	struct arp_hdr *ah_rpl;
	struct dev_pkt pkt;

	rc = route_get_tx_packet(ifp, &pkt, TX_CAN_REDIRECT);
	if (rc) {
		counter64_inc(&ifp->rif_tx_drop);
		arps.arps_txrepliesdropped++;
		return;
	}
	pkt.pkt_len = sizeof(struct eth_hdr) + sizeof(struct arp_hdr);
	eh_rpl = (struct eth_hdr *)pkt.pkt_data;
	ah_rpl = (struct arp_hdr *)(eh_rpl + 1);
	eh_rpl->eh_type = ETH_TYPE_ARP_BE;
	eh_rpl->eh_saddr = ifp->rif_hwaddr;
	eh_rpl->eh_daddr = ah->ah_data.aip_sha;
	ah_rpl->ah_hrd = ARP_HRD_ETH_BE;
	ah_rpl->ah_pro = ETH_TYPE_IP4_BE;
	ah_rpl->ah_hlen = sizeof(struct eth_addr);
	ah_rpl->ah_plen = sizeof(be32_t);
	ah_rpl->ah_op = ARP_OP_REPLY_BE;
	ah_rpl->ah_data.aip_sha = ifp->rif_hwaddr;
	ah_rpl->ah_data.aip_sip = ah->ah_data.aip_tip;
	ah_rpl->ah_data.aip_tha = ah->ah_data.aip_sha;
	ah_rpl->ah_data.aip_tip = ah->ah_data.aip_sip;
	arps.arps_txreplies++;
	route_transmit(ifp, &pkt);
}
