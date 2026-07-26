// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/arp.h>
#include <gbtcp/kernel/cli.h>
#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/htable.h>
#include <gbtcp/kernel/inet.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/timer.h>
#include <gbtcp/kernel/worker.h>

#define gt_notice(...) gt_notice3(&gt_main->arp_logger, ##__VA_ARGS__)
#define gt_info(...) gt_info3(&gt_main->arp_logger, ##__VA_ARGS__)
#define gt_err(...) gt_err3(&gt_main->arp_logger, ##__VA_ARGS__)

#define ARP_REACHABLE_TIME (30 * GT_NSEC_PER_SEC)
#define ARP_RETRANS_TIMER GT_NSEC_PER_SEC
#define ARP_MAX_UNICAST_SOLICIT 3
#define ARP_MIN_RANDOM_FACTOR 0.5
#define ARP_MAX_RANDOM_FACTOR 1.5

enum arp_state {
	ARP_NONE = 0,
	ARP_INCOMPLETE,
	ARP_REACHABLE,
	ARP_STALE,
	ARP_PROBE
};

struct arp_entry {
	// First field: doubles as the RCU-free queue node (gt_free_rcu).
	struct gt_dlist ae_list;
	be32_t ae_next_hop;
	short ae_state;
	short ae_admin;
	short ae_n_probes;
	// Entry removed from the table while ae_timer is still pending on the
	// wheel of the thread which armed it; the timer callback frees it.
	short ae_dying;
	uint64_t ae_confirmed;
	struct gt_timer ae_timer;
	struct gt_eth_addr ae_addr;
	struct dev_pkt *ae_incomplete_q;
};

const char *
arp_state_str(int state)
{
	switch (state) {
	case ARP_NONE:
		return "NONE";
	case ARP_INCOMPLETE:
		return "INCOMPLETE";
	case ARP_REACHABLE:
		return "REACHABLE";
	case ARP_STALE:
		return "STALE";
	case ARP_PROBE:
		return "PROBE";
	default:
		return "???";
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
	struct dev_pkt *cp;

	if (e->ae_incomplete_q != NULL) {
		cp = e->ae_incomplete_q;
		e->ae_incomplete_q = NULL;
		arpstat.arps_dropped++;
	} else {
		cp = gt_malloc(shm_cache(), DEV_PKT_SIZE_MAX, 0);
		if (cp == NULL) {
			arpstat.arps_dropped++;
			return;
		}
	}
	cp->pkt_len = pkt->pkt_len;
	cp->pkt_data = (uint8_t *)cp + sizeof(*cp);
	memcpy(cp->pkt_data, pkt->pkt_data, pkt->pkt_len);
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
		memcpy(pkt.pkt_data, x->pkt_data, x->pkt_len);
		pkt.pkt_len = x->pkt_len;
		arp_set_eh(e, route.rt_ifp, pkt.pkt_data);
		route_transmit(route.rt_ifp, &pkt);
	}
	gt_free_internal(shm_cache(), x);
	return;
err:
	gt_free_internal(shm_cache(), x);
	arpstat.arps_dropped++;
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

	if (gt_timer_is_running(&e->ae_timer)) {
		return;
	}
	e->ae_n_probes++;
	gt_timer_set_fn(&e->ae_timer, ARP_RETRANS_TIMER,
			gt_main->main_timer_fn);
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
		len = arp_fill_probe4(eh, route.rt_ifa->ria_addr.ipa_4,
				      e->ae_next_hop);
	} else {
		dev_put_tx_packet(&pkt);
		assert(0);
	}
	pkt.pkt_len = len;
	route_transmit(route.rt_ifp, &pkt);
	arpstat.arps_txrequests++;
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
	x = min + (max - min) * x / (double)(UINT64_MAX);
	assert(x >= min);
	assert(x <= max);
	return x;
}

static int
gt_arp_add_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	int rc;
	struct ipaddr *host;
	struct gt_eth_addr *hwaddr;
	struct gt_cli_arg *arg;

	host = NULL;
	hwaddr = NULL;
	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "host")) {
			host = arg->arg_value;
		} else if (!strcmp(arg->arg_name, "hwaddr")) {
			hwaddr = arg->arg_value;
		}
	}

	assert(host != NULL);
	assert(hwaddr != NULL);

	rc = arp_add(host->ipa_4, hwaddr);
	return rc;
}

int
gt_arp_init(void)
{
	int rc;

	log_scope_init(&gt_main->arp_logger, "arp");
	rc = htable_init(&gt_main->arp_htable, shm_cache(), 32, arp_entry_hash,
			 HTABLE_POWOF2);
	if (rc) {
		return rc;
	}

	gt_cli_register_command("arp add", gt_arp_add_cli_handler, NULL,
				"<host ip4-address> <hwaddr eth-address>");

	gt_main->arp_reachable_time = arp_calc_reachable_time();
	return 0;
}

void
gt_arp_deinit(void)
{
	htable_deinit(&gt_main->arp_htable);
}

int
service_init_arp(struct service *s)
{
	// ARP entries and incomplete-queue packets are allocated on demand from
	// the service cache (s->p_mm_cache); no per-service pools anymore.
	GT_UNUSED(s);
	return 0;
}

void
service_deinit_arp(struct service *s)
{
	GT_UNUSED(s);
}

static inline void
arp_set_state(struct arp_entry *e, int state)
{
	gt_info(0, "Set arp entry state; state=%s->%s, next_hop=%s",
		arp_state_str(e->ae_state), arp_state_str(state),
		log_add_ipaddr(AF_INET, &e->ae_next_hop));
	WRITE_ONCE(e->ae_state, state);
	if (state == ARP_REACHABLE) {
		// Do not cancel ae_timer: it may live on another thread's
		// timer wheel, and wheels are single-threaded. Let it expire
		// there; the callback ignores REACHABLE entries.
		e->ae_confirmed = shared_ns();
		e->ae_n_probes = 0;
	}
}

static int
arp_entry_add(struct arp_entry **ep, struct htable_bucket *b, be32_t next_hop,
	      int admin, const struct gt_eth_addr *addr)
{
	struct arp_entry *e;

	e = gt_malloc(shm_cache(), sizeof(struct arp_entry), GT_MF_ZERO);
	if (e == NULL) {
		return -ENOMEM;
	}
	*ep = e;
	e->ae_n_probes = 0;
	e->ae_dying = 0;
	e->ae_incomplete_q = NULL;
	e->ae_state = ARP_NONE;
	e->ae_admin = admin;
	if (addr != NULL) {
		e->ae_addr = *addr;
	}
	gt_timer_init(&e->ae_timer);
	e->ae_next_hop = next_hop;
	gt_dlist_insert_tail_rcu(&b->htb_head, &e->ae_list);
	return 0;
}

static void
arp_entry_del(struct arp_entry *e)
{
	gt_dlist_remove_rcu(&e->ae_list);
	arp_set_state(e, ARP_NONE);
	gt_free_internal(shm_cache(), e->ae_incomplete_q);
	e->ae_incomplete_q = NULL;
	if (gt_timer_is_running(&e->ae_timer)) {
		// The timer may live on another thread's wheel and only that
		// thread may unlink it; the callback frees the entry.
		e->ae_dying = 1;
	} else {
		gt_free_rcu(&e->ae_list);
	}
}

static struct arp_entry *
arp_entry_get(struct htable_bucket *b, be32_t next_hop)
{
	struct arp_entry *e;

	GT_DLIST_FOREACH(e, &b->htb_head, ae_list) {
		if (e->ae_next_hop == next_hop) {
			return e;
		}
	}
	return NULL;
}

void
gt_kernel_module_timer(struct gt_timer *timer)
{
	uint32_t h;
	struct arp_entry *e;
	struct htable_bucket *b;

	arpstat.arps_timeouts++;
	e = container_of(timer, struct arp_entry, ae_timer);
	h = arp_entry_hash(e);
	b = htable_bucket_get(&gt_main->arp_htable, h);
	HTABLE_BUCKET_LOCK(b);
	if (e->ae_dying) {
		gt_free_rcu(&e->ae_list);
	} else if (e->ae_state == ARP_INCOMPLETE || e->ae_state == ARP_PROBE) {
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
	return t - e->ae_confirmed > gt_main->arp_reachable_time;
}

void
arp_resolve_slow(struct route_if *ifp, struct htable_bucket *b, be32_t next_hop,
		 struct dev_pkt *pkt)
{
	int rc;
	struct arp_entry *e, *tmp;

	GT_DLIST_FOREACH_SAFE(e, &b->htb_head, ae_list, tmp) {
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
	b = htable_bucket_get(&gt_main->arp_htable, h);

	// Fast path
	GT_DLIST_FOREACH_RCU(e, &b->htb_head, ae_list) {
		state = READ_ONCE(e->ae_state);
		if (state == ARP_REACHABLE && arp_is_reachable_timeouted(e)) {
			break;
		}
		if (e->ae_next_hop != next_hop) {
			if (state == ARP_STALE) {
				break;
			}
		} else if (state == ARP_REACHABLE || state == ARP_PROBE) {
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
			rc = arp_entry_add(&e, b, adv->arpa_next_hop, 0,
					   &adv->arpa_addr);
			if (rc == 0) {
				arp_set_state(e, ARP_STALE);
			}
		}
		return;
	}
	same_addr =
		!memcmp(&e->ae_addr, &adv->arpa_addr, sizeof(adv->arpa_addr));
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

	gt_info(0, "Update arp entry; next_hop=%s",
		log_add_ipaddr(AF_INET, &adv->arpa_next_hop));
	if (!eth_addr_is_ucast(adv->arpa_addr.eth_u8)) {
		return;
	}
	h = arp_hash(adv->arpa_next_hop);
	b = htable_bucket_get(&gt_main->arp_htable, h);
	HTABLE_BUCKET_LOCK(b);
	arp_update_locked(adv, b);
	HTABLE_BUCKET_UNLOCK(b);
}

int
arp_add(be32_t next_hop, struct gt_eth_addr *addr)
{
	int rc;
	uint32_t h;
	struct htable_bucket *b;
	struct arp_entry *e;

	rc = 0;
	h = arp_hash(next_hop);
	b = htable_bucket_get(&gt_main->arp_htable, h);
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
		arpstat.arps_txrepliesdropped++;
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
	ah_rpl->ah_hlen = sizeof(struct gt_eth_addr);
	ah_rpl->ah_plen = sizeof(be32_t);
	ah_rpl->ah_op = ARP_OP_REPLY_BE;
	ah_rpl->ah_data.aip_sha = ifp->rif_hwaddr;
	ah_rpl->ah_data.aip_sip = ah->ah_data.aip_tip;
	ah_rpl->ah_data.aip_tha = ah->ah_data.aip_sha;
	ah_rpl->ah_data.aip_tip = ah->ah_data.aip_sip;
	arpstat.arps_txreplies++;
	route_transmit(ifp, &pkt);
}

int
arp_del(be32_t next_hop)
{
	int rc;
	uint32_t h;
	struct htable_bucket *b;
	struct arp_entry *e;

	h = arp_hash(next_hop);
	b = htable_bucket_get(&gt_main->arp_htable, h);
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

int
gt_arp_input(struct route_if *ifp, void *dat, int datlen)
{
	int i, is_req;
	be32_t sip, tip;
	struct route_if_addr *ifa;
	struct arp_hdr *ah;
	struct arp_advert adv;

	arpstat.arps_received++;
	if (datlen < sizeof(struct arp_hdr)) {
		arpstat.arps_toosmall++;
		return IN_DROP;
	}
	ah = (struct arp_hdr *)dat;
	if (ah->ah_hrd != ARP_HRD_ETH_BE) {
		arpstat.arps_badhrd++;
		return IN_DROP;
	}
	if (ah->ah_pro != ETH_TYPE_IP4_BE) {
		arpstat.arps_badpro++;
		return IN_DROP;
	}
	if (ah->ah_hlen != sizeof(struct gt_eth_addr)) {
		arpstat.arps_badhlen++;
		return IN_DROP;
	}
	if (ah->ah_plen != sizeof(be32_t)) {
		arpstat.arps_badplen++;
		return IN_DROP;
	}
	tip = ah->ah_data.aip_tip;
	sip = ah->ah_data.aip_sip;
	if (ipaddr4_is_loopback(tip)) {
		arpstat.arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_bcast(tip)) {
		arpstat.arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_loopback(sip)) {
		arpstat.arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_bcast(sip)) {
		arpstat.arps_badaddr++;
		return IN_DROP;
	}
	ifa = route_ifaddr_get4(tip);
	if (ifa == NULL) {
		return IN_BYPASS;
	}
	for (i = 0; i < ifp->rif_n_addrs; ++i) {
		if (ifa == ifp->rif_addrs[i]) {
			break;
		}
	}
	if (i == ifp->rif_n_addrs) {
		arpstat.arps_filtered++;
		return IN_BYPASS;
	}
	if (sip == 0) {
		// IP4 duplicate address detection
		return IN_BYPASS;
	}
	switch (ah->ah_op) {
	case ARP_OP_REQUEST_BE:
		arpstat.arps_rxrequests++;
		is_req = 1;
		arp_reply(ifp, ah);
		break;
	case ARP_OP_REPLY_BE:
		arpstat.arps_rxreplies++;
		is_req = 0;
		break;
	default:
		arpstat.arps_badop++;
		return IN_OK;
	}
	adv.arpa_af = AF_INET;
	adv.arpa_advert = !is_req;
	adv.arpa_solicited = !is_req;
	adv.arpa_override = !is_req;
	adv.arpa_next_hop = ah->ah_data.aip_sip;
	adv.arpa_addr = ah->ah_data.aip_sha;
	arp_update(&adv);
	if (is_req) {
		return IN_OK;
	} else {
		return IN_BYPASS;
	}
}
