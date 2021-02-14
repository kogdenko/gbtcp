#include "internals.h"

#define CURMOD route

struct route_entry_long {
	struct lptree_rule rtl_rule;
	struct dlist rtl_list;
	int rtl_af;
	struct route_if *rtl_ifp;
	struct ipaddr rtl_via;
	int rtl_nsrcs;
	struct route_if_addr **rtl_srcs;
};

static struct fd_event *route_monitor_event;
static int route_monitor_fd = -1;

static int route_ifaddr_del(struct route_if *, const struct ipaddr *);

static int route_src_compar(const void *a, const void *b, void *);

static int route_set_srcs(struct route_entry_long *route);

static void route_del(struct route_entry_long *);
static int route_del2(be32_t, int);

static void route_on_msg(struct route_msg *msg);

static int route_monitor_handler(void *udata, short revent);

static void
route_foreach_set_srcs(struct route_if *ifp)
{
	struct route_entry_long *route;

	DLIST_FOREACH(route, &ifp->rif_route_head, rtl_list) {
		route_set_srcs(route);
	}
}

struct route_if *
route_if_get(int i)
{
	return READ_ONCE(curmod->route_ifs[i]);
}

struct route_if *
route_if_get_by_index(int ifindex)
{
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_index == ifindex) {
			return ifp;
		}
	}
	return NULL;
}

struct route_if *
route_if_get_by_name(const char *ifname)
{
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		if (!strcpy(ifp->rif_name, ifname)) {
			return ifp;
		}
	}
	return NULL;
}

static int
route_if_add(const char *ifname)
{
	int i, rc, slot;
	char host[IFNAMSIZ + 2];
	struct route_if *ifp;
	struct nmreq *req;

	ifp = route_if_get_by_name(ifname);
	if (ifp != NULL) {
		return -EEXIST;
	}
	slot = -1;
	for (i = 0; i < ARRAY_SIZE(curmod->route_ifs); ++i) {
		if (curmod->route_ifs[i] == NULL) {
			slot = i;
			break;
		}
	}
	if (slot == -1) {
		return -ENFILE;
	}
	ifp = mem_alloc(sizeof(*ifp));
	if (ifp == NULL) {
		return -ENOMEM;
	}
	memset(ifp, 0, sizeof(*ifp));

	// TODO: checks
	counter64_init(&ifp->rif_rx_pkts);
	counter64_init(&ifp->rif_rx_bytes);
	counter64_init(&ifp->rif_rx_drop);
	counter64_init(&ifp->rif_tx_pkts);
	counter64_init(&ifp->rif_tx_bytes);
	counter64_init(&ifp->rif_tx_drop);


	ifp->rif_id = slot;
	dlist_init(&ifp->rif_route_head);
	ifp->rif_mtu = 1500;
	strzcpy(ifp->rif_name, ifname, IFNAMSIZ);
	rc = sys_if_nametoindex(ifname);
	ifp->rif_index = rc;
	rc = read_irq_table(ifp->rif_name, ifp->if_queue_cpu);
	if (rc < 0) {
		goto err_free;
	}
	ifp->rif_n_queues = rc;
//	memset(ifp->if_cpu_queue, -1, sizeof(ifp->if_cpu_queue));
///	for (i = 0; i < ifp->rif_n_queues; ++i) {
//		dbg("%d->%d", i, ifp->rif_q2cpu[i]);
//		ifp->rif_cpu2q[ifp->rif_q2cpu[i]] = i;
//	}
	if (ifp->rif_n_queues > 1) {
		rc = read_rss_key(ifp->rif_name, ifp->rif_rss_key);
		if (rc) {
			ERR(0, "Cannot read RSS key; ifname=%s", ifname);
			goto err_free;
		}
	}
	snprintf(host, sizeof(host), "%s^", ifp->rif_name);
	rc = dev_init(&ifp->rif_host_dev, current_cpu_id, host, host_rxtx);
	if (rc) {
		goto err_free;
	}
	req = &ifp->rif_host_dev.dev_nmd->req;
	if (req->nr_rx_rings != req->nr_tx_rings ||
	    req->nr_rx_rings != ifp->rif_n_queues) {
		ERR(0, "Unsupported interface config; ifname=%s, nrxq=%d, ntxq=%d, nirq=%d",
			ifname, req->nr_rx_rings, req->nr_tx_rings,
			ifp->rif_n_queues);
		rc = -ENOTSUP;
		goto err;
	}
	// FIXME: 
	proc_add_interface(current, ifp);
	ifp->rif_flags |= IFF_UP;
	WRITE_ONCE(curmod->route_ifs[slot], ifp);

	if (route_monitor_fd != -1) {
		// TODO: DELETE OLD ROUTES...
		dbg("monitor!");
		route_dump(route_on_msg);
	}
	return 0;
err:
	dev_deinit(&ifp->rif_host_dev);
err_free:
	mem_free(ifp);
	return rc;
}

static void
route_if_del(struct route_if *ifp)
{
	struct route_entry_long *route;

	while (!dlist_is_empty(&ifp->rif_route_head)) {
		route = DLIST_FIRST(&ifp->rif_route_head,
			struct route_entry_long, rtl_list);
		route_del(route);
	}
	while (ifp->rif_n_addrs) {
		route_ifaddr_del(ifp, &(ifp->rif_addrs[0]->ria_addr));
	}

	WRITE_ONCE(curmod->route_ifs[ifp->rif_id], NULL);

	counter64_fini(&ifp->rif_rx_pkts);
	counter64_fini(&ifp->rif_rx_bytes);
	counter64_fini(&ifp->rif_rx_drop);
	counter64_fini(&ifp->rif_tx_pkts);
	counter64_fini(&ifp->rif_tx_bytes);
	counter64_fini(&ifp->rif_tx_drop);


	mem_free(ifp);

	//ROUTE_LOCK();
	//ifp->rif_slot

	//ROUTE_UNLOCK();


}

static int
route_ifaddr_add(struct route_if_addr **ifap,
	struct route_if *ifp, const struct ipaddr *addr)
{
	int i, size;
	void *new_ptr;
	struct route_if_addr *ifa, *tmp;

	ifa = route_ifaddr_get(AF_INET, addr);
	if (ifa == NULL) {
		ifa = mem_alloc(sizeof(*ifa));
		if (ifa == NULL) {
			return -ENOMEM;
		}
		ifa->ria_addr = *addr;
		ifa->ria_ref_cnt = 0;
		i = rand32() % NEPHEMERAL_PORTS;
		ifa->ria_ephemeral_port = EPHEMERAL_PORT_MIN + i;
		DLIST_INSERT_HEAD(&curmod->route_addr_head, ifa, ria_list);
	}
	for (i = 0; i < ifp->rif_n_addrs; ++i) {
		tmp = ifp->rif_addrs[i];
		if (!ipaddr_cmp(AF_INET, addr, &tmp->ria_addr)) {
			ERR(0, "exists; addr=%s",
			    log_add_ipaddr(AF_INET, &addr->ipa_4));
			return -EEXIST;
		}
	}
	ifa->ria_ref_cnt++;
	size = (ifp->rif_n_addrs + 1) * sizeof(ifa);
	new_ptr = mem_realloc(ifp->rif_addrs, size);
	if (new_ptr == NULL) {
		DLIST_REMOVE(ifa, ria_list);
		mem_free(ifa);
		return -ENOMEM;
	}
	ifp->rif_addrs = new_ptr;
	ifp->rif_addrs[ifp->rif_n_addrs++] = ifa;
	route_foreach_set_srcs(ifp);
	if (ifap != NULL) {
		*ifap = ifa;
	}
	INFO(0, "ok; addr=%s", log_add_ipaddr(AF_INET, &addr->ipa_4));
	return 0;
}

static int
route_ifaddr_del(struct route_if *ifp, const struct ipaddr *addr)
{
	int rc, i, last;
	struct route_if_addr *ifa;

	ifa = route_ifaddr_get(AF_INET, addr);
	rc = -ENOENT;
	if (ifa != NULL) {
		for (i = 0; i < ifp->rif_n_addrs; ++i) {
			if (ifp->rif_addrs[i] == ifa) {
				last = ifp->rif_n_addrs - 1;
				ifp->rif_addrs[i] = ifp->rif_addrs[last];
				ifp->rif_n_addrs--;
				ifa->ria_ref_cnt--;
				route_foreach_set_srcs(ifp);
				if (ifa->ria_ref_cnt == 0) {
					DLIST_REMOVE(ifa, ria_list);
					mem_free(ifa);
				}
				rc = 0;
				break;
			}
		}
	}
	LOGF(rc ? LOG_ERR : LOG_INFO, -rc,
	     "%s; addr=%s", rc ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &addr->ipa_4));
	return rc;
}

static int
route_src_compar(const void *a, const void *b, void *arg)
{
	uint32_t ax, bx, *next_hop;
	struct route_if_addr *ifa_a, *ifa_b;

	next_hop = arg;
	ifa_a = *((struct route_if_addr **)a);
	ifa_b = *((struct route_if_addr **)b);
	ax = (*next_hop - ntoh32(ifa_b->ria_addr.ipa_4));
	bx = (*next_hop - ntoh32(ifa_a->ria_addr.ipa_4));
	return ax - bx;
}

static int
route_set_srcs(struct route_entry_long *route)
{
	int n, size;
	void *new_ptr;
	uint32_t next_hop;

	n = route->rtl_ifp->rif_n_addrs;
	size = n * sizeof(struct route_if_addr *);
	if (route->rtl_nsrcs < n) {
		new_ptr = mem_realloc(route->rtl_srcs, size);
		if (new_ptr == NULL) {
			return -ENOMEM;
		}
		route->rtl_srcs = new_ptr;
	}
	memcpy(route->rtl_srcs, route->rtl_ifp->rif_addrs, size);
	route->rtl_nsrcs = n;
	if (route->rtl_via.ipa_4) {
		next_hop = ntoh32(route->rtl_via.ipa_4);
	} else {
		next_hop = route->rtl_rule.lpr_key;
	}
	gt_qsort_r(route->rtl_srcs, route->rtl_nsrcs,
		sizeof(struct route_if_addr *),
		route_src_compar, &next_hop);
	return 0;
}

static int
route_add(struct route_entry *a)
{
	int rc;
	uint32_t key;
	struct lptree_rule *rule;
	struct route_entry_long *route;

	assert(a->rt_af == AF_INET);
	assert(a->rt_ifp != NULL);
	key = ntoh32(a->rt_dst.ipa_4);
	if (a->rt_pfx > 32) {
		rc = -EINVAL;
		goto out;
	}
	if (a->rt_pfx == 0) {
		route = curmod->route_default;
	} else {
		rule = lptree_get(&curmod->route_lptree, key, a->rt_pfx);
		route = (struct route_entry_long *)rule;
	}
	if (route != NULL) {
		rc = -EEXIST;
		goto out;
	}
	route = mem_alloc(sizeof(*route));
	if (route == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	rule = (struct lptree_rule *)route;
	memset(rule, 0, sizeof(*rule));
	if (a->rt_pfx == 0) {
		rule->lpr_key = key; 
		rule->lpr_depth = a->rt_pfx;
		curmod->route_default = route;
	} else {
		rc = lptree_set(&curmod->route_lptree, rule, key, a->rt_pfx);
		if (rc) {
			mem_free(route);
			goto out;
		}
	}
	route->rtl_af = a->rt_af;
	route->rtl_ifp = a->rt_ifp;
	route->rtl_via = a->rt_via;
	route->rtl_nsrcs = 0;
	route->rtl_srcs = NULL;
	DLIST_INSERT_HEAD(&route->rtl_ifp->rif_route_head, route, rtl_list);
	route_set_srcs(route);
out:
	NOTICE(-rc, "add route%s; dst=%s/%u, dev='%s', via=%s",
		rc  ? " failed" : "",
		log_add_ipaddr(AF_INET, &a->rt_dst.ipa_4),
		a->rt_pfx, a->rt_ifp->rif_name,
		log_add_ipaddr(AF_INET, &a->rt_via.ipa_4));
	return rc;
}

static void
route_del(struct route_entry_long *route)
{
	struct lptree_rule *rule;

	rule = &route->rtl_rule;
	NOTICE(0, "ok; dst=%s/%d",
		log_add_ip_addr4(hton32(rule->lpr_key)),
		rule->lpr_depth);
	mem_free(route->rtl_srcs);
	DLIST_REMOVE(route, rtl_list);
	lptree_del(&curmod->route_lptree, rule);
}

static int
route_del2(be32_t dst, int pfx)
{
	int rc;
	struct lptree_rule *rule;
	struct route_entry_long *route;

	if (pfx > 32) {
		rc = -EINVAL;
		goto err;
	}
	if (pfx == 0) {
		route = curmod->route_default;
	} else {
		rule = lptree_get(&curmod->route_lptree, ntoh32(dst), pfx);
		route = (struct route_entry_long *)rule;
	}
	if (route == NULL) {
		rc = -ESRCH;
		goto err;
	}		
	route_del(route);
	return 0;
err:
	ERR(-rc, "failed; dst=%s/%d", log_add_ipaddr(AF_INET, &dst), pfx);
	return rc;
}

static void
route_on_msg(struct route_msg *msg)
{
	struct route_entry route;
	struct route_if *ifp;

	if (msg->rtm_type != ROUTE_MSG_LINK) {
		if (msg->rtm_af != AF_INET) {
			return;
		}
	}
	ifp = route_if_get_by_index(msg->rtm_if_idx);
	if (ifp == NULL) {
		return;
	}
	switch (msg->rtm_type) {
	case ROUTE_MSG_LINK:
		if (msg->rtm_cmd == ROUTE_MSG_ADD) {
			// TODO: handle interface up/down
			ifp->rif_flags = msg->rtm_link.rtml_flags;
			ifp->rif_hwaddr = msg->rtm_link.rtml_hwaddr;
		}
		break;
	case ROUTE_MSG_ADDR:
		if (msg->rtm_cmd == ROUTE_MSG_ADD) {
			route_ifaddr_add(NULL, ifp, &msg->rtm_addr);
		} else {
			route_ifaddr_del(ifp, &msg->rtm_addr);
		}
		break;
	case ROUTE_MSG_ROUTE:
		route.rt_ifp = ifp;
		route.rt_af = msg->rtm_af;
		route.rt_pfx = msg->rtm_route.rtmr_pfx;
		route.rt_dst = msg->rtm_route.rtmr_dst;
		route.rt_via = msg->rtm_route.rtmr_via;
		if (msg->rtm_cmd == ROUTE_MSG_ADD) {
			route_add(&route);
		} else {
			route_del2(route.rt_dst.ipa_4, route.rt_pfx);
		}
		break;
	default:
		break;
	}
}

static int
route_monitor_handler(void *udata, short revent)
{
	route_read(route_monitor_fd, route_on_msg);
	return 0;
}

static void
route_monitor_stop()
{
	if (route_monitor_fd != -1) {
		sys_close(&route_monitor_fd);
	}
	if (route_monitor_event != NULL) {
		fd_event_del(route_monitor_event);
		route_monitor_event = NULL;
	}
}

static int
route_monitor_start()
{
	int rc;

	if (route_monitor_fd != -1) {
		return -EALREADY;
	}
	rc = route_open();
	if (rc < 0) {
		return rc;
	}
	route_monitor_fd = rc;
	rc = fcntl_setfl_nonblock2(route_monitor_fd);
	if (rc < 0) {
		goto err;
	}
	route_monitor_event = fd_event_add(current_fd_thread,
		route_monitor_fd,
		NULL, route_monitor_handler);
	if (rc) {
		goto err;
	}
	fd_event_set(route_monitor_event, POLLIN);
	INFO(0, "ok; fd=%d", route_monitor_fd);
	route_dump(route_on_msg);
	return 0;
err:
	route_monitor_stop();
	return rc;
}

static int
sysctl_route_if_del(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *out)
{
	struct route_if *ifp;

	if (new == NULL) {
		return 0;
	}
	ifp = route_if_get_by_name(new);
	if (ifp == NULL) {
		return -ENXIO;
	}
	route_if_del(ifp);
	return 0;
}

static int
sysctl_route_if_list_next(void *udata, const char *ident, struct strbuf *out)
{
	int rc, ifindex;
	struct route_if *ifp;

	rc = -1;
	if (ident == NULL) {
		ifindex = 0;
	} else {
		ifindex = strtoul(ident, NULL, 10) + 1;
	}
	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_index == ifindex) {
			rc = ifindex;
			break;
		} else if (ifp->rif_index > ifindex &&
		           (rc < 0 || rc > ifp->rif_index)) {
			rc = ifp->rif_index;
		}
	}
	if (rc < 0) {
		return -ENOENT;
	} else {
		strbuf_addf(out, "%d", rc);
		return 0;
	}
}

static int
sysctl_route_if_list(void *udata, const char *ident, const char *new,
	struct strbuf *out)
{
	int ifindex;
	uint64_t rx_pkts, rx_drop, rx_bytes, tx_pkts, tx_drop, tx_bytes;
	struct route_if *ifp;

	ifindex = strtoul(ident, NULL, 10);
	ifp = route_if_get_by_index(ifindex);
	if (ifp == NULL) {
		return -ENOENT;
	}
	rx_pkts = counter64_get(&ifp->rif_rx_pkts);
	rx_drop = counter64_get(&ifp->rif_rx_drop);
	rx_bytes = counter64_get(&ifp->rif_rx_bytes);
	tx_pkts = counter64_get(&ifp->rif_tx_pkts);
	tx_drop = counter64_get(&ifp->rif_tx_drop);
	tx_bytes = counter64_get(&ifp->rif_tx_bytes);
	strbuf_addf(out, "%s,%d,%x,",
		ifp->rif_name, ifp->rif_index, ifp->rif_flags);
	strbuf_add_eth_addr(out, &ifp->rif_hwaddr);
	strbuf_addf(out, ",%"PRIu64",%"PRIu64",%"PRIu64,
		rx_pkts, rx_drop, rx_bytes);
	strbuf_addf(out, ",%"PRIu64",%"PRIu64",%"PRIu64,
		tx_pkts, tx_drop, tx_bytes);
	return 0;
}

static int
sysctl_route_if_add(struct sysctl_conn *cp, void *udata,
		const char *new, struct strbuf *out)
{
	int rc;

	if (new == NULL) {
		return 0;
	}
	rc = route_if_add(new);
	if (rc && rc != -EEXIST) {
		return rc;
	}
	return 0;
}

static int
sysctl_route_addr_list_next(void *udata, const char *ident, struct strbuf *out)
{
	int id, off;
	struct route_if *ifp;

	if (ident == NULL) {
		id = 0;
	} else {
		id = strtoul(ident, NULL, 10) + 1;
	}
	off = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_n_addrs) {
			strbuf_addf(out, "%d", id);
			return 0;
		}
		off += ifp->rif_n_addrs;
	}
	return -ENOENT;
}

static int
sysctl_route_addr_list(void *udata, const char *ident, const char *new,
	struct strbuf *out)
{
	int id, off;
	struct route_if *ifp;
	struct route_if_addr *ifa;

	id = strtoul(ident, NULL, 10);
	off = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_n_addrs) {
			ifa = ifp->rif_addrs[id - off];
			strbuf_addf(out, "%s,", ifp->rif_name);
			strbuf_add_ipaddr(out, AF_INET, &ifa->ria_addr);
			return 0;
		}
		off += ifp->rif_n_addrs;
	}
	return -ENOENT;
}

/*static int
sysctl_route_list_next(void *udata, const char *ident, struct strbuf *out)
{
	int rc, id;
	struct mbuf *m;

	if (ident == NULL) {
		id = 0;
	} else {
		id = strtoul(ident, NULL, 10) + 1;
	}
	m = mbuf_next(curmod->route_pool, id);
	if (m == NULL) {
		return -ENOENT;
	} else {
		rc = mbuf_get_id(m);
		strbuf_addf(out, "%d", rc);
		return 0;
	}
}

static int
sysctl_route_list(void *udata, const char *ident, const char *new,
	struct strbuf *out)
{
	int id, pfx;
	be32_t dst;
	struct mbuf *m;
	struct route_entry_long *route;

	id = strtoul(ident, NULL, 10);
	m = mbuf_get(curmod->route_pool, id);
	route = (struct route_entry_long *)m;
	if (route == NULL) {
		return -ENOENT;
	}
	assert(route->rtl_ifp != NULL);
	assert(route->rtl_af == AF_INET);
	pfx = route->rtl_rule.lpr_depth;
	dst = hton32(route->rtl_rule.lpr_key);
	strbuf_add_ipaddr(out, AF_INET, &dst);
	strbuf_addf(out, "/%u,%s,", pfx, route->rtl_ifp->rif_name);
	strbuf_add_ipaddr(out, AF_INET, &route->rtl_via);
	return 0;
}*/

int
route_mod_init()
{
	int rc;

	rc = curmod_init();
	if (rc) {
		return rc;
	}
	
	curmod->route_default = NULL;
	dlist_init(&curmod->route_addr_head);
	rc = lptree_init(&curmod->route_lptree);
	if (rc) {
		goto err;
	}
	rc = route_monitor_start();
	if (rc) {
		goto err;
	}
	sysctl_add_list(GT_SYSCTL_ROUTE_IF_LIST, SYSCTL_WR, NULL,
		sysctl_route_if_list_next, sysctl_route_if_list);
	sysctl_add(GT_SYSCTL_ROUTE_IF_ADD, SYSCTL_WR,
		NULL, NULL, sysctl_route_if_add);
	sysctl_add(GT_SYSCTL_ROUTE_IF_DEL, SYSCTL_WR,
		NULL, NULL, sysctl_route_if_del);
	sysctl_add_list(GT_SYSCTL_ROUTE_ADDR_LIST, SYSCTL_RD, NULL,
		sysctl_route_addr_list_next, sysctl_route_addr_list);
//	sysctl_add_list(GT_SYSCTL_ROUTE_ROUTE_LIST, SYSCTL_RD, NULL,
//		sysctl_route_list_next, sysctl_route_list);
	return 0;
err:
	route_mod_deinit(curmod);
	return rc;
}

void
route_mod_deinit()
{
	sysctl_del(GT_SYSCTL_ROUTE);
	route_monitor_stop();
	lptree_deinit(&curmod->route_lptree);
	curmod_deinit();
}


struct route_if_addr *
route_ifaddr_get(int af, const struct ipaddr *addr)
{
	struct route_if_addr *ifa;

	DLIST_FOREACH(ifa, &curmod->route_addr_head, ria_list) {
		if (!ipaddr_cmp(af, &ifa->ria_addr, addr)) {
			return ifa;
		}
	}
	return NULL;
}

struct route_if_addr *
route_ifaddr_get4(be32_t a4)
{
	struct ipaddr a;
	struct route_if_addr *ifa;

	a.ipa_4 = a4;
	ifa = route_ifaddr_get(AF_INET, &a);
	return ifa;
}

int
route_get(int af, struct ipaddr *src, struct route_entry *g)
{
	int i;
	uint32_t key;
	struct lptree_rule *rule;
	struct route_entry_long *route;
	struct route_if_addr *ifa;

	assert(af == AF_INET);
	g->rt_af = AF_INET;
	if (ipaddr4_is_loopback(g->rt_dst.ipa_4)) {
		return -ENETUNREACH;
	}
	key = ntoh32(g->rt_dst.ipa_4);
	rule = lptree_search(&curmod->route_lptree, key);
	route = (struct route_entry_long *)rule;
	if (route == NULL) {
		route = curmod->route_default;
		if (route == NULL) {
			return -ENETUNREACH;
		}
	}
	if (route->rtl_nsrcs == 0) {
		return -EADDRNOTAVAIL;
	}
	g->rt_via = route->rtl_via;
	g->rt_ifp = route->rtl_ifp;
	g->rt_ifa = NULL;
	if (src != NULL && !ipaddr_is_zero(af, src)) {
		for (i = 0; i < route->rtl_nsrcs; ++i) {
			ifa = route->rtl_srcs[i];
			if (!ipaddr_cmp(af, src, &ifa->ria_addr)) {
				g->rt_ifa = ifa;
				return 0;
			}
		}
	}
	if (g->rt_ifa == NULL) {
		g->rt_ifa = route->rtl_srcs[0];
	}
	return 0;
}

int
route_get4(be32_t pref_src_ip4, struct route_entry *route)
{
	int rc;
	struct ipaddr src;

	src.ipa_4 = pref_src_ip4;
	rc = route_get(AF_INET, &src, route);
	return rc;
}

int
route_not_empty_txr(struct route_if *ifp, struct dev_pkt *pkt, int flags)
{
	int rc;
	struct process_percpu *pc;
	struct dev *dev;

	pc =  current->ps_percpu + current_cpu_id;
	dev = pc->ps_interface_dev + ifp->rif_id;
	if (dev_is_inited(dev)) {
		rc = dev_not_empty_txr(dev, pkt, flags);
	} else {
		rc = -ENODEV;
	}
	return rc;
#if 0
	int i, rc, queue_id;
	struct dev *dev;

	queue_id = ifp->rif_queue_table[current_cpu_id];
	if (queue_id > 0) {
		dev = &(current_proc->ps_tds[current_cpu_id].td_devs[ifp->rif_slot]);
		rc = 
	} else {

	}

	rc = -ENODEV;
	for (i = 0; i < ifp->rif_rss_nq; ++i) {
		dev = &(ifp->rif_dev[current->p_sid][i]);
		if (dev_is_inited(dev)) {
			rc = dev_not_empty_txr(dev, pkt, flags);
			if (rc == 0) {
				break;
			}	
		}
	}
	if (rc == -ENODEV && (flags & TX_CAN_REDIRECT)) {
		rc = vale_not_empty_txr(ifp, pkt, flags);
	}
	return rc;
#endif
	assert(0);
	return -EINVAL;
}

//REDIR_TX
//REDIR_RX

void
route_transmit(struct route_if *ifp, struct dev_pkt *pkt)
{
	if (pkt->pkt_pid == current->ps_pid) {
		counter64_inc(&ifp->rif_tx_pkts);
		counter64_add(&ifp->rif_tx_bytes, pkt->pkt_len);
		dev_transmit(pkt);
	} else {
		vale_transmit(ifp, SERVICE_MSG_TX, pkt);
	}
}
