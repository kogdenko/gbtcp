// GPL v2 license
#include "internals.h"
//#include "list.h"
//#include "route.h"
//#include "shm.h"
//#include "service.h"
//#include "controller.h"

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

static void route_if_del(struct route_if *);

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

	DLIST_FOREACH(route, &ifp->rif_routes, rtl_list) {
		route_set_srcs(route);
	}
}

struct dlist *
route_if_head()
{
	return &curmod->route_if_head;
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
route_if_get(const char *ifname)
{
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		if (!strcmp(ifp->rif_name, ifname)) {
			return ifp;
		}
	}
	return NULL;
}

static int
route_if_add(const char *ifname, struct route_if **ifpp)
{
	int rc;
	struct route_if *ifp;

	if (ifpp != NULL) {
		*ifpp = NULL;
	}
	ifp = route_if_get(ifname);
	if (ifp != NULL) {
		*ifpp = ifp;
		return -EEXIST;
	}
	ifp = shm_malloc(sizeof(*ifp));
	if (ifp == NULL) {
		rc = -ENOMEM;
		goto err;
	}
	memset(ifp, 0, sizeof(*ifp));
	dlist_init(&ifp->rif_routes);
	ifp->rif_mtu = 1500;
	strzcpy(ifp->rif_name, ifname, sizeof(ifp->rif_name));
	rc = sys_if_nametoindex(ifname);
	ifp->rif_index = rc;
	DLIST_INSERT_HEAD(&curmod->route_if_head, ifp, rif_list);
	rc = dev_init(&ifp->rif_host_dev, ifp->rif_name, DEV_QUEUE_HOST, interface_dev_host_rx);
	if (rc < 0 && rc != -ENOTSUP) {
		goto err;
	}
	rc = read_rss_queue_num(ifname);
	if (rc < 0) {
		goto err;
	}
	ifp->rif_rss_queue_num = rc;
	if (ifp->rif_rss_queue_num > 1) {
		rc = read_rss_key(ifp->rif_name, ifp->rif_rss_key);
		if (rc < 0) {
			goto err;
		}
	}
	// FIXME: Handle interface up/down
	ifp->rif_flags |= IFF_UP;
	update_rss_table();
	if (route_monitor_fd != -1) {
		// TODO: Delete old routes
		route_dump(route_on_msg);
	}
	*ifpp = ifp;
	NOTICE(0, "Interface '%s' added", ifname);
	return 0;
err:
	ERR(-rc, "Failed to add interface '%s'", ifname);
	route_if_del(ifp);
	return rc;
}

static void
route_if_del(struct route_if *ifp)
{
	struct route_entry_long *route;

	if (ifp == NULL) {
		return;
	}
	DLIST_REMOVE(ifp, rif_list);
	NOTICE(0, "Delete interface '%s'", ifp->rif_name);
	ifp->rif_list.dls_next = NULL;
	while (!dlist_is_empty(&ifp->rif_routes)) {
		route = DLIST_FIRST(&ifp->rif_routes, struct route_entry_long, rtl_list);
		route_del(route);
	}
	while (ifp->rif_n_addrs) {
		route_ifaddr_del(ifp, &(ifp->rif_addrs[0]->ria_addr));
	}
	shm_free(ifp);
}

static int
route_ifaddr_add(struct route_if_addr **ifap,
	struct route_if *ifp, const struct ipaddr *addr)
{
	int i, rc, size;
	void *new_ptr;
	struct route_if_addr *ifa, *tmp;

	ifa = route_ifaddr_get(AF_INET, addr);
	if (ifa == NULL) {
		ifa = shm_malloc(sizeof(*ifa));
		if (ifa == NULL) {
			rc = -ENOMEM;
			goto err;
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
			rc = -EEXIST;
			goto err;
		}
	}
	ifa->ria_ref_cnt++;
	size = (ifp->rif_n_addrs + 1) * sizeof(ifa);
	new_ptr = shm_realloc(ifp->rif_addrs, size);
	if (new_ptr == NULL) {
		DLIST_REMOVE(ifa, ria_list);
		shm_free(ifa);
		rc = -ENOMEM;
		goto err;
	}
	ifp->rif_addrs = new_ptr;
	ifp->rif_addrs[ifp->rif_n_addrs++] = ifa;
	route_foreach_set_srcs(ifp);
	if (ifap != NULL) {
		*ifap = ifa;
	}
	INFO(0, "Address '%s' added", log_add_ipaddr(AF_INET, &addr->ipa_4));
	return 0;
err:
	ERR(-rc, "Failed to add adress '%s'", log_add_ipaddr(AF_INET, &addr->ipa_4));
	return rc;
}

static int
route_ifaddr_del(struct route_if *ifp, const struct ipaddr *addr)
{
	int i, last;
	struct route_if_addr *ifa;

	ifa = route_ifaddr_get(AF_INET, addr);
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
					shm_free(ifa);
				}
				goto out;
			}
		}
	}
	ERR(0, "Failed to delete address '%s' (Address not found)",
	     log_add_ipaddr(AF_INET, &addr->ipa_4));
	return -ENOENT;
out:
	NOTICE(0, "Address '%s' deleted", log_add_ipaddr(AF_INET, &addr->ipa_4));
	return 0;
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
		new_ptr = shm_realloc(route->rtl_srcs, size);
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
		sizeof(struct route_if_addr *), route_src_compar, &next_hop);
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
		goto err;
	}
	if (a->rt_pfx == 0) {
		route = curmod->route_default;
	} else {
		route = NULL;
	}
	if (route != NULL) {
		rc = -EEXIST;
		goto err;
	}
	rc = mbuf_alloc(curmod->route_pool, (struct mbuf **)&route);
	if (rc) {
		goto err;
	}
	rule = (struct lptree_rule *)route;
	if (a->rt_pfx == 0) {
		rule->lpr_key = key; 
		rule->lpr_depth = a->rt_pfx;
		curmod->route_default = route;
	} else {
		lptree_add(&curmod->route_lptree, rule, key, a->rt_pfx);
		if (rc) {
			mbuf_free((struct mbuf *)rule);
			goto err;
		}
	}
	route->rtl_af = a->rt_af;
	route->rtl_ifp = a->rt_ifp;
	route->rtl_via = a->rt_via;
	route->rtl_nsrcs = 0;
	route->rtl_srcs = NULL;
	DLIST_INSERT_HEAD(&route->rtl_ifp->rif_routes, route, rtl_list);
	route_set_srcs(route);
	NOTICE(0, "Route to '%s/%u' added, dev='%s', via='%s'",
		log_add_ipaddr(AF_INET, &a->rt_dst.ipa_4), a->rt_pfx, a->rt_ifp->rif_name,
		log_add_ipaddr(AF_INET, &a->rt_via.ipa_4));
	return 0;
err:
	ERR(-rc, "Failed to add route to '%s/%u', dev='%s', via='%s'",
		log_add_ipaddr(AF_INET, &a->rt_dst.ipa_4), a->rt_pfx, a->rt_ifp->rif_name,
		log_add_ipaddr(AF_INET, &a->rt_via.ipa_4));
	return rc;
}

static void
route_del(struct route_entry_long *route)
{
	int pfx;
	uint32_t dst;
	struct lptree_rule *rule;

	rule = &route->rtl_rule;
	dst = hton32(rule->lpr_key);
	pfx = rule->lpr_depth;
	shm_free(route->rtl_srcs);
	DLIST_REMOVE(route, rtl_list);
	lptree_del(&curmod->route_lptree, rule);
	NOTICE(0, "Route to '%s/%d' deteled", log_add_ipaddr(AF_INET, &dst), pfx);
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
	ERR(-rc, "Failed to delete route to %s/%d", log_add_ipaddr(AF_INET, &dst), pfx);
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
			// TODO: Handle interface up/down
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
		sys_close(route_monitor_fd);
		route_monitor_fd = -1;
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
	rc = fd_event_add(&route_monitor_event, route_monitor_fd, NULL, route_monitor_handler);
	if (rc) {
		goto err;
	}
	fd_event_set(route_monitor_event, POLLIN);
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
	ifp = route_if_get(new);
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
		} else if (ifp->rif_index > ifindex && (rc < 0 || rc > ifp->rif_index)) {
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
	strbuf_addf(out, "%s,%d,%x,", ifp->rif_name, ifp->rif_index, ifp->rif_flags);
	strbuf_add_eth_addr(out, &ifp->rif_hwaddr);
	strbuf_addf(out, ",%"PRIu64",%"PRIu64",%"PRIu64, rx_pkts, rx_drop, rx_bytes);
	strbuf_addf(out, ",%"PRIu64",%"PRIu64",%"PRIu64, tx_pkts, tx_drop, tx_bytes);
	return 0;
}

static int
sysctl_route_if_add(struct sysctl_conn *cp, void *udata, const char *new, struct strbuf *out)
{
	int rc;
	struct route_if *ifp;

	if (new == NULL) {
		return 0;
	}
	rc = route_if_add(new, &ifp);
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
sysctl_route_addr_list(void *udata, const char *ident, const char *new,	struct strbuf *out)
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

static int
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
}

int
route_mod_init()
{
	int rc;

	rc = curmod_init();
	if (rc) {
		return rc;
	}
	curmod->route_default = NULL;
	dlist_init(&curmod->route_if_head);
	dlist_init(&curmod->route_addr_head);
	rc = mbuf_pool_alloc(&curmod->route_pool, CONTROLLER_SID,
		PAGE_SIZE, sizeof(struct route_entry_long), 10000);
	if (rc) {
		goto err;
	}
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
	sysctl_add(GT_SYSCTL_ROUTE_IF_ADD, SYSCTL_WR, NULL, NULL, sysctl_route_if_add);
	sysctl_add(GT_SYSCTL_ROUTE_IF_DEL, SYSCTL_WR, NULL, NULL, sysctl_route_if_del);
	sysctl_add_list(GT_SYSCTL_ROUTE_ADDR_LIST, SYSCTL_RD, NULL,
		sysctl_route_addr_list_next, sysctl_route_addr_list);
	sysctl_add_list(GT_SYSCTL_ROUTE_ROUTE_LIST, SYSCTL_RD, NULL,
		sysctl_route_list_next, sysctl_route_list);
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
	mbuf_pool_free(curmod->route_pool);
	curmod->route_pool = NULL;	
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
	assert(rule != NULL);
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
	int i, rc;
	struct dev *dev;

	rc = -ENODEV;
	for (i = 0; i < ifp->rif_rss_queue_num; ++i) {
		dev = &(ifp->rif_dev[current->p_sid][i]);
		if (dev_is_inited(dev)) {
			rc = dev_not_empty_txr(dev, pkt);
			if (rc == 0) {
				break;
			}	
		}
	}
	if (rc == -ENODEV && (flags & TX_CAN_REDIRECT)) {
		rc = redirect_dev_not_empty_txr(ifp, pkt);
	}
	return rc;
}

void
route_transmit(struct route_if *ifp, struct dev_pkt *pkt)
{
	if (pkt->pkt_sid == current->p_sid) {
		counter64_inc(&ifp->rif_tx_pkts);
		counter64_add(&ifp->rif_tx_bytes, pkt->pkt_len);
		dev_transmit(pkt);
	} else {
		redirect_dev_transmit(ifp, SERVICE_MSG_TX, pkt);
	}
}
