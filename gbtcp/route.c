#include "internals.h"

static struct route_mod *curmod;

static struct fd_event *route_monitor_event;
static int route_monfd = -1;

static int route_ifaddr_del(struct route_if *, const struct ipaddr *);

static int route_src_compar(const void *a, const void *b, void *);

static int route_set_srcs(struct route_entry_long *route);

static int route_del(be32_t dst, int pfx);

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

void gtd_host_rxtx(struct dev *dev, short revents);
void service_rxtx(struct dev *dev, short revents);

void
gtd_host_rxtx(struct dev *dev, short revents)
{
	int i, n, len;
	u_char *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
//	struct route_if *ifp;

	//ifp = container_of(dev, struct route_if, rif_host_dev);
	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			data = (u_char *)NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			UNUSED(data);
			UNUSED(slot);
			UNUSED(len);
			//gtd_tx_to_net(ifp, data, len);
			
			DEV_RXR_NEXT(rxr);
		}
	}
}

struct dlist *
route_if_head()
{
	return &curmod->route_if_head;
}

struct route_if *
route_if_get_by_ifindex(int ifindex)
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
route_if_get(const char *ifname, int ifname_len, int ifname_type)
{
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_name_len[ifname_type] == ifname_len &&
		    !memcmp(ifp->rif_name, ifname, ifname_len)) {
			return ifp;
		}
	}
	return NULL;
}

static int
route_if_add(const char *ifname_nm, struct route_if **ifpp)
{
	int i, rc, is_pipe, nr_rx_rings, nr_tx_rings, rss_nq;
	int ifname_nm_len, ifname_os_len;
	char ifname_os[IFNAMSIZ];
	char host[IFNAMSIZ + 2];
	struct route_if *ifp;
	struct nmreq *req;

	if (ifpp != NULL) {
		*ifpp = NULL;
	}
	ifname_nm_len = strlen(ifname_nm);
	ASSERT(ifname_nm_len < IFNAMSIZ);
	ifp = route_if_get(ifname_nm, ifname_nm_len, ROUTE_IFNAME_NM);
	if (ifp != NULL) {
		*ifpp = ifp;
		return -EEXIST;
	}
	rc = shm_malloc((void **)&ifp, sizeof(*ifp));
	if (rc < 0) {
		return rc;
	}
	memset(ifp, 0, sizeof(*ifp));
	dlist_init(&ifp->rif_routes);
	ifp->rif_name_len[ROUTE_IFNAME_NM] = ifname_nm_len;
	ifname_os_len = ifname_nm_len;
	is_pipe = 0;
	for (i = 0; i < ifname_nm_len; ++i) {
		if (strchr("{}", ifname_nm[i]) != NULL) {
			ifname_os_len = i;
			is_pipe = 1;
			break;
		}
	}
	ifp->rif_name_len[ROUTE_IFNAME_OS] = ifname_os_len;
	for (i = 0; i < ARRAY_SIZE(ifp->rif_txq); ++i) {
		dlist_init(ifp->rif_txq + i);
	}
	ifp->rif_mtu = 1500;
	memcpy(ifp->rif_name, ifname_nm, ifname_nm_len);
	ifp->rif_name[ifname_nm_len] = '\0';
	memcpy(ifname_os, ifname_nm, ifname_os_len);
	ifname_os[ifname_os_len] = '\0';
	rc = sys_if_nametoindex(ifname_os);
	ifp->rif_index = rc;
	DLIST_INSERT_HEAD(&curmod->route_if_head, ifp, rif_list);
	nr_rx_rings = nr_tx_rings = 1;
	if (is_pipe == 0) {
		snprintf(host, sizeof(host), "%s^", ifp->rif_name);
		rc = dev_init(&ifp->rif_host_dev, host, gtd_host_rxtx);
		if (rc) {
			shm_free(ifp);
			return rc;
		}
		req = &ifp->rif_host_dev.dev_nmd->req;
		nr_rx_rings = req->nr_rx_rings; 
		nr_tx_rings = req->nr_tx_rings;
		ASSERT(nr_rx_rings > 0);
		ASSERT(nr_tx_rings <= nr_rx_rings);
	}
	rss_nq = MIN(nr_rx_rings, nr_tx_rings);
	ifp->rif_rss_nq = rss_nq;
	if (rss_nq > 1) {
		read_rss_key(ifp->rif_name, ifp->rif_rss_key);
	}
	// FIXME: 
	ifp->rif_flags |= IFF_UP;
	controller_update_rss_table();
//	sched_link_up();
	if (route_monfd != -1) {
		// TODO: DELETE OLD ROUTES...
		route_dump(route_on_msg);
	}
	*ifpp = ifp;
	INFO(0, "ok; if='%s'", ifname_nm);
	return 0;
}

static int
route_if_del(struct route_if *ifp)
{
	int rc, pfx;
	uint32_t key;
	be32_t dst;
	struct route_entry_long *route;

	rc = 0;
	DLIST_REMOVE(ifp, rif_list);
	INFO(0, "ok; ifname='%s'", ifp->rif_name);
	ifp->rif_list.dls_next = NULL;
	while (!dlist_is_empty(&ifp->rif_routes)) {
		route = DLIST_FIRST(&ifp->rif_routes,
		                     struct route_entry_long,
		                     rtl_list);
		if (route == &curmod->route_default) {
			pfx = 0;
			dst = 0;
		} else {
			pfx = route->rtl_rule.lpr_depth;
			key = route->rtl_rule.lpr_key;
			dst = hton32(key);
		}
		rc = route_del(dst, pfx);
		ASSERT3(-rc, rc == 0, "route_del(%s/%u)",
		        log_add_ipaddr(AF_INET, &dst), pfx);
	}
	while (ifp->rif_naddrs) {
		route_ifaddr_del(ifp, &(ifp->rif_addrs[0]->ria_addr));
	}
	
	return rc;
}

static int
route_ifaddr_add(struct route_if_addr **ifap,
	struct route_if *ifp, const struct ipaddr *addr)
{
	int i, rc;
	struct route_if_addr *ifa, *tmp;

	ifa = route_ifaddr_get(AF_INET, addr);
	if (ifa == NULL) {
		rc = shm_malloc((void **)&ifa, sizeof(*ifa));
		if (rc < 0) {
			return rc;
		}
		ifa->ria_addr = *addr;
		ifa->ria_ref_cnt = 0;
		i = rand32() % NEPHEMERAL_PORTS;
		ifa->ria_ephemeral_port = EPHEMERAL_PORT_MIN + i;
		DLIST_INSERT_HEAD(&curmod->route_addr_head, ifa, ria_list);
	}
	for (i = 0; i < ifp->rif_naddrs; ++i) {
		tmp = ifp->rif_addrs[i];
		if (!ipaddr_cmp(AF_INET, addr, &tmp->ria_addr)) {
			ERR(0, "exists; addr=%s",
			    log_add_ipaddr(AF_INET, &addr->ipa_4));
			return -EEXIST;
		}
	}
	ifa->ria_ref_cnt++;
	rc = shm_realloc((void **)&ifp->rif_addrs,
	                 (ifp->rif_naddrs + 1) * sizeof(ifa));
	if (rc) {
		DLIST_REMOVE(ifa, ria_list);
		shm_free(ifa);
		return rc;
	}
	ifp->rif_addrs[ifp->rif_naddrs++] = ifa;
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
		for (i = 0; i < ifp->rif_naddrs; ++i) {
			if (ifp->rif_addrs[i] == ifa) {
				last = ifp->rif_naddrs - 1;
				ifp->rif_addrs[i] = ifp->rif_addrs[last];
				ifp->rif_naddrs--;
				ifa->ria_ref_cnt--;
				route_foreach_set_srcs(ifp);
				if (ifa->ria_ref_cnt == 0) {
					DLIST_REMOVE(ifa, ria_list);
					shm_free(ifa);
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
	uint32_t ax, bx, key;
	struct route_entry_long *route;
	struct route_if_addr *ifa_a, *ifa_b;

	route = arg;
	if (route == &curmod->route_default) {
		key = 0;
	} else {
		key = route->rtl_rule.lpr_key;
	}
	ifa_a = *((struct route_if_addr **)a);
	ifa_b = *((struct route_if_addr **)b);
	ax = (key - ntoh32(ifa_b->ria_addr.ipa_4));
	bx = (key - ntoh32(ifa_a->ria_addr.ipa_4));
	return ax - bx;
}

static int
route_set_srcs(struct route_entry_long *route)
{
	int n, rc, size;

	n = route->rtl_ifp->rif_naddrs;
	size = n * sizeof(struct route_if_addr *);
	if (route->rtl_nsrcs < n) {
		rc = shm_realloc((void **)&route->rtl_srcs, size);
		if (rc) {
			return rc;
		}
	}
	memcpy(route->rtl_srcs, route->rtl_ifp->rif_addrs, size);
	route->rtl_nsrcs = n;
	qsort_r(route->rtl_srcs, route->rtl_nsrcs,
	        sizeof(struct route_if_addr *),
	        route_src_compar, (void *)route);
	return 0;
}

static int
route_alloc(struct route_entry_long **proute, uint32_t key, uint8_t depth)
{
	int rc;
	struct lptree_rule *rule;

	rc = mbuf_alloc(&curmod->route_pool, (struct mbuf **)proute);
	if (rc == 0) {
		rule = (struct lptree_rule *)*proute;
		lptree_set(&curmod->route_lptree, rule, key, depth);
		if (rc) {
			mbuf_free((struct mbuf *)rule);
		}
	}
	return rc;
}

static int
route_add(struct route_entry *a)
{
	int rc;
	uint32_t key;
	struct lptree_rule *rule;
	struct route_entry_long *route;

	ASSERT(a->rt_af == AF_INET);
	ASSERT(a->rt_ifp != NULL);
	if (a->rt_pfx > 32) {
		rc = -EINVAL;
	} else if (a->rt_pfx == 0) {
		route = &curmod->route_default;
		rc = 0;
	} else {
		key = ntoh32(a->rt_dst.ipa_4);
		rule = lptree_get(&curmod->route_lptree, key, a->rt_pfx);
		route = (struct route_entry_long *)rule;
		if (route != NULL) {
			rc = -EEXIST;
		} else {
			rc = route_alloc(&route, key, a->rt_pfx);
		}
	}
	if (rc == 0) {
		route->rtl_af = a->rt_af;
		route->rtl_ifp = a->rt_ifp;
		route->rtl_via = a->rt_via;
		route->rtl_nsrcs = 0;
		route->rtl_srcs = NULL;
		DLIST_INSERT_HEAD(&route->rtl_ifp->rif_routes,
		                  route, rtl_list);
		route_set_srcs(route);
	}
	LOGF(rc ? LOG_ERR : LOG_INFO, -rc,
	     "%s; dst=%s/%u, dev='%s', via=%s",
	     rc  ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &a->rt_dst.ipa_4),
	     a->rt_pfx,
	     a->rt_ifp->rif_name,
	     log_add_ipaddr(AF_INET, &a->rt_via.ipa_4));
	return rc;
}

static int
route_del(be32_t dst, int pfx)
{
	int rc;
	struct lptree_rule *rule;
	struct route_entry_long *route;

	if (pfx > 32) {
		rc = -EINVAL;
	} else if (pfx == 0) {
		route = &curmod->route_default;
		route->rtl_af = AF_UNSPEC;
		rc = 0;
	} else {
		rule = lptree_get(&curmod->route_lptree, ntoh32(dst), pfx);
		route = (struct route_entry_long *)rule;
		if (route != NULL) {
			rc = 0;
			shm_free(route->rtl_srcs);
			lptree_del(&curmod->route_lptree, &route->rtl_rule);
		} else {
			rc = -ESRCH;
		}
	}
	if (rc == 0) {
		DLIST_REMOVE(route, rtl_list);
	}
	LOGF(rc ? LOG_ERR : LOG_INFO, -rc, "%s; dst=%s/%d",
	     rc ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &dst), pfx);
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
	ifp = route_if_get_by_ifindex(msg->rtm_if_idx);
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
			route_del(route.rt_dst.ipa_4, route.rt_pfx);
		}
		break;
	default:
		break;
	}
}

static int
route_monitor_handler(void *udata, short revent)
{
	route_read(route_monfd, route_on_msg);
	return 0;
}

static int
route_monitor_stop()
{
	if (route_monfd == -1) {
		return -EALREADY;
	}
	gt_fd_event_del(route_monitor_event);
	sys_close(route_monfd);
	route_monfd = -1;
	route_monitor_event = NULL;
	return 0;
}

static int
route_monitor_start()
{
	int rc;

	if (route_monfd != -1) {
		return -EALREADY;
	}
	rc = route_open(curmod);
	if (rc < 0) {
		return rc;
	}
	route_monfd = rc;
	rc = fcntl_setfl_nonblock2(route_monfd);
	if (rc < 0) {
		goto err;
	}
	rc = gt_fd_event_new(&route_monitor_event, route_monfd,
	                     "route_monitor", route_monitor_handler, NULL);
	if (rc) {
		goto err;
	}
	gt_fd_event_set(route_monitor_event, POLLIN);
	INFO(0, "ok; fd=%d", route_monfd);
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
	int rc;
	struct route_if *ifp;

	if (new == NULL) {
		return 0;
	}
	ifp = route_if_get(new, strlen(new), ROUTE_IFNAME_OS);
	if (ifp == NULL) {
		return -ENXIO;
	}
	rc = route_if_del(ifp);
	return rc;
}

static long long
sysctl_route_if_list_next(void *udata, long long id)
{
	int rc;
	struct route_if *ifp;

	rc = -ENOENT;
	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_index == id) {
			return id;
		} else if (ifp->rif_index > id) {
			if (rc < 0 || rc > ifp->rif_index) {
				rc = ifp->rif_index;
			}
		}
	}
	return rc;
}

static int
sysctl_route_if_list(void *udata, long long id, const char *new,
	struct strbuf *out)
{
	struct route_if *ifp;

	ifp = route_if_get_by_ifindex(id);
	if (ifp == NULL) {
		return -ENOENT;
	}
	strbuf_addf(out, "%s,%d,%x,",
	            ifp->rif_name, ifp->rif_index, ifp->rif_flags);
	strbuf_add_ethaddr(out, &ifp->rif_hwaddr);
	strbuf_addf(out, ",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64,
                    ifp->rif_cnt_rx_pkts,
	            ifp->rif_cnt_rx_bytes,
	            ifp->rif_cnt_tx_pkts,
	            ifp->rif_cnt_tx_bytes,
	            ifp->rif_cnt_tx_drop);
	if (new != NULL && !strcmp(new, "0")) {
		ifp->rif_cnt_rx_pkts = 0;
		ifp->rif_cnt_rx_bytes = 0;
		ifp->rif_cnt_tx_pkts = 0;
		ifp->rif_cnt_tx_bytes = 0;
		ifp->rif_cnt_tx_drop = 0;
	}
	return 0;
}

static int
sysctl_route_if_add(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *out)
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

static long long
sysctl_route_addr_list_next(void *udata, long long id)
{
	int off;
	struct route_if *ifp;

	off = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_naddrs) {
			return id;
		}
		off += ifp->rif_naddrs;
	}
	return -ENOENT;
}

static int
sysctl_route_addr_list(void *udata, long long id, const char *new,
	struct strbuf *out)
{
	int off;
	struct route_if *ifp;
	struct route_if_addr *ifa;

	off = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_naddrs) {
			ifa = ifp->rif_addrs[id - off];
			strbuf_addf(out, "%s,", ifp->rif_name);
			strbuf_add_ipaddr(out, AF_INET, &ifa->ria_addr);
			return 0;
		}
		off += ifp->rif_naddrs;
	}
	return -ENOENT;
}

static long long
sysctl_route_list_next(void *udata, long long id)
{
	int rc;
	struct mbuf *m;

	if (id == 0) {
		if (curmod->route_default.rtl_af == AF_INET) {
			return 0;
		}
		id++;
	}
	m = mbuf_next(&curmod->route_pool, id - 1);
	if (m == NULL) {
		return -ENOENT;
	} else {
		rc = mbuf_get_id(m);
		return rc + 1;
	}
}

static int
sysctl_route_list(void *udata, long long id, const char *new,
	struct strbuf *out)
{
	int pfx;
	uint32_t key;
	be32_t dst;
	struct mbuf *m;
	struct route_entry_long *route;

	if (id == 0) {
		if (curmod->route_default.rtl_af == AF_INET) {
			dst = 0;
			pfx = 0;
			route = &curmod->route_default;
			goto out;
		} else {
			return -ENOENT;
		}
	}
	m = mbuf_get(&curmod->route_pool, id - 1);
	route = (struct route_entry_long *)m;
	if (route == NULL) {
		return -ENOENT;
	}
	ASSERT(route->rtl_ifp != NULL);
	ASSERT(route->rtl_af == AF_INET);
	key = route->rtl_rule.lpr_key;
	pfx = route->rtl_rule.lpr_depth;
	dst = hton32(key);
out:
	strbuf_add_ipaddr(out, AF_INET, &dst);
	strbuf_addf(out, "/%u,%s,", pfx, route->rtl_ifp->rif_name);
	strbuf_add_ipaddr(out, AF_INET, &route->rtl_via);
	return 0;
}

static int
sysctl_route_monitor(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *out)
{
	int rc, flag;

	strbuf_addf(out, "%d", route_monfd == -1 ? 0 : 1);
	if (new == NULL) { 
		return 0;
	}
	flag = strtoul(new, NULL, 10);
	if (flag) {
		rc = route_monitor_start();
	} else {
		rc = route_monitor_stop();
	}
	return rc;
}

int
route_mod_init(void **pp)
{
	int rc;
	struct route_mod *mod;

	rc = shm_malloc(pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "route");
	mod->route_default.rtl_af = AF_UNSPEC;
	dlist_init(&mod->route_if_head);
	dlist_init(&mod->route_addr_head);
	lptree_init(&mod->route_lptree);
	mbuf_pool_init(&mod->route_pool, 0, sizeof(struct route_entry_long));
	sysctl_add(SYSCTL_ROUTE_MONITOR, SYSCTL_WR,
	           NULL, NULL, sysctl_route_monitor);
	sysctl_add_list(GT_SYSCTL_ROUTE_IF_LIST, SYSCTL_WR, NULL,
	                sysctl_route_if_list_next, sysctl_route_if_list);
	sysctl_add(GT_SYSCTL_ROUTE_IF_ADD, SYSCTL_WR,
	           NULL, NULL, sysctl_route_if_add);
	sysctl_add(GT_SYSCTL_ROUTE_IF_DEL, SYSCTL_WR,
	           NULL, NULL, sysctl_route_if_del);
	sysctl_add_list(GT_SYSCTL_ROUTE_ADDR_LIST, SYSCTL_RD, NULL,
	                sysctl_route_addr_list_next,
	                sysctl_route_addr_list);
	sysctl_add_list(GT_SYSCTL_ROUTE_ROUTE_LIST, SYSCTL_RD, NULL,
	                sysctl_route_list_next, sysctl_route_list);
	return 0;
}

int
route_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
route_mod_deinit(void *raw_mod)
{
	struct route_mod *mod;

	mod = raw_mod;
	sysctl_del(GT_SYSCTL_ROUTE);
	lptree_deinit(&mod->route_lptree);
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
route_mod_detach()
{
	curmod = NULL;
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

	ASSERT(af == AF_INET);
	g->rt_af = AF_INET;
	if (ipaddr4_is_loopback(g->rt_dst.ipa_4)) {
		return -ENETUNREACH;
	}
	key = ntoh32(g->rt_dst.ipa_4);
	rule = lptree_search(&curmod->route_lptree, key);
	route = (struct route_entry_long *)rule;
	if (route == NULL) {
		if (curmod->route_default.rtl_af == AF_INET) {
			route = &curmod->route_default;
		} else {
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
route_if_not_empty_txr(struct route_if *ifp, struct dev_pkt *pkt)
{
	int i, rc;
	struct dev *dev;

	rc = -ENOBUFS;
	for (i = 0; i < ifp->rif_rss_nq; ++i) {
		dev = &(ifp->rif_dev[current->p_id][i]);
		if (dev_is_inited(dev)) {
			rc = dev_not_empty_txr(dev, pkt);
			if (rc == 0) {
				break;
			}	
		}
	}
	return rc;
}

void
route_if_rxr_next(struct route_if *ifp, struct netmap_ring *rxr)
{
	struct netmap_slot *slot;

	slot = rxr->slot + rxr->cur;
	ifp->rif_cnt_rx_pkts++;
	ifp->rif_cnt_rx_bytes += slot->len;
	DEV_RXR_NEXT(rxr);
}

void
route_if_tx(struct route_if *ifp, struct dev_pkt *pkt)
{
	ifp->rif_cnt_tx_pkts++;
	ifp->rif_cnt_tx_bytes += pkt->pkt_len;
//	if (pkt->pkt_no_dev) {
//		(*gt_route_if_tx_fn)(ifp, pkt);
//	}
	dev_tx(pkt);
}

int
route_if_calc_rss_qid(struct route_if *ifp, struct sock_tuple *so_tuple)
{
	uint32_t h;
	struct sock_tuple tmp;

	tmp.sot_laddr = so_tuple->sot_faddr;
	tmp.sot_faddr = so_tuple->sot_laddr;
	tmp.sot_lport = so_tuple->sot_fport;
	tmp.sot_fport = so_tuple->sot_lport;
	h = toeplitz_hash((u_char *)&tmp, sizeof(tmp), ifp->rif_rss_key);
	h &= 0x0000007F;
	return h % ifp->rif_rss_nq;
}
