#include "internals.h"


#define ROUTE_IF_FOREACH(ifp) \
	DLIST_FOREACH(ifp, &curmod->route_if_head, rif_list)

#define ROUTE_IF_FOREACH_SAFE(ifp, tmp) \
	DLIST_FOREACH_SAFE(ifp, &curmod->route_if_head, rif_list, tmp)


static struct route_mod *curmod;

static struct gt_fd_event *route_monitor_event;
static int route_monfd = -1;

static void gt_route_foreach_set_saddrs(struct log *log,
	struct route_if *ifp);

static int route_ifaddr_add(struct log *log,
	struct gt_route_if_addr **ifap, struct route_if *ifp,
	const struct ipaddr *addr);

static int route_ifaddr_del(struct log *log, struct route_if *ifp,
	const struct ipaddr *addr);

static int gt_route_saddr_compar(const void *a, const void *b, void *arg);

static int route_set_saddrs(struct log *log,
	struct gt_route_entry_long *route);

static int route_del(struct log *log, be32_t dst, int pfx);

static void route_on_msg(struct gt_route_msg *msg);

static int gt_route_monitor_handler(void *udata, short revent);

static void
gt_route_foreach_set_saddrs(struct log *log, struct route_if *ifp)
{
	struct gt_route_entry_long *route;

	DLIST_FOREACH(route, &ifp->rif_routes, rtl_list) {
		route_set_saddrs(log, route);
	}
}

void gtd_host_rxtx(struct dev *dev, short revents);
void gt_service_rxtx(struct dev *dev, short revents);

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

static int
route_if_init_nm(struct log *log, struct route_if *ifp)
{
	int rc, rss_nq, nr_rx_rings, nr_tx_rings;
	char ifname[NM_IFNAMSIZ];
	uint8_t rss_key[RSS_KEY_SIZE];
	struct nmreq *req;

	LOG_TRACE(log);
	if (ifp->rif_is_pipe == 0) {
		snprintf(ifname, sizeof(ifname), "%s^", ifp->rifname);
		rc = dev_init(log, &ifp->rif_host_dev, ifname, gtd_host_rxtx);
		if (rc) {
			return rc;
		}
	}
	req = &ifp->rif_host_dev.dev_nmd->req;
	nr_rx_rings = req->nr_rx_rings; 
	nr_tx_rings = req->nr_tx_rings;
	ASSERT(nr_rx_rings > 0);
	if (nr_rx_rings > GT_SERVICE_COUNT_MAX || nr_tx_rings < nr_rx_rings) {
		LOGF(log, LOG_ERR, 0,
		     "invalid ring config; if='%s', nr_rx_rings=%d, nr_tx_rings=%d",
		     ifp->rifname, nr_rx_rings, nr_tx_rings);
		return -EINVAL;
	}
	rss_nq = get_rss_nq();
	if (rss_nq == 0) {
		controller_set_rss_nq(log, nr_rx_rings);
		memcpy(curmod->route_rss_key, rss_key, RSS_KEY_SIZE);
	} else if (nr_rx_rings != rss_nq) {
		LOGF(log, LOG_ERR, 0,
		     "invalid nr_rx_rings; ifname='%s', nr_rx_rings=%d, rss_nq=%d",
		     ifp->rifname, nr_rx_rings, rss_nq);
		return -EINVAL;
	} else if (rss_nq > 1 &&
	           memcmp(curmod->route_rss_key, rss_key, RSS_KEY_SIZE)) {
		LOGF(log, LOG_ERR, 0, "unexpected rss_key; ifname=%s",
		     ifp->rifname);
	}
	return 0;
}

void
route_set_rss_qid(struct log *log)
{
	char buf[NM_IFNAMSIZ];
	struct dev *dev;
	struct route_if *ifp;

	LOG_TRACE(log);
	ASSERT(current->p_rss_qid != current->p_rss_qid_saved);
	ROUTE_IF_FOREACH(ifp) {
		dev = ifp->rif_dev + service_id();
		dev_deinit(log, dev);
		if (current->p_rss_qid >= 0) {
			snprintf(buf, sizeof(buf), "%s-%d",
			         ifp->rifname, current->p_rss_qid);
			dev_init(log, dev, buf, gt_service_rxtx);
			dev->dev_udata = ifp;
		}
	}
	current->p_rss_qid_saved = current->p_rss_qid;
}

struct route_if *
route_if_get_by_ifindex(int ifindex)
{
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rifindex == ifindex) {
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
		if (ifp->rifname_len[ifname_type] == ifname_len &&
		    !memcmp(ifp->rifname, ifname, ifname_len)) {
			return ifp;
		}
	}
	return NULL;
}
static int
route_if_add(struct log *log, const char *ifname, struct route_if **ifpp)
{
	int i, rc, ifname_len;
	struct route_if *ifp;

	LOG_TRACE(log);
	if (ifpp != NULL) {
		*ifpp = NULL;
	}
	ifname_len = strlen(ifname);
	ifp = route_if_get(ifname, ifname_len, ROUTE_IFNAME_NM);
	if (ifp != NULL) {
		*ifpp = ifp;
		return -EEXIST;
	}
	rc = shm_alloc(log, (void **)&ifp, sizeof(*ifp));
	if (rc < 0) {
		return rc;
	}
	memset(ifp, 0, sizeof(*ifp));
	dlist_init(&ifp->rif_routes);
	ifp->rifname_len[ROUTE_IFNAME_NM] = ifname_len;
	for (i = 0; i < ifname_len; ++i) {
		if (strchr("{}", ifname[i]) != NULL) {
			ifp->rif_is_pipe = 1;
			break;
		}
	}
	for (i = 0; i < ARRAY_SIZE(ifp->rif_txq); ++i) {
		dlist_init(ifp->rif_txq + i);
	}
	ifp->rif_mtu = 1500;
	ifp->rifname_len[ROUTE_IFNAME_OS] = i;
	memcpy(ifp->rifname, ifname, ifname_len);
	ifp->rifname[ifname_len] = '\0';
	rc = route_if_init_nm(log, ifp);
	if (rc) {
		shm_free(ifp);
		return rc;
	}
	rc = sys_if_nametoindex(log, ifname); // TODO: PIPE!!!! 
	ifp->rifindex = rc;
	DLIST_INSERT_HEAD(&curmod->route_if_head, ifp, rif_list);
	if (route_monfd != -1) {
		// TODO: DELETE OLD ROUTES...
		route_dump(route_on_msg);
	}
	*ifpp = ifp;
	LOGF(log, LOG_INFO, 0, "ok; if='%s'", ifname);
	return 0;
}

static int
route_if_del(struct log *log, struct route_if *ifp)
{
	int rc, pfx;
	uint32_t key;
	be32_t dst;
	struct gt_route_entry_long *route;

	rc = 0;
	LOG_TRACE(log);
	DLIST_REMOVE(ifp, rif_list);
	LOGF(log, LOG_INFO, 0, "ok; ifname='%s'", ifp->rifname);
	ifp->rif_list.dls_next = NULL;
	while (!dlist_is_empty(&ifp->rif_routes)) {
		route = DLIST_FIRST(&ifp->rif_routes,
		                     struct gt_route_entry_long,
		                     rtl_list);
		if (route == &curmod->route_default) {
			pfx = 0;
			dst = 0;
		} else {
			pfx = route->rtl_rule.lpr_depth;
			key = route->rtl_rule.lpr_key;
			dst = GT_HTON32(key);
		}
		rc = route_del(log, dst, pfx);
		ASSERT3(-rc, rc == 0, "route_del(%s/%u)",
		        log_add_ipaddr(AF_INET, &dst), pfx);
	}
	while (ifp->rif_nr_addrs) {
		route_ifaddr_del(log, ifp, &(ifp->rif_addrs[0]->ria_addr));
	}
	return rc;
}

static int
route_ifaddr_add(struct log *log, struct gt_route_if_addr **ifap,
	struct route_if *ifp, const struct ipaddr *addr)
{
	int i, rc;
	struct gt_route_if_addr *ifa, *tmp;

	LOG_TRACE(log);
	ifa = route_ifaddr_get(AF_INET, addr);
	if (ifa == NULL) {
		rc = shm_alloc(log, (void **)&ifa, sizeof(*ifa));
		if (rc < 0) {
			return rc;
		}
		ifa->ria_addr = *addr;
		ifa->ria_ref_cnt = 0;
		i = gt_rand32() % NEPHEMERAL_PORTS;
		ifa->ria_cur_ephemeral_port = EPHEMERAL_PORT_MIN + i;
		DLIST_INSERT_HEAD(&curmod->route_addr_head, ifa, ria_list);
	}
	for (i = 0; i < ifp->rif_nr_addrs; ++i) {
		tmp = ifp->rif_addrs[i];
		if (!ipaddr_cmp(AF_INET, addr, &tmp->ria_addr)) {
			LOGF(log, LOG_ERR, 0, "exists; addr=%s",
			     log_add_ipaddr(AF_INET, &addr->ipa_4));
			return -EEXIST;
		}
	}
	ifa->ria_ref_cnt++;
	rc = shm_realloc(log, (void **)&ifp->rif_addrs,
	                 (ifp->rif_nr_addrs + 1) * sizeof(ifa));
	if (rc) {
		DLIST_REMOVE(ifa, ria_list);
		shm_free(ifa);
		return rc;
	}
	ifp->rif_addrs[ifp->rif_nr_addrs++] = ifa;
	gt_route_foreach_set_saddrs(log, ifp);
	if (ifap != NULL) {
		*ifap = ifa;
	}
	LOGF(log, LOG_INFO, 0, "ok; addr=%s",
	     log_add_ipaddr(AF_INET, &addr->ipa_4));
	return 0;
}

static int
route_ifaddr_del(struct log *log, struct route_if *ifp,
	const struct ipaddr *addr)
{
	int rc, i, last;
	struct gt_route_if_addr *ifa;

	LOG_TRACE(log);
	ifa = route_ifaddr_get(AF_INET, addr);
	rc = -ENOENT;
	if (ifa != NULL) {
		for (i = 0; i < ifp->rif_nr_addrs; ++i) {
			if (ifp->rif_addrs[i] == ifa) {
				last = ifp->rif_nr_addrs - 1;
				ifp->rif_addrs[i] = ifp->rif_addrs[last];
				ifp->rif_nr_addrs--;
				ifa->ria_ref_cnt--;
				gt_route_foreach_set_saddrs(log, ifp);
				if (ifa->ria_ref_cnt == 0) {
					DLIST_REMOVE(ifa, ria_list);
					shm_free(ifa);
				}
				rc = 0;
				break;
			}
		}
	}
	LOGF(log, rc ? LOG_ERR : LOG_INFO, -rc,
	     "%s; addr=%s", rc ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &addr->ipa_4));
	return rc;
}

static int
gt_route_saddr_compar(const void *a, const void *b, void *arg)
{
	uint32_t ax, bx, key;
	struct gt_route_entry_long *route;
	struct gt_route_if_addr *ifa_a, *ifa_b;

	route = arg;
	if (route == &curmod->route_default) {
		key = 0;
	} else {
		key = route->rtl_rule.lpr_key;
	}
	ifa_a = *((struct gt_route_if_addr **)a);
	ifa_b = *((struct gt_route_if_addr **)b);
	ax = (key - GT_NTOH32(ifa_b->ria_addr.ipa_4));
	bx = (key - GT_NTOH32(ifa_a->ria_addr.ipa_4));
	return ax - bx;
}

static int
route_set_saddrs(struct log *log, struct gt_route_entry_long *route)
{
	int n, rc, size;

	LOG_TRACE(log);
	n = route->rtl_ifp->rif_nr_addrs;
	size = n * sizeof(struct gt_route_if_addr *);
	if (route->rtl_nr_saddrs < n) {
		rc = shm_realloc(log, (void **)&route->rtl_saddrs, size);
		if (rc) {
			return rc;
		}
	}
	memcpy(route->rtl_saddrs, route->rtl_ifp->rif_addrs, size);
	route->rtl_nr_saddrs = n;
	qsort_r(route->rtl_saddrs, route->rtl_nr_saddrs,
	        sizeof(struct gt_route_if_addr *),
	        gt_route_saddr_compar, (void *)route);
	return 0;
}

static int
gt_route_alloc(struct log *log, struct gt_route_entry_long **proute,
	uint32_t key, uint8_t depth)
{
	int rc;
	struct lprule *rule;
	rc = mbuf_alloc(log, &curmod->route_pool, (struct mbuf **)proute);
	if (rc == 0) {
		rule = (struct lprule *)*proute;
		rc = lptree_set(log, &curmod->route_lptree, rule, key, depth);
		if (rc) {
			mbuf_free((struct mbuf *)rule);
		}
	}
	return rc;
}

static int
route_add(struct log *log, struct gt_route_entry *a)
{
	int rc;
	uint32_t key;
	struct lprule *rule;
	struct gt_route_entry_long *route;

	ASSERT(a->rt_af == AF_INET);
	ASSERT(a->rt_ifp != NULL);
	LOG_TRACE(log);
	if (a->rt_pfx > 32) {
		rc = -EINVAL;
	} else if (a->rt_pfx == 0) {
		route = &curmod->route_default;
		rc = 0;
	} else {
		key = GT_NTOH32(a->rt_dst.ipa_4);
		rule = lptree_get(log, &curmod->route_lptree, key, a->rt_pfx);
		route = (struct gt_route_entry_long *)rule;
		if (route != NULL) {
			rc = -EEXIST;
		} else {
			rc = gt_route_alloc(log, &route, key, a->rt_pfx);
		}
	}
	if (rc == 0) {
		route->rtl_af = a->rt_af;
		route->rtl_ifp = a->rt_ifp;
		route->rtl_via = a->rt_via;
		route->rtl_nr_saddrs = 0;
		route->rtl_saddrs = NULL;
		DLIST_INSERT_HEAD(&route->rtl_ifp->rif_routes,
		                  route, rtl_list);
		route_set_saddrs(log, route);
	}
	LOGF(log, rc ? LOG_ERR : LOG_INFO, -rc,
	     "%s; dst=%s/%u, dev='%s', via=%s",
	     rc  ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &a->rt_dst.ipa_4),
	     a->rt_pfx,
	     a->rt_ifp->rifname,
	     log_add_ipaddr(AF_INET, &a->rt_via.ipa_4));
	return rc;
}

static int
route_del(struct log *log, be32_t dst, int pfx)
{
	int rc;
	struct lprule *rule;
	struct gt_route_entry_long *route;

	LOG_TRACE(log);	
	if (pfx > 32) {
		rc = -EINVAL;
	} else if (pfx == 0) {
		route = &curmod->route_default;
		route->rtl_af = AF_UNSPEC;
		rc = 0;
	} else {
		rule = lptree_get(log, &curmod->route_lptree, GT_NTOH32(dst), pfx);
		route = (struct gt_route_entry_long *)rule;
		if (route != NULL) {
			rc = 0;
			shm_free(route->rtl_saddrs);
			lptree_del(&curmod->route_lptree, &route->rtl_rule);
		} else {
			rc = -ESRCH;
		}
	}
	if (rc == 0) {
		DLIST_REMOVE(route, rtl_list);
	}
	LOGF(log, rc ? LOG_ERR : LOG_INFO, -rc, "%s; dst=%s/%d",
	     rc ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &dst), pfx);
	return rc;
}

static void
route_on_msg(struct gt_route_msg *msg)
{
	struct log *log;
	struct gt_route_entry route;
	struct route_if *ifp;

	log = log_trace0();
	if (msg->rtm_type != GT_ROUTE_MSG_LINK) {
		if (msg->rtm_af != AF_INET) {
			return;
		}
	}
	ifp = route_if_get_by_ifindex(msg->rtm_if_idx);
	if (ifp == NULL) {
		return;
	}
	switch (msg->rtm_type) {
	case GT_ROUTE_MSG_LINK:
		if (msg->rtm_cmd == GT_ROUTE_MSG_ADD) {
			// TODO: handle interface up/down
			ifp->rifflags = msg->rtm_link.rtml_flags;
			ifp->rif_hwaddr = msg->rtm_link.rtml_hwaddr;
		}
		break;
	case GT_ROUTE_MSG_ADDR:
		if (msg->rtm_cmd == GT_ROUTE_MSG_ADD) {
			route_ifaddr_add(log, NULL, ifp, &msg->rtm_addr);
		} else {
			route_ifaddr_del(log, ifp, &msg->rtm_addr);
		}
		break;
	case GT_ROUTE_MSG_ROUTE:
		route.rt_ifp = ifp;
		route.rt_af = msg->rtm_af;
		route.rt_pfx = msg->rtm_route.rtmr_pfx;
		route.rt_dst = msg->rtm_route.rtmr_dst;
		route.rt_via = msg->rtm_route.rtmr_via;
		if (msg->rtm_cmd == GT_ROUTE_MSG_ADD) {
			route_add(log, &route);
		} else {
			route_del(log, route.rt_dst.ipa_4, route.rt_pfx);
		}
		break;
	default:
		break;
	}
}

static int
gt_route_monitor_handler(void *udata, short revent)
{
	gt_route_read(route_monfd, route_on_msg);
	return 0;
}

static int
route_monitor_stop(struct log *log)
{
	if (route_monfd == -1) {
		return -EALREADY;
	}
	LOG_TRACE(log);
	gt_fd_event_del(route_monitor_event);
	sys_close(log, route_monfd);
	route_monfd = -1;
	route_monitor_event = NULL;
	return 0;
}

static int
route_monitor_start(struct log *log)
{
	int rc;

	if (route_monfd != -1) {
		return -EALREADY;
	}
	LOG_TRACE(log);
	rc = route_open(curmod, log);
	if (rc < 0) {
		return rc;
	}
	route_monfd = rc;
	rc = fcntl_setfl_nonblock2(log, route_monfd);
	if (rc < 0) {
		goto err;
	}
	rc = gt_fd_event_new(log, &route_monitor_event, route_monfd,
	                     "route_monitor", gt_route_monitor_handler, NULL);
	if (rc) {
		goto err;
	}
	gt_fd_event_set(route_monitor_event, POLLIN);
	LOGF(log, LOG_INFO, 0, "ok; fd=%d", route_monfd);
	route_dump(route_on_msg);
	return 0;
err:
	route_monitor_stop(log);
	return rc;
}

static int
sysctl_route_if_del(struct log *log, void *udata, const char *new,
	struct strbuf *out)
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
	rc = route_if_del(log, ifp);
	return rc;
}

static int
sysctl_route_if_list_next(void *udata, int id)
{
	int rc;
	struct route_if *ifp;

	rc = -ENOENT;
	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rifindex > id) {
			if (rc < 0 || rc > ifp->rifindex) {
				rc = ifp->rifindex;
			}
		}
	}
	return rc;
}

static int
sysctl_route_if_list(void *udata, int id, const char *new, struct strbuf *out)
{
	struct route_if *ifp;

	ifp = route_if_get_by_ifindex(id);
	if (ifp == NULL) {
		return -ENOENT;
	}
	strbuf_addf(out, "%s,%d,%x,",
	            ifp->rifname, ifp->rifindex, ifp->rifflags);
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
sysctl_route_rss_key(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	strbuf_add_rss_key(out, curmod->route_rss_key);
	return 0;
}

static int
sysctl_route_if_add(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc;
	struct route_if *ifp;

	if (new == NULL) {
		return 0;
	}
	rc = route_if_add(log, new, &ifp);
	if (rc && rc != -EEXIST) {
		return rc;
	}
	return 0;
}

static int
sysctl_route_addr_list_next(void *udata, int id)
{
	int off;
	struct route_if *ifp;

	off = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_nr_addrs) {
			return id;
		}
		off += ifp->rif_nr_addrs;
	}
	return -ENOENT;
}

static int
sysctl_route_addr_list(void *udata, int id, const char *new,
	struct strbuf *out)
{
	int off;
	struct route_if *ifp;
	struct gt_route_if_addr *ifa;

	off = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_nr_addrs) {
			ifa = ifp->rif_addrs[id - off];
			strbuf_addf(out, "%s,", ifp->rifname);
			strbuf_add_ipaddr(out, AF_INET, &ifa->ria_addr);
			return 0;
		}
		off += ifp->rif_nr_addrs;
	}
	return -ENOENT;
}

static int
sysctl_route_list_next(void *udata, int id)
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
sysctl_route_list(void *udata, int id, const char *new, struct strbuf *out)
{
	int pfx;
	uint32_t key;
	be32_t dst;
	struct gt_route_entry_long *route;

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
	route = (struct gt_route_entry_long *)
		mbuf_get(&curmod->route_pool, id - 1);
	if (route == NULL) {
		return -ENOENT;
	}
	ASSERT(route->rtl_ifp != NULL);
	ASSERT(route->rtl_af == AF_INET);
	key = route->rtl_rule.lpr_key;
	pfx = route->rtl_rule.lpr_depth;
	dst = GT_HTON32(key);
out:
	strbuf_add_ipaddr(out, AF_INET, &dst);
	strbuf_addf(out, "/%u,%s,", pfx, route->rtl_ifp->rifname);
	strbuf_add_ipaddr(out, AF_INET, &route->rtl_via);
	return 0;
}

static int
sysctl_route_monitor(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc, flag;

	strbuf_addf(out, "%d", route_monfd == -1 ? 0 : 1);
	if (new == NULL) { 
		return 0;
	}
	flag = strtoul(new, NULL, 10);
	if (flag) {
		rc = route_monitor_start(log);
	} else {
		rc = route_monitor_stop(log);
	}
	return rc;
}

int
route_mod_init(struct log *log, void **pp)
{
	int rc;
	struct route_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "route");
	mod->route_default.rtl_af = AF_UNSPEC;
	dlist_init(&mod->route_if_head);
	dlist_init(&mod->route_addr_head);
	rc = lptree_init(log, &mod->route_lptree);
	if (rc) {
		goto err;
	}
	mbuf_pool_init(&mod->route_pool, sizeof(struct gt_route_entry_long));
	sysctl_add(log, SYSCTL_ROUTE_RSS_KEY, SYSCTL_RD,
	           NULL, NULL, sysctl_route_rss_key);
	sysctl_add(log, SYSCTL_ROUTE_MONITOR, SYSCTL_WR,
	           NULL, NULL, sysctl_route_monitor);
	sysctl_add_list(log, SYSCTL_ROUTE_IF_LIST, SYSCTL_WR, NULL,
	                sysctl_route_if_list_next, sysctl_route_if_list);
	sysctl_add(log, SYSCTL_ROUTE_IF_ADD, SYSCTL_WR,
	           NULL, NULL, sysctl_route_if_add);
	sysctl_add(log, SYSCTL_ROUTE_IF_DEL, SYSCTL_WR,
	           NULL, NULL, sysctl_route_if_del);
	sysctl_add_list(log, SYSCTL_ROUTE_ADDR_LIST, SYSCTL_RD, NULL,
	                sysctl_route_addr_list_next,
	                sysctl_route_addr_list);
	sysctl_add_list(log, SYSCTL_ROUTE_ROUTE_LIST, SYSCTL_RD, NULL,
	                sysctl_route_list_next, sysctl_route_list);
	return 0;
err:
	sysctl_del(log, SYSCTL_ROUTE);
	lptree_deinit(&mod->route_lptree);
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
	return rc;
}

int
route_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

int
route_proc_init(struct log *log, struct proc *p)
{
	return 0;
}


void
route_mod_deinit(struct log *log, void *raw_mod)
{
	struct route_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	sysctl_del(log, SYSCTL_ROUTE);
	lptree_deinit(&mod->route_lptree);
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
route_mod_detach(struct log *log)
{
	curmod = NULL;
}

struct gt_route_if_addr *
route_ifaddr_get(int af, const struct ipaddr *addr)
{
	struct gt_route_if_addr *ifa;

	DLIST_FOREACH(ifa, &curmod->route_addr_head, ria_list) {
		if (!ipaddr_cmp(af, &ifa->ria_addr, addr)) {
			return ifa;
		}
	}
	return NULL;
}

struct gt_route_if_addr *
gt_route_if_addr_get4(be32_t a4)
{
	struct ipaddr a;
	struct gt_route_if_addr *ifa;

	a.ipa_4 = a4;
	ifa = route_ifaddr_get(AF_INET, &a);
	return ifa;
}

int
gt_route_get(int af, struct ipaddr *src, struct gt_route_entry *g)
{
	int i;
	uint32_t key;
	struct lprule *rule;
	struct gt_route_entry_long *route;
	struct gt_route_if_addr *ifa;

	ASSERT(af == AF_INET);
	g->rt_af = AF_INET;
	if (ipaddr4_is_loopback(g->rt_dst.ipa_4)) {
		return -ENETUNREACH;
	}
	key = GT_NTOH32(g->rt_dst.ipa_4);
	rule = lptree_search(&curmod->route_lptree, key);
	route = (struct gt_route_entry_long *)rule;
	if (route == NULL) {
		if (curmod->route_default.rtl_af == AF_INET) {
			route = &curmod->route_default;
		} else {
			return -ENETUNREACH;
		}
	}
	if (route->rtl_nr_saddrs == 0) {
		return -EADDRNOTAVAIL;
	}
	g->rt_via = route->rtl_via;
	g->rt_ifp = route->rtl_ifp;
	g->rt_ifa = NULL;
	if (src != NULL && !ipaddr_is_zero(af, src)) {
		for (i = 0; i < route->rtl_nr_saddrs; ++i) {
			ifa = route->rtl_saddrs[i];
			if (!ipaddr_cmp(af, src, &ifa->ria_addr)) {
				g->rt_ifa = ifa;
				return 0;
			}
		}
	}
	if (g->rt_ifa == NULL) {
		g->rt_ifa = route->rtl_saddrs[0];
	}
	return 0;
}

int
gt_route_get4(be32_t pref_src_ip4, struct gt_route_entry *route)
{
	int rc;
	struct ipaddr src;

	src.ipa_4 = pref_src_ip4;
	rc = gt_route_get(AF_INET, &src, route);
	return rc;
}

struct dev *
route_if_get_dev(struct route_if *ifp)
{
	struct dev *dev;

	if (current->p_rss_qid < 0) {
		return NULL;
	}
	dev = ifp->rif_dev + service_id();
	return dev;
}

int
gt_route_if_not_empty_txr(struct route_if *ifp, struct dev_pkt *pkt)
{
	int rc;
	struct dev *dev;

	dev = route_if_get_dev(ifp);
	if (dev == NULL) {
		return -ENOBUFS;
	}
	rc = dev_not_empty_txr(dev, pkt);
	return rc;
}

void
gt_route_if_rxr_next(struct route_if *ifp, struct netmap_ring *rxr)
{
	struct netmap_slot *slot;

	slot = rxr->slot + rxr->cur;
	ifp->rif_cnt_rx_pkts++;
	ifp->rif_cnt_rx_bytes += slot->len;
	DEV_RXR_NEXT(rxr);
}

void
gt_route_if_tx(struct route_if *ifp, struct dev_pkt *pkt)
{
	ifp->rif_cnt_tx_pkts++;
	ifp->rif_cnt_tx_bytes += pkt->pkt_len;
//	if (pkt->pkt_no_dev) {
//		(*gt_route_if_tx_fn)(ifp, pkt);
//	}
	dev_tx(pkt);
}

int
gt_route_if_tx3(struct route_if *ifp, void *data, int len)
{
	int rc;
	struct dev *dev;

	dev = route_if_get_dev(ifp);
	if (dev == NULL) {
		return -ENOBUFS;
	}
	rc = dev_tx3(dev, data, len);
	if (rc) {
		ifp->rif_cnt_tx_drop++;
	}
	return rc;
}

 void tcp_flush_if(struct route_if *ifp);

void
gt_sock_tx_flush()
{
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		tcp_flush_if(ifp);
	}
}

int
route_calc_rss_qid(struct sock_tuple *so_tuple, int rss_nq)
{
	uint32_t h;
	struct sock_tuple tmp;

	tmp.sot_laddr = so_tuple->sot_faddr;
	tmp.sot_faddr = so_tuple->sot_laddr;
	tmp.sot_lport = so_tuple->sot_fport;
	tmp.sot_fport = so_tuple->sot_lport;
	h = toeplitz_hash((u_char *)&tmp, sizeof(tmp), curmod->route_rss_key);
	h &= 0x0000007F;
	return h % rss_nq;
}
