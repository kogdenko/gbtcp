#include "internals.h"


#define ROUTE_IF_FOREACH(ifp) \
	DLIST_FOREACH(ifp, &current_mod->route_if_head, rif_list)

#define ROUTE_IF_FOREACH_SAFE(ifp, tmp) \
	DLIST_FOREACH_SAFE(ifp, &current_mod->route_if_head, rif_list, tmp)



int gt_route_rss_q_id = -1;
int gt_route_rss_q_cnt;
int gt_route_port_pairity;
uint8_t gt_route_rss_key[RSSKEYSIZ];

static struct route_mod *current_mod;

static struct gt_fd_event *gt_route_monitor_event;
static int route_monfd = -1;

static void gt_route_foreach_set_saddrs(struct log *log,
	struct gt_route_if *ifp);

static int gt_route_if_add(struct log *log, const char *ifname,
	struct gt_route_if **ifpp);

static int gt_route_if_del(struct log *log, struct gt_route_if *ifp);

static int route_ifaddr_add(struct log *log,
	struct gt_route_if_addr **ifap, struct gt_route_if *ifp,
	const struct ipaddr *addr);

static int route_ifaddr_del(struct log *log, struct gt_route_if *ifp,
	const struct ipaddr *addr);

static int gt_route_saddr_compar(const void *a, const void *b, void *arg);

static int route_set_saddrs(struct log *log,
	struct gt_route_entry_long *route);

static int gt_route_add(struct log *log, struct gt_route_entry *a);

static int route_del(struct log *log, be32_t dst, int pfx);

static void route_on_msg(struct gt_route_msg *msg);

static int gt_route_monitor_handler(void *udata, short revent);

static int gt_route_monitor_start(struct log *log);

static int gt_route_monitor_stop(struct log *log);

static int gt_route_ctl_if_del(struct log *log, void *udata, const char *new,
	struct strbuf *out);

static int gt_route_ctl_if_list_next(void *udata, int id);

static int gt_route_ctl_if_list(void *udata, int id, const char *new,
	struct strbuf *out);

static int gt_route_ctl_rss_key(struct log *log, void *udata,
	const char *new, struct strbuf *out);

static int gt_route_ctl_if_add(struct log *log, void *udata,
	const char *new, struct strbuf *out);

static int gt_route_ctl_addr_list_next(void *udata, int id);

static int gt_route_ctl_addr_list(void *udata, int id, const char *new,
	struct strbuf *out);

static int gt_route_ctl_addr_mod(struct log *log, int add, void *udata,
	const char *new, struct strbuf *out);

static int gt_route_ctl_addr_add(struct log *log, void *udata,
	const char *new, struct strbuf *out);

static int gt_route_ctl_addr_del(struct log *log, void *udata,
	const char *new, struct strbuf *out);

static int gt_route_ctl_list_next(void *udata, int id);

static int gt_route_ctl_list(void *udata, int id, const char *new,
	struct strbuf *out);

static int gt_route_ctl_add(struct log *log, void *udata, const char *new,
	struct strbuf *out);

static int gt_route_ctl_del(struct log *log, void *udata, const char *new,
	struct strbuf *out);

static int gt_route_ctl_monitor(struct log *log, void *udata,
	const char *new, struct strbuf *out);

static void
gt_route_foreach_set_saddrs(struct log *log, struct gt_route_if *ifp)
{
	struct gt_route_entry_long *route;

	DLIST_FOREACH(route, &ifp->rif_routes, rtl_list) {
		route_set_saddrs(log, route);
	}
}

void gtd_host_rxtx(struct dev *dev, short revents);
void gt_service_rxtx(struct dev *dev, short revents);

static int
gtd_set_rss_conf(struct log *log, int rss_q_cnt, const uint8_t *rss_key)
{
//	int i;
//	struct gtd_service *s;

	LOG_TRACE(log);
//	GTD_SERVICE_FOREACH(s) {
///		gtd_service_del(log, s);
//	}
//	memset(gtd_services, 0, sizeof(gtd_services));
	gt_route_rss_q_cnt = rss_q_cnt;
	if (gt_route_rss_q_cnt > 1) {
		memcpy(gt_route_rss_key, rss_key, sizeof(gt_route_rss_key));
	}
//	for (i = 0; i < gt_route_rss_q_cnt; ++i) {
//		gtd_service_start(log);
//	}
	LOGF(log, 7, LOG_INFO, 0,
	     "ok; rss_q_cnt=%d", gt_route_rss_q_cnt);
	return 0;
}

static int
route_if_create_devs(struct log *log, struct gt_route_if *ifp)
{
	int i, rc, nr_rx_rings, nr_tx_rings;
	char ifname[NM_IFNAMSIZ];
	uint8_t rss_key[RSSKEYSIZ];
	struct nmreq *req;

	LOG_TRACE(log);
	if (ifp->rif_is_pipe == 0) {
		snprintf(ifname, sizeof(ifname), "%s^", ifp->rif_name);
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
		LOGF(log, LOG_MSG(if_add), LOG_ERR, 0,
		     "invalid ring config; if='%s', nr_rx_rings=%d, nr_tx_rings=%d",
		     ifp->rif_name, nr_rx_rings, nr_tx_rings);
		return -EINVAL;
	}
	if (gt_route_rss_q_cnt == 0) {
		gtd_set_rss_conf(log, nr_rx_rings, rss_key);
	} else if (nr_rx_rings != gt_route_rss_q_cnt) {
		LOGF(log, 7, LOG_ERR, 0,
		     "invalid nr_rx_rings; if='%s', nr_rx_rings=%d, rss_q_cnt=%d",
		     ifp->rif_name, nr_rx_rings, gt_route_rss_q_cnt);
		return -EINVAL;
	} else if (gt_route_rss_q_cnt > 1 &&
	           memcmp(gt_route_rss_key, rss_key, RSSKEYSIZ)) {
		LOGF(log, 7, LOG_ERR, 0,
		     "invalid rsskey - all interfaces must have same rss_key; if=%s",
		     ifp->rif_name);
	}
	struct dev *dev;
	char buf[NM_IFNAMSIZ];
	for (i = 0; i < nr_rx_rings; ++i) {
		dlist_init(&ifp->rif_rss[i].rifrss_txq);
		dev = &ifp->rif_rss[i].rifrss_dev;
		snprintf(buf, sizeof(buf), "%s-%d", ifp->rif_name, i);
		rc = dev_init(log, dev, buf, gt_service_rxtx);
		assert(rc == 0);
	}
	return 0;
}

static int
gt_route_if_add(struct log *log, const char *ifname,
	struct gt_route_if **ifpp)
{
	int i, rc, if_name_len;
	struct gt_route_if *ifp;

	LOG_TRACE(log);
	if (ifpp != NULL) {
		*ifpp = NULL;
	}
	if_name_len = strlen(ifname);
	ifp = gt_route_if_get_by_name(ifname, if_name_len,
	                              GT_ROUTE_IF_NAME_NETMAP);
	if (ifp != NULL) {
		*ifpp = ifp;
		return -EEXIST;
	}
	rc = shm_alloc(log, (void **)&ifp, sizeof(*ifp));
	if (rc < 0) {
		return rc;
	}
	memset(ifp, 0, sizeof(*ifp));
	ifp->rif_idx = -1;
	dlist_init(&ifp->rif_routes);
	ifp->rif_name_len[GT_ROUTE_IF_NAME_NETMAP] = if_name_len;
	for (i = 0; i < if_name_len; ++i) {
		if (strchr("{}", ifname[i]) != NULL) {
			ifp->rif_is_pipe = 1;
			break;
		}
	}
	ifp->rif_mtu = 1500;
	ifp->rif_name_len[GT_ROUTE_IF_NAME_OS] = i;
	memcpy(ifp->rif_name, ifname, if_name_len);
	ifp->rif_name[if_name_len] = '\0';
	rc = route_if_create_devs(log, ifp);
	if (rc) {
		shm_free(ifp);
		return rc;
	}
	DLIST_INSERT_HEAD(&current_mod->route_if_head, ifp, rif_list);
	if (route_monfd != -1) {
		// TODO: DELETE OLD ROUTES...
		gt_route_dump(route_on_msg);
	}
	*ifpp = ifp;
	LOGF(log, LOG_MSG(if_add), LOG_INFO, 0, "ok; if='%s'", ifname);
	return 0;
}

static int
gt_route_if_del(struct log *log, struct gt_route_if *ifp)
{
	int rc, pfx;
	uint32_t key;
	be32_t dst;
	struct gt_route_entry_long *route;

	rc = 0;
	LOG_TRACE(log);
	DLIST_REMOVE(ifp, rif_list);
//	if (gt_route_if_set_link_status_fn != NULL) {
///		(*gt_route_if_set_link_status_fn)(log, ifp, 0);
//	}
	LOGF(log, LOG_MSG(del), LOG_INFO, 0, "ok; if='%s'", ifp->rif_name);
	ifp->rif_list.dls_next = NULL;
	while (!dlist_is_empty(&ifp->rif_routes)) {
		route = DLIST_FIRST(&ifp->rif_routes,
		                     struct gt_route_entry_long,
		                     rtl_list);
		if (route == &current_mod->route_default) {
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
	struct gt_route_if *ifp, const struct ipaddr *addr)
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
		i = gt_rand32() % GT_NR_EPHEMERAL_PORTS;
		ifa->ria_cur_ephemeral_port = GT_EPHEMERAL_PORT_MIN + i;
		DLIST_INSERT_HEAD(&current_mod->route_addr_head, ifa, ria_list);
	}
	for (i = 0; i < ifp->rif_nr_addrs; ++i) {
		tmp = ifp->rif_addrs[i];
		if (!ipaddr_cmp(AF_INET, addr, &tmp->ria_addr)) {
			LOGF(log, LOG_MSG(ifaddr_add), LOG_ERR, 0,
			     "exists; addr=%s",
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
	LOGF(log, LOG_MSG(ifaddr_add), LOG_INFO, 0, "ok; addr=%s",
	     log_add_ipaddr(AF_INET, &addr->ipa_4));
	return 0;
}

static int
route_ifaddr_del(struct log *log, struct gt_route_if *ifp,
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
	LOGF(log, LOG_MSG(ifaddr_del), rc ? LOG_ERR : LOG_INFO, -rc,
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
	if (route == &current_mod->route_default) {
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
	rc = mbuf_alloc(log, current_mod->route_pool, (struct mbuf **)proute);
	if (rc == 0) {
		rule = (struct lprule *)*proute;
		rc = lptree_set(log, &current_mod->route_lptree, rule, key, depth);
		if (rc) {
			mbuf_free((struct mbuf *)rule);
		}
	}
	return rc;
}

static int
gt_route_add(struct log *log, struct gt_route_entry *a)
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
		route = &current_mod->route_default;
		rc = 0;
	} else {
		key = GT_NTOH32(a->rt_dst.ipa_4);
		rule = lptree_get(log, &current_mod->route_lptree, key, a->rt_pfx);
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
	LOGF(log, LOG_MSG(add), rc ? LOG_ERR : LOG_INFO, -rc,
	     "%s; dst=%s/%u, dev='%s', via=%s",
	     rc  ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &a->rt_dst.ipa_4),
	     a->rt_pfx,
	     a->rt_ifp->rif_name,
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
		route = &current_mod->route_default;
		route->rtl_af = AF_UNSPEC;
		rc = 0;
	} else {
		rule = lptree_get(log, &current_mod->route_lptree, GT_NTOH32(dst), pfx);
		route = (struct gt_route_entry_long *)rule;
		if (route != NULL) {
			rc = 0;
			shm_free(route->rtl_saddrs);
			lptree_del(&current_mod->route_lptree, &route->rtl_rule);
		} else {
			rc = -ESRCH;
		}
	}
	if (rc == 0) {
		DLIST_REMOVE(route, rtl_list);
	}
	LOGF(log, LOG_MSG(del), rc ? LOG_ERR : LOG_INFO, -rc, "%s; dst=%s/%d",
	     rc ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &dst), pfx);
	return rc;
}

static void
route_on_msg(struct gt_route_msg *msg)
{
	char buf[NM_IFNAMSIZ + 2 * INET6_ADDRSTRLEN + 32];
	int rc;
	const char *path;
	struct log *log;
	struct gt_route_if *ifp;
	struct strbuf new;

	log = log_trace0();
	strbuf_init(&new, buf, sizeof(buf));
	if (msg->rtm_type != GT_ROUTE_MSG_LINK) {
		if (msg->rtm_af != AF_INET) {
			return;
		}
	}
	// TODO: Why we can't directly get interface by index?
	rc = sys_if_indextoname(log, msg->rtm_if_idx, buf);
	if (rc) {
		return;
	}
	ifp = gt_route_if_get_by_name(buf, strlen(buf), GT_ROUTE_IF_NAME_OS);
	if (ifp == NULL) {
		return;
	}
	switch (msg->rtm_type) {
	case GT_ROUTE_MSG_LINK:
		if (msg->rtm_cmd == GT_ROUTE_MSG_ADD) {
			path = GT_CTL_ROUTE_IF_ADD;
		} else {
			return;
		}
		strbuf_addf(&new, "%s,%d,%d,",
		            ifp->rif_name, msg->rtm_if_idx,
		             msg->rtm_link.rtml_flags);
		strbuf_add_ethaddr(&new, &msg->rtm_link.rtml_hwaddr);
		break;
	case GT_ROUTE_MSG_ADDR:
		if (msg->rtm_cmd == GT_ROUTE_MSG_ADD) {
			path = GT_CTL_ROUTE_ADDR_ADD;
		} else {
			path = GT_CTL_ROUTE_ADDR_DEL;
		}
		strbuf_addf(&new, "%s,", ifp->rif_name); 
		strbuf_add_ipaddr(&new, msg->rtm_af,
		                  msg->rtm_addr.ipa_data_32);
		break;
	case GT_ROUTE_MSG_ROUTE:
		if (msg->rtm_cmd == GT_ROUTE_MSG_ADD) {
			path = GT_CTL_ROUTE_ROUTE_ADD;
		} else {
			path = GT_CTL_ROUTE_ROUTE_DEL;
		}
		strbuf_add_ipaddr(&new, msg->rtm_af,
		                  msg->rtm_route.rtmr_dst.ipa_data_32);
		strbuf_addf(&new, "/%d,%s,",
		            msg->rtm_route.rtmr_pfx,
		            ifp->rif_name);
		strbuf_add_ipaddr(&new, msg->rtm_af,
		                  msg->rtm_route.rtmr_via.ipa_data_32);
		break;
	default:
		return;
	}
	sysctl_me(log, path, strbuf_cstr(&new), NULL);
}

static int
gt_route_monitor_handler(void *udata, short revent)
{
	gt_route_read(route_monfd, route_on_msg);
	return 0;
}

static int
gt_route_monitor_start(struct log *log)
{
	int rc;

	if (route_monfd != -1) {
		return -EALREADY;
	}
	LOG_TRACE(log);
	rc = route_open(current_mod, log);
	if (rc < 0) {
		return rc;
	}
	route_monfd = rc;
	rc = gt_set_nonblock(log, route_monfd);
	if (rc < 0) {
		goto err;
	}
	rc = gt_fd_event_new(log, &gt_route_monitor_event, route_monfd,
	                     "route_monitor", gt_route_monitor_handler, NULL);
	if (rc) {
		goto err;
	}
	gt_fd_event_set(gt_route_monitor_event, POLLIN);
	LOGF(log, LOG_MSG(mon_start), LOG_INFO, 0, "ok; fd=%d", route_monfd);
	gt_route_dump(route_on_msg);
	return 0;
err:
	gt_route_monitor_stop(log);
	return rc;
}

static int
gt_route_monitor_stop(struct log *log)
{
	if (route_monfd == -1) {
		return -EALREADY;
	}
	LOG_TRACE(log);
	gt_fd_event_del(gt_route_monitor_event);
	sys_close(log, route_monfd);
	route_monfd = -1;
	gt_route_monitor_event = NULL;
	return 0;
}

static int
gt_route_ctl_if_del(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc;
	struct gt_route_if *ifp;

	if (new == NULL) {
		return 0;
	}
	ifp = gt_route_if_get_by_name(new, strlen(new), GT_ROUTE_IF_NAME_OS);
	if (ifp == NULL) {
		return -ENXIO;
	}
	rc = gt_route_if_del(log, ifp);
	return rc;
}

static int
gt_route_ctl_if_list_next(void *udata, int id)
{
	int rc;
	struct gt_route_if *ifp;

	rc = -ENOENT;
	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_idx > id) {
			if (rc < 0 || rc > ifp->rif_idx) {
				rc = ifp->rif_idx;
			}
		}
	}
	return rc;
}

static int
gt_route_ctl_if_list(void *udata, int id, const char *new,
	struct strbuf *out)
{
	struct gt_route_if *ifp;

	ifp = gt_route_if_get_by_idx(id);
	if (ifp == NULL) {
		return -ENOENT;
	}
	strbuf_addf(out, "%s,%d,%x,",
	            ifp->rif_name, ifp->rif_idx, ifp->rif_flags);
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
gt_route_ctl_rss_key(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	strbuf_add_rsskey(out, gt_route_rss_key);
	return 0;
}

static int
gt_route_ctl_if_add(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	char ifname[IFNAMSIZ];
	char if_hwaddr_buf[64];
	struct ethaddr if_hwaddr;
	int rc, if_flags, ifindex, configured;
	struct gt_route_if *ifp;

	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%64[^,],%d,%x,%64[^,]",
	            ifname, &ifindex, &if_flags, if_hwaddr_buf);
	if (rc == 4) {
		configured = 1;
		if (ifindex < 0) {
			return -EINVAL;
		}
		rc = ethaddr_aton(&if_hwaddr, if_hwaddr_buf);
		if (rc) {
			return rc;
		}
	} else if (rc == 1) {
		configured = 0;
	} else {
		return -EINVAL;
	}
	rc = gt_route_if_add(log, ifname, &ifp);
	if (rc && rc != -EEXIST) {
		return rc;
	}
	if (configured) {
		ifp->rif_idx = ifindex;
		ifp->rif_flags = if_flags;
		ifp->rif_hwaddr = if_hwaddr;
	}
	return 0;
}

static int
gt_route_ctl_addr_list_next(void *udata, int id)
{
	int off;
	struct gt_route_if *ifp;

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
gt_route_ctl_addr_list(void *udata, int id, const char *new,
	struct strbuf *out)
{
	int off;
	struct gt_route_if *ifp;
	struct gt_route_if_addr *ifa;

	off = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_nr_addrs) {
			ifa = ifp->rif_addrs[id - off];
			strbuf_addf(out, "%s,", ifp->rif_name);
			strbuf_add_ipaddr(out, AF_INET, &ifa->ria_addr);
			return 0;
		}
		off += ifp->rif_nr_addrs;
	}
	return -ENOENT;
}

static int
gt_route_ctl_addr_mod(struct log *log, int add, void *udata,
	const char *new, struct strbuf *out)
{
	int rc, if_name_len;
	char if_name_buf[64];
	char addr_buf[64];
	struct gt_route_if *ifp;
	struct ipaddr a;

	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%64[^,],%64[^,]", if_name_buf, addr_buf);
	if (rc != 2) {
		return -EPROTO;
	}
	if_name_len = strlen(if_name_buf);
	ifp = gt_route_if_get_by_name(if_name_buf, if_name_len,
	                              GT_ROUTE_IF_NAME_NETMAP);
	if (ifp == NULL) {
		return -ENXIO;
	}
	rc = ipaddr_pton(AF_INET, &a, addr_buf);
	if (rc) {
		return rc;
	}
	if (add) {
		rc = route_ifaddr_add(log, NULL, ifp, &a);
	} else {
		rc = route_ifaddr_del(log, ifp, &a);
	}
	return rc;
}

static int
gt_route_ctl_addr_add(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc;

	rc = gt_route_ctl_addr_mod(log, 1, udata, new, out);
	return rc;
}

static int
gt_route_ctl_addr_del(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc;

	rc = gt_route_ctl_addr_mod(log, 0, udata, new, out);
	return rc;
}

static int
gt_route_ctl_list_next(void *udata, int id)
{
	int rc;
	struct mbuf *m;

	if (id == 0) {
		if (current_mod->route_default.rtl_af == AF_INET) {
			return 0;
		}
		id++;
	}
	m = mbuf_next(current_mod->route_pool, id - 1);
	if (m == NULL) {
		return -ENOENT;
	} else {
		rc = mbuf_get_id(current_mod->route_pool, m);
		return rc + 1;
	}
}

static int
gt_route_ctl_list(void *udata, int id, const char *new, struct strbuf *out)
{
	int pfx;
	uint32_t key;
	be32_t dst;
	struct gt_route_entry_long *route;

	if (id == 0) {
		if (current_mod->route_default.rtl_af == AF_INET) {
			dst = 0;
			pfx = 0;
			route = &current_mod->route_default;
			goto out;
		} else {
			return -ENOENT;
		}
	}
	route = (struct gt_route_entry_long *)
		mbuf_get(current_mod->route_pool, id - 1);
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
	strbuf_addf(out, "/%u,%s,", pfx, route->rtl_ifp->rif_name);
	strbuf_add_ipaddr(out, AF_INET, &route->rtl_via);
	return 0;
}

static int
gt_route_ctl_add(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc, dev_len;
	char dst_buf[64];
	char dev_buf[64];
	char via_buf[64];
	struct gt_route_entry route;

	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%64[^/]/%u,%64[^,],%64[^,]",
	            dst_buf,
	            &route.rt_pfx,
	            dev_buf,
	            via_buf);
	if (rc != 4) {
		return -EINVAL;
	}
	route.rt_af = AF_INET;
	if (route.rt_pfx > 32) {
		return -EINVAL;
	}
	rc = ipaddr_pton(AF_INET, &route.rt_dst, dst_buf);
	if (rc) {
		return rc;
	}
	rc = ipaddr_pton(AF_INET, &route.rt_via, via_buf);
	if (rc) {
		return rc;
	}
	dev_len = strlen(dev_buf);
	route.rt_ifp = gt_route_if_get_by_name(dev_buf, dev_len,
	                                       GT_ROUTE_IF_NAME_NETMAP);
	if (route.rt_ifp == NULL) {
		return -ENXIO;
	}
	rc = gt_route_add(log, &route);
	return rc;
}

static int
gt_route_ctl_del(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc, pfx;
	char dst_buf[64];
	struct ipaddr dst;

	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%64[^/]/%u", dst_buf, &pfx);
	if (rc != 2) {
		return -EINVAL;
	}
	if (pfx > 32) {
		return -EINVAL;
	}
	rc = ipaddr_pton(AF_INET, &dst, dst_buf);
	if (rc) {
		return rc;
	}
	rc = route_del(log, dst.ipa_4, pfx);
	return rc;
}

static int
gt_route_ctl_monitor(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc, flag;

	strbuf_addf(out, "%d", route_monfd == -1 ? 0 : 1);
	if (new == NULL) { 
		return 0;
	}
	flag = strtoul(new, NULL, 10);
	if (flag) {
		rc = gt_route_monitor_start(log);
	} else {
		rc = gt_route_monitor_stop(log);
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
	gt_dbg("0");
	rc = lptree_init(log, &mod->route_lptree);
	gt_dbg("1");
	if (rc) {
		return rc;
	}
	rc = mbuf_pool_alloc(log, &mod->route_pool,
	                     sizeof(struct gt_route_entry_long));
	if (rc) {
		return rc;
	}
	gt_dbg("2");
	sysctl_add(log, GT_CTL_ROUTE_RSS_KEY, SYSCTL_RD,
	           NULL, NULL, gt_route_ctl_rss_key);
	sysctl_add_int(log, GT_CTL_ROUTE_RSS_QUEUE_CNT, SYSCTL_RD,
	               &gt_route_rss_q_cnt, 0, 0);
	sysctl_add_list(log, GT_CTL_ROUTE_IF_LIST, SYSCTL_WR,
	                NULL, gt_route_ctl_if_list_next, gt_route_ctl_if_list);
	sysctl_add(log, GT_CTL_ROUTE_IF_ADD, SYSCTL_WR,
	           NULL, NULL, gt_route_ctl_if_add);
	sysctl_add(log, GT_CTL_ROUTE_IF_DEL, SYSCTL_WR,
	           NULL, NULL, gt_route_ctl_if_del);
	sysctl_add_list(log, GT_CTL_ROUTE_ADDR_LIST, SYSCTL_RD,
	                NULL, gt_route_ctl_addr_list_next,
	                gt_route_ctl_addr_list);
	sysctl_add(log, GT_CTL_ROUTE_ADDR_ADD, SYSCTL_WR,
	           NULL, NULL, gt_route_ctl_addr_add);
	sysctl_add(log, GT_CTL_ROUTE_ADDR_DEL, SYSCTL_WR,
	           NULL, NULL, gt_route_ctl_addr_del);
	sysctl_add_list(log, GT_CTL_ROUTE_ROUTE_LIST, SYSCTL_RD,
	                   NULL, gt_route_ctl_list_next, gt_route_ctl_list);
	sysctl_add(log, GT_CTL_ROUTE_ROUTE_ADD, SYSCTL_WR,
	           NULL, NULL, gt_route_ctl_add);
	sysctl_add(log, GT_CTL_ROUTE_ROUTE_DEL, SYSCTL_WR,
	           NULL, NULL,  gt_route_ctl_del);
	sysctl_add(log, GT_CTL_ROUTE_MONITOR, SYSCTL_WR,
	           NULL, NULL, gt_route_ctl_monitor);
	return rc;
}
int
route_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
	printf("Route attach %p(%p)\n", current_mod, raw_mod);
	return 0;
}

void
route_mod_deinit(struct log *log, void *raw_mod)
{
	struct route_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	sysctl_del(log, GT_CTL_ROUTE_MONITOR);
	sysctl_del(log, GT_CTL_ROUTE_ROUTE_DEL);
	sysctl_del(log, GT_CTL_ROUTE_ROUTE_ADD);
	sysctl_del(log, GT_CTL_ROUTE_ROUTE_LIST);
	sysctl_del(log, GT_CTL_ROUTE_ADDR_DEL);
	sysctl_del(log, GT_CTL_ROUTE_ADDR_ADD);
	sysctl_del(log, GT_CTL_ROUTE_ADDR_LIST);
	sysctl_del(log, GT_CTL_ROUTE_IF_DEL);
	sysctl_del(log, GT_CTL_ROUTE_IF_ADD);
	sysctl_del(log, GT_CTL_ROUTE_IF_LIST);
	sysctl_del(log, GT_CTL_ROUTE_PORT_PAIRITY);
	sysctl_del(log, GT_CTL_ROUTE_RSS_QUEUE_CNT);
	sysctl_del(log, GT_CTL_ROUTE_RSS_QUEUE_ID);
	sysctl_del(log, GT_CTL_ROUTE_RSS_KEY);
	gt_route_mod_clean(log);
	lptree_deinit(&mod->route_lptree);
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
route_mod_detach(struct log *log)
{
	current_mod = NULL;
}

void
gt_route_mod_clean(struct log *log)
{
#if 0
	struct gt_route_if *ifp;
	struct gt_route_if_addr *ifa;

	LOG_TRACE(log);
	gt_route_monitor_stop(log);
	gt_route_default.rtl_af = AF_UNSPEC;
	while (!dlist_is_empty(&gt_route_if_head)) {
		ifp = DLIST_FIRST(&gt_route_if_head,
		                  struct gt_route_if, rif_list);
		gt_route_if_del(log, ifp);
	}
	while (!dlist_is_empty(&gt_route_addr_head)) {
		ifa = DLIST_FIRST(&gt_route_addr_head,
		                  struct gt_route_if_addr, ria_list);
		DLIST_REMOVE(ifa, ria_list);
		free(ifa);
	}
	// TODO: clean routes
#endif
}

struct gt_route_if *
gt_route_if_get_by_idx(int idx)
{
	struct gt_route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_idx == idx) {
			return ifp;
		}
	}
	return NULL;
}

struct gt_route_if *
gt_route_if_get_by_name(const char *if_name, int if_name_len, int if_name_type)
{
	struct gt_route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_name_len[if_name_type] == if_name_len &&
		    !memcmp(ifp->rif_name, if_name, if_name_len)) {
			return ifp;
		}
	}
	return NULL;
}

struct gt_route_if_addr *
route_ifaddr_get(int af, const struct ipaddr *addr)
{
	struct gt_route_if_addr *ifa;

	DLIST_FOREACH(ifa, &current_mod->route_addr_head, ria_list) {
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
	rule = lptree_search(&current_mod->route_lptree, key);
	route = (struct gt_route_entry_long *)rule;
	if (route == NULL) {
		if (current_mod->route_default.rtl_af == AF_INET) {
			route = &current_mod->route_default;
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

int
gt_route_if_not_empty_txr(struct gt_route_if *ifp, struct dev_pkt *pkt)
{
	int rc;
	struct dev *dev;
	if (gt_route_rss_q_id < 0 || gt_route_rss_q_id > 3)
		return -ENOBUFS;
	dev = &ifp->rif_rss[gt_route_rss_q_id].rifrss_dev;
	rc = dev_not_empty_txr(dev, pkt);
	return rc;
}

void
gt_route_if_rxr_next(struct gt_route_if *ifp, struct netmap_ring *rxr)
{
	struct netmap_slot *slot;

	slot = rxr->slot + rxr->cur;
	ifp->rif_cnt_rx_pkts++;
	ifp->rif_cnt_rx_bytes += slot->len;
	DEV_RXR_NEXT(rxr);
}

void
gt_route_if_tx(struct gt_route_if *ifp, struct dev_pkt *pkt)
{
	ifp->rif_cnt_tx_pkts++;
	ifp->rif_cnt_tx_bytes += pkt->pkt_len;
//	if (pkt->pkt_no_dev) {
//		(*gt_route_if_tx_fn)(ifp, pkt);
//	}
	dev_tx(pkt);
}

int
gt_route_if_tx3(struct gt_route_if *ifp, void *data, int len)
{
	int rc;
	struct dev *dev;
	if (gt_route_rss_q_id < 0 || gt_route_rss_q_id > 3)
		return -ENOBUFS;
	dev = &ifp->rif_rss[gt_route_rss_q_id].rifrss_dev;
	rc = dev_tx3(dev, data, len);
	if (rc) {
		ifp->rif_cnt_tx_drop++;
	}
	return rc;
}

 void gt_tcp_flush_if(struct gt_route_if *ifp);

void
gt_sock_tx_flush()
{
	struct gt_route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		gt_tcp_flush_if(ifp);
	}
}


