#include "route.h"
#include "log.h"
#include "sys.h"
#include "mbuf.h"
#include "inet.h"
#include "ctl.h"
#include "strbuf.h"
#include "lptree.h"
#include "fd_event.h"

#define ROUTE_LOG_MSG_FOREACH(x) \
	x(if_add) \
	x(if_del) \
	x(ifaddr_add) \
	x(ifaddr_del) \
	x(set_saddrs); \
	x(add) \
	x(del) \
	x(on_msg) \
	x(mon_start) \
	x(mon_stop) \
	x(mod_init) \
	x(mod_deinit) \
	x(mod_clean) \

struct route_mod {
	struct log_scope log_scope;
};

struct gt_route_entry_long {
	struct lprule rtl_rule;
	struct dllist rtl_list;
	int rtl_af;
	struct gt_route_if *rtl_ifp;
	struct gt_ip_addr rtl_via;
	int rtl_nr_saddrs;
	struct gt_route_if_addr **rtl_saddrs;
};

struct dllist gt_route_if_head;
int gt_route_rss_q_id;
int gt_route_rss_q_cnt;
int gt_route_port_pairity;
uint8_t gt_route_rss_key[GT_RSS_KEY_SIZE];
int (*gt_route_if_set_link_status_fn)(struct gt_log *log,
	struct gt_route_if *ifp, int add);
int (*gt_route_if_not_empty_txr_fn)(struct gt_route_if *ifp,
	struct gt_dev_pkt *pkt);
void (*gt_route_if_tx_fn)(struct gt_route_if *ifp, struct gt_dev_pkt *pkt);

static struct route_mod *this_mod;

static struct gt_fd_event *gt_route_monitor_event;
static int route_monfd = -1;
static struct lpnode gt_route_lptree;
static struct gt_mbuf_pool *gt_route_pool;
static struct gt_route_entry_long gt_route_default;
static struct dllist gt_route_addr_head;

static void gt_route_foreach_set_saddrs(struct gt_log *log,
	struct gt_route_if *ifp);

static int gt_route_if_add(struct gt_log *log, const char *ifname,
	struct gt_route_if **ifpp);

static int gt_route_if_del(struct gt_log *log, struct gt_route_if *ifp);

static int route_ifaddr_add(struct gt_log *log,
	struct gt_route_if_addr **ifap, struct gt_route_if *ifp,
	const struct gt_ip_addr *addr);

static int route_ifaddr_del(struct gt_log *log, struct gt_route_if *ifp,
	const struct gt_ip_addr *addr);

static int gt_route_saddr_compar(const void *a, const void *b, void *arg);

static int route_set_saddrs(struct gt_log *log,
	struct gt_route_entry_long *route);

static int gt_route_add(struct gt_log *log, struct gt_route_entry *a);

static int route_del(struct gt_log *log, be32_t dst, int pfx);

static void route_on_msg(struct gt_route_msg *msg);

static int gt_route_monitor_handler(void *udata, short revent);

static int gt_route_monitor_start(struct gt_log *log);

static int gt_route_monitor_stop(struct gt_log *log);

static int gt_route_ctl_if_del(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out);

static int gt_route_ctl_if_list_next(void *udata, int id);

static int gt_route_ctl_if_list(void *udata, int id, const char *new,
	struct gt_strbuf *out);

static int gt_route_ctl_rss_key(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);

static int gt_route_ctl_if_add(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);

static int gt_route_ctl_addr_list_next(void *udata, int id);

static int gt_route_ctl_addr_list(void *udata, int id, const char *new,
	struct gt_strbuf *out);

static int gt_route_ctl_addr_mod(struct gt_log *log, int add, void *udata,
	const char *new, struct gt_strbuf *out);

static int gt_route_ctl_addr_add(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);

static int gt_route_ctl_addr_del(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);

static int gt_route_ctl_list_next(void *udata, int id);

static int gt_route_ctl_list(void *udata, int id, const char *new,
	struct gt_strbuf *out);

static int gt_route_ctl_add(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out);

static int gt_route_ctl_del(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out);

static int gt_route_ctl_monitor(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);

static void
gt_route_foreach_set_saddrs(struct gt_log *log, struct gt_route_if *ifp)
{
	struct gt_route_entry_long *route;

	DLLIST_FOREACH(route, &ifp->rif_routes, rtl_list) {
		route_set_saddrs(log, route);
	}
}

static int
gt_route_if_add(struct gt_log *log, const char *ifname,
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
	rc = gt_sys_malloc(log, (void **)&ifp, sizeof(*ifp));
	if (rc < 0) {
		return rc;
	}
	memset(ifp, 0, sizeof(*ifp));
	ifp->rif_idx = -1;
	dllist_init(&ifp->rif_txq);
	dllist_init(&ifp->rif_routes);
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
	if (gt_route_if_set_link_status_fn != NULL) {
		rc = (*gt_route_if_set_link_status_fn)(log, ifp, 1);
		if (rc && rc != -EEXIST) {
			return rc;
		}
	}
	DLLIST_INSERT_HEAD(&gt_route_if_head, ifp, rif_list);
	if (route_monfd != -1) {
		// TODO: DELETE OLD ROUTES...
		gt_route_dump(route_on_msg);
	}
	*ifpp = ifp;
	LOGF(log, if_add, LOG_INFO, 0, "ok; if='%s'", ifname);
	return 0;
}

static int
gt_route_if_del(struct gt_log *log, struct gt_route_if *ifp)
{
	int rc, pfx;
	uint32_t key;
	be32_t dst;
	struct gt_route_entry_long *route;

	rc = 0;
	LOG_TRACE(log);
	DLLIST_REMOVE(ifp, rif_list);
	if (gt_route_if_set_link_status_fn != NULL) {
		(*gt_route_if_set_link_status_fn)(log, ifp, 0);
	}
	LOGF(log, del, LOG_INFO, 0, "ok; if='%s'", ifp->rif_name);
	ifp->rif_list.dls_next = NULL;
	while (!dllist_isempty(&ifp->rif_routes)) {
		route = DLLIST_FIRST(&ifp->rif_routes,
		                     struct gt_route_entry_long,
		                     rtl_list);
		if (route == &gt_route_default) {
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
route_ifaddr_add(struct gt_log *log, struct gt_route_if_addr **ifap,
	struct gt_route_if *ifp, const struct gt_ip_addr *addr)
{
	int i, rc;
	struct gt_route_if_addr *ifa, *tmp;

	LOG_TRACE(log);
	ifa = route_ifaddr_get(AF_INET, addr);
	if (ifa == NULL) {
		rc = gt_sys_malloc(log, (void **)&ifa, sizeof(*ifa));
		if (rc < 0) {
			return rc;
		}
		ifa->ria_addr = *addr;
		ifa->ria_ref_cnt = 0;
		i = gt_rand32() % GT_NR_EPHEMERAL_PORTS;
		ifa->ria_cur_ephemeral_port = GT_EPHEMERAL_PORT_MIN + i;
		DLLIST_INSERT_HEAD(&gt_route_addr_head, ifa, ria_list);
	}
	for (i = 0; i < ifp->rif_nr_addrs; ++i) {
		tmp = ifp->rif_addrs[i];
		if (!gt_ip_addr_cmp(AF_INET, addr, &tmp->ria_addr)) {
			LOGF(log, ifaddr_add, LOG_ERR, 0, "exists; addr=%s",
			     gt_log_add_ip_addr(AF_INET, &addr->ipa_4));
			return -EEXIST;
		}
	}
	ifa->ria_ref_cnt++;
	rc = gt_sys_realloc(log, (void **)&ifp->rif_addrs,
	                    (ifp->rif_nr_addrs + 1) * sizeof(ifa));
	if (rc) {
		DLLIST_REMOVE(ifa, ria_list);
		free(ifa);
		return rc;
	}
	ifp->rif_addrs[ifp->rif_nr_addrs++] = ifa;
	gt_route_foreach_set_saddrs(log, ifp);
	if (ifap != NULL) {
		*ifap = ifa;
	}
	LOGF(log, ifaddr_add, LOG_INFO, 0, "ok; addr=%s",
	     log_add_ipaddr(AF_INET, &addr->ipa_4));
	return 0;
}

static int
route_ifaddr_del(struct gt_log *log, struct gt_route_if *ifp,
	const struct gt_ip_addr *addr)
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
					DLLIST_REMOVE(ifa, ria_list);
					free(ifa);
				}
				rc = 0;
				break;
			}
		}
	}
	LOGF(log, ifaddr_del, rc ? LOG_ERR : LOG_INFO, -rc, "%s; addr=%s",
	     rc ? "failed" : "ok",
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
	if (route == &gt_route_default) {
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
route_set_saddrs(struct gt_log *log, struct gt_route_entry_long *route)
{
	int n, rc, size;

	LOG_TRACE(log);
	n = route->rtl_ifp->rif_nr_addrs;
	size = n * sizeof(struct gt_route_if_addr *);
	if (route->rtl_nr_saddrs < n) {
		rc = gt_sys_realloc(log, (void **)&route->rtl_saddrs, size);
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
gt_route_alloc(struct gt_log *log, struct gt_route_entry_long **proute,
	uint32_t key, uint8_t depth)
{
	int rc;
	struct lprule *rule;

	rc = gt_mbuf_alloc(log, gt_route_pool, (struct gt_mbuf **)proute);
	if (rc == 0) {
		rule = (struct lprule *)*proute;
		rc = lptree_set(log, &gt_route_lptree, rule, key, depth);
		if (rc) {
			gt_mbuf_free((struct gt_mbuf *)rule);
		}
	}
	return rc;
}

static int
gt_route_add(struct gt_log *log, struct gt_route_entry *a)
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
		route = &gt_route_default;
		rc = 0;
	} else {
		key = GT_NTOH32(a->rt_dst.ipa_4);
		rule = lptree_get(&gt_route_lptree, key, a->rt_pfx);
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
		DLLIST_INSERT_HEAD(&route->rtl_ifp->rif_routes,
		                   route, rtl_list);
		route_set_saddrs(log, route);
	}
	LOGF(log, add, rc ? LOG_ERR : LOG_INFO, -rc,
	     "%s; dst=%s/%u, dev='%s', via=%s",
	     rc  ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &a->rt_dst.ipa_4),
	     a->rt_pfx,
	     a->rt_ifp->rif_name,
	     log_add_ipaddr(AF_INET, &a->rt_via.ipa_4));
	return rc;
}

static int
route_del(struct gt_log *log, be32_t dst, int pfx)
{
	int rc;
	struct lprule *rule;
	struct gt_route_entry_long *route;

	LOG_TRACE(log);	
	if (pfx > 32) {
		rc = -EINVAL;
	} else if (pfx == 0) {
		route = &gt_route_default;
		route->rtl_af = AF_UNSPEC;
		rc = 0;
	} else {
		rule = lptree_get(&gt_route_lptree, GT_NTOH32(dst), pfx);
		route = (struct gt_route_entry_long *)rule;
		if (route != NULL) {
			rc = 0;
			free(route->rtl_saddrs);
			lptree_del(&route->rtl_rule);
		} else {
			rc = -ESRCH;
		}
	}
	if (rc == 0) {
		DLLIST_REMOVE(route, rtl_list);
	}
	LOGF(log, del, rc ? LOG_ERR : LOG_INFO, -rc, "%s; dst=%s/%d",
	     rc ? "failed" : "ok",
	     log_add_ipaddr(AF_INET, &dst), pfx);
	return rc;
}

static void
route_on_msg(struct gt_route_msg *msg)
{
	char buf[GT_IFNAMSIZ + 2 * INET6_ADDRSTRLEN + 32];
	int rc;
	const char *path;
	struct gt_log *log;
	struct gt_route_if *ifp;
	struct gt_strbuf new;

	log = log_trace0();
	gt_strbuf_init(&new, buf, sizeof(buf));
	if (msg->rtm_type != GT_ROUTE_MSG_LINK) {
		if (msg->rtm_af != AF_INET) {
			return;
		}
	}
	// TODO: Why we can't directly get interface by index?
	rc = gt_sys_if_indextoname(log, msg->rtm_if_idx, buf);
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
		gt_strbuf_addf(&new, "%s,%d,%d,",
		               ifp->rif_name, msg->rtm_if_idx,
		               msg->rtm_link.rtml_flags);
		gt_strbuf_add_eth_addr(&new, &msg->rtm_link.rtml_hwaddr);
		break;
	case GT_ROUTE_MSG_ADDR:
		if (msg->rtm_cmd == GT_ROUTE_MSG_ADD) {
			path = GT_CTL_ROUTE_ADDR_ADD;
		} else {
			path = GT_CTL_ROUTE_ADDR_DEL;
		}
		gt_strbuf_addf(&new, "%s,", ifp->rif_name); 
		gt_strbuf_add_ip_addr(&new, msg->rtm_af,
		                       msg->rtm_addr.ipa_data_32);
		break;
	case GT_ROUTE_MSG_ROUTE:
		if (msg->rtm_cmd == GT_ROUTE_MSG_ADD) {
			path = GT_CTL_ROUTE_ROUTE_ADD;
		} else {
			path = GT_CTL_ROUTE_ROUTE_DEL;
		}
		gt_strbuf_add_ip_addr(&new, msg->rtm_af,
		                      msg->rtm_route.rtmr_dst.ipa_data_32);
		gt_strbuf_addf(&new, "/%d,%s,",
		                msg->rtm_route.rtmr_pfx,
		                ifp->rif_name);
		gt_strbuf_add_ip_addr(&new, msg->rtm_af,
		                      msg->rtm_route.rtmr_via.ipa_data_32);
		break;
	default:
		return;
	}
	gt_ctl_me(log, path, gt_strbuf_cstr(&new), NULL);
}

static int
gt_route_monitor_handler(void *udata, short revent)
{
	gt_route_read(route_monfd, route_on_msg);
	return 0;
}

static int
gt_route_monitor_start(struct gt_log *log)
{
	int rc;

	if (route_monfd != -1) {
		return -EALREADY;
	}
	LOG_TRACE(log);
	rc = gt_route_open(log);
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
	LOGF(log, mon_start, LOG_INFO, 0, "ok; fd=%d", route_monfd);
	gt_route_dump(route_on_msg);
	return 0;
err:
	gt_route_monitor_stop(log);
	return rc;
}

static int
gt_route_monitor_stop(struct gt_log *log)
{
	if (route_monfd == -1) {
		return -EALREADY;
	}
	LOG_TRACE(log);
	gt_fd_event_del(gt_route_monitor_event);
	gt_sys_close(log, route_monfd);
	route_monfd = -1;
	gt_route_monitor_event = NULL;
	return 0;
}

static int
gt_route_ctl_if_del(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
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
	GT_ROUTE_IF_FOREACH(ifp) {
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
	struct gt_strbuf *out)
{
	struct gt_route_if *ifp;

	ifp = gt_route_if_get_by_idx(id);
	if (ifp == NULL) {
		return -ENOENT;
	}
	gt_strbuf_addf(out, "%s,%d,%x,",
	               ifp->rif_name, ifp->rif_idx, ifp->rif_flags);
	gt_strbuf_add_eth_addr(out, &ifp->rif_hwaddr);
	gt_strbuf_addf(out, ",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64,
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
gt_route_ctl_rss_key(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	gt_strbuf_add_rss_key(out, gt_route_rss_key);
	return 0;
}

static int
gt_route_ctl_if_add(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	char ifname[IFNAMSIZ];
	char if_hwaddr_buf[64];
	struct gt_eth_addr if_hwaddr;
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
		rc = gt_eth_addr_aton(&if_hwaddr, if_hwaddr_buf);
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
	GT_ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_nr_addrs) {
			return id;
		}
		off += ifp->rif_nr_addrs;
	}
	return -ENOENT;
}

static int
gt_route_ctl_addr_list(void *udata, int id, const char *new,
	struct gt_strbuf *out)
{
	int off;
	struct gt_route_if *ifp;
	struct gt_route_if_addr *ifa;

	off = 0;
	GT_ROUTE_IF_FOREACH(ifp) {
		if (id - off < ifp->rif_nr_addrs) {
			ifa = ifp->rif_addrs[id - off];
			gt_strbuf_addf(out, "%s,", ifp->rif_name);
			gt_strbuf_add_ip_addr(out, AF_INET, &ifa->ria_addr);
			return 0;
		}
		off += ifp->rif_nr_addrs;
	}
	return -ENOENT;
}

static int
gt_route_ctl_addr_mod(struct gt_log *log, int add, void *udata,
	const char *new, struct gt_strbuf *out)
{
	int rc, if_name_len;
	char if_name_buf[64];
	char addr_buf[64];
	struct gt_route_if *ifp;
	struct gt_ip_addr a;

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
	rc = gt_ip_addr_pton(AF_INET, &a, addr_buf);
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
gt_route_ctl_addr_add(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc;

	rc = gt_route_ctl_addr_mod(log, 1, udata, new, out);
	return rc;
}

static int
gt_route_ctl_addr_del(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc;

	rc = gt_route_ctl_addr_mod(log, 0, udata, new, out);
	return rc;
}

static int
gt_route_ctl_list_next(void *udata, int id)
{
	int rc;
	struct gt_mbuf *m;

	if (id == 0) {
		if (gt_route_default.rtl_af == AF_INET) {
			return 0;
		}
		id++;
	}
	m = gt_mbuf_next(gt_route_pool, id - 1);
	if (m == NULL) {
		return -ENOENT;
	} else {
		rc = gt_mbuf_get_id(gt_route_pool, m);
		return rc + 1;
	}
}

static int
gt_route_ctl_list(void *udata, int id, const char *new, struct gt_strbuf *out)
{
	int pfx;
	uint32_t key;
	be32_t dst;
	struct gt_route_entry_long *route;

	if (id == 0) {
		if (gt_route_default.rtl_af == AF_INET) {
			dst = 0;
			pfx = 0;
			route = &gt_route_default;
			goto out;
		} else {
			return -ENOENT;
		}
	}
	route = (struct gt_route_entry_long *)
		gt_mbuf_get(gt_route_pool, id - 1);
	if (route == NULL) {
		return -ENOENT;
	}
	ASSERT(route->rtl_ifp != NULL);
	ASSERT(route->rtl_af == AF_INET);
	key = route->rtl_rule.lpr_key;
	pfx = route->rtl_rule.lpr_depth;
	dst = GT_HTON32(key);
out:
	gt_strbuf_add_ip_addr(out, AF_INET, &dst);
	gt_strbuf_addf(out, "/%u,%s,", pfx, route->rtl_ifp->rif_name);
	gt_strbuf_add_ip_addr(out, AF_INET, &route->rtl_via);
	return 0;
}

static int
gt_route_ctl_add(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
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
	rc = gt_ip_addr_pton(AF_INET, &route.rt_dst, dst_buf);
	if (rc) {
		return rc;
	}
	rc = gt_ip_addr_pton(AF_INET, &route.rt_via, via_buf);
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
gt_route_ctl_del(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc, pfx;
	char dst_buf[64];
	struct gt_ip_addr dst;

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
	rc = gt_ip_addr_pton(AF_INET, &dst, dst_buf);
	if (rc) {
		return rc;
	}
	rc = route_del(log, dst.ipa_4, pfx);
	return rc;
}

static int
gt_route_ctl_monitor(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc, flag;

	gt_strbuf_addf(out, "%d", route_monfd == -1 ? 0 : 1);
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
gt_route_mod_init()
{
	int rc;
	struct gt_log *log;

	log_scope_init(&this_mod->log_scope, "route");
	log = log_trace0();
	gt_route_default.rtl_af = AF_UNSPEC;
	dllist_init(&gt_route_if_head);
	dllist_init(&gt_route_addr_head);
	rc = gt_mbuf_pool_new(log, &gt_route_pool,
	                      sizeof(struct gt_route_entry_long));
	if (rc) {
		log_scope_deinit(log, &this_mod->log_scope);
		return rc;
	}
	rc = lptree_init(log, &gt_route_lptree);
	if (rc) {
		gt_mbuf_pool_del(gt_route_pool);
		log_scope_deinit(log, &this_mod->log_scope);
		return rc;
	}
	gt_ctl_add(log, GT_CTL_ROUTE_RSS_KEY, GT_CTL_RD,
	           NULL, NULL, gt_route_ctl_rss_key);
	gt_ctl_add_int(log, GT_CTL_ROUTE_RSS_QUEUE_ID, GT_CTL_RD,
	               &gt_route_rss_q_id, 0, 0);
	gt_ctl_add_int(log, GT_CTL_ROUTE_RSS_QUEUE_CNT, GT_CTL_RD,
	               &gt_route_rss_q_cnt, 0, 0);
	gt_ctl_add_int(log, GT_CTL_ROUTE_PORT_PAIRITY, GT_CTL_RD,
	               &gt_route_port_pairity, 0, 0);
	gt_ctl_add_list(log, GT_CTL_ROUTE_IF_LIST, GT_CTL_WR,
	                NULL, gt_route_ctl_if_list_next, gt_route_ctl_if_list);
	gt_ctl_add(log, GT_CTL_ROUTE_IF_ADD, GT_CTL_WR,
	           NULL, NULL, gt_route_ctl_if_add);
	gt_ctl_add(log, GT_CTL_ROUTE_IF_DEL, GT_CTL_WR,
	           NULL, NULL, gt_route_ctl_if_del);
	gt_ctl_add_list(log, GT_CTL_ROUTE_ADDR_LIST, GT_CTL_RD,
	                NULL, gt_route_ctl_addr_list_next,
	                gt_route_ctl_addr_list);
	gt_ctl_add(log, GT_CTL_ROUTE_ADDR_ADD, GT_CTL_WR,
	           NULL, NULL, gt_route_ctl_addr_add);
	gt_ctl_add(log, GT_CTL_ROUTE_ADDR_DEL, GT_CTL_WR,
	           NULL, NULL, gt_route_ctl_addr_del);
	gt_ctl_add_list(log, GT_CTL_ROUTE_ROUTE_LIST, GT_CTL_RD,
	                   NULL, gt_route_ctl_list_next, gt_route_ctl_list);
	gt_ctl_add(log, GT_CTL_ROUTE_ROUTE_ADD, GT_CTL_WR,
	           NULL, NULL, gt_route_ctl_add);
	gt_ctl_add(log, GT_CTL_ROUTE_ROUTE_DEL, GT_CTL_WR,
	           NULL, NULL,  gt_route_ctl_del);
	gt_ctl_add(log, GT_CTL_ROUTE_MONITOR, GT_CTL_WR,
	           NULL, NULL, gt_route_ctl_monitor);
	return 0;
}

void
gt_route_mod_deinit(struct gt_log *log)
{
	LOG_TRACE(log);
	gt_ctl_del(log, GT_CTL_ROUTE_MONITOR);
	gt_ctl_del(log, GT_CTL_ROUTE_ROUTE_DEL);
	gt_ctl_del(log, GT_CTL_ROUTE_ROUTE_ADD);
	gt_ctl_del(log, GT_CTL_ROUTE_ROUTE_LIST);
	gt_ctl_del(log, GT_CTL_ROUTE_ADDR_DEL);
	gt_ctl_del(log, GT_CTL_ROUTE_ADDR_ADD);
	gt_ctl_del(log, GT_CTL_ROUTE_ADDR_LIST);
	gt_ctl_del(log, GT_CTL_ROUTE_IF_DEL);
	gt_ctl_del(log, GT_CTL_ROUTE_IF_ADD);
	gt_ctl_del(log, GT_CTL_ROUTE_IF_LIST);
	gt_ctl_del(log, GT_CTL_ROUTE_PORT_PAIRITY);
	gt_ctl_del(log, GT_CTL_ROUTE_RSS_QUEUE_CNT);
	gt_ctl_del(log, GT_CTL_ROUTE_RSS_QUEUE_ID);
	gt_ctl_del(log, GT_CTL_ROUTE_RSS_KEY);
	gt_route_mod_clean(log);
	lptree_deinit(&gt_route_lptree);
	log_scope_deinit(log, &this_mod->log_scope);
}

void
gt_route_mod_clean(struct gt_log *log)
{
	struct gt_route_if *ifp;
	struct gt_route_if_addr *ifa;

	LOG_TRACE(log);
	gt_route_monitor_stop(log);
	gt_route_default.rtl_af = AF_UNSPEC;
	while (!dllist_isempty(&gt_route_if_head)) {
		ifp = DLLIST_FIRST(&gt_route_if_head,
		                   struct gt_route_if, rif_list);
		gt_route_if_del(log, ifp);
	}
	while (!dllist_isempty(&gt_route_addr_head)) {
		ifa = DLLIST_FIRST(&gt_route_addr_head,
		                   struct gt_route_if_addr, ria_list);
		DLLIST_REMOVE(ifa, ria_list);
		free(ifa);
	}
	// TODO: clean routes
	gt_route_if_set_link_status_fn = NULL;
}

struct gt_route_if *
gt_route_if_get_by_idx(int idx)
{
	struct gt_route_if *ifp;

	GT_ROUTE_IF_FOREACH(ifp) {
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

	DLLIST_FOREACH(ifp, &gt_route_if_head, rif_list) {
		if (ifp->rif_name_len[if_name_type] == if_name_len &&
		    !memcmp(ifp->rif_name, if_name, if_name_len)) {
			return ifp;
		}
	}
	return NULL;
}

struct gt_route_if_addr *
route_ifaddr_get(int af, const struct gt_ip_addr *addr)
{
	struct gt_route_if_addr *ifa;

	DLLIST_FOREACH(ifa, &gt_route_addr_head, ria_list) {
		if (!gt_ip_addr_cmp(af, &ifa->ria_addr, addr)) {
			return ifa;
		}
	}
	return NULL;
}

struct gt_route_if_addr *
gt_route_if_addr_get4(be32_t a4)
{
	struct gt_ip_addr a;
	struct gt_route_if_addr *ifa;

	a.ipa_4 = a4;
	ifa = route_ifaddr_get(AF_INET, &a);
	return ifa;
}

int
gt_route_get(int af, struct gt_ip_addr *src, struct gt_route_entry *g)
{
	int i;
	uint32_t key;
	struct lprule *rule;
	struct gt_route_entry_long *route;
	struct gt_route_if_addr *ifa;

	ASSERT(af == AF_INET);
	g->rt_af = AF_INET;
	if (gt_ip_addr4_is_loopback(g->rt_dst.ipa_4)) {
		return -ENETUNREACH;
	}
	key = GT_NTOH32(g->rt_dst.ipa_4);
	rule = lptree_search(&gt_route_lptree, key);
	route = (struct gt_route_entry_long *)rule;
	if (route == NULL) {
		if (gt_route_default.rtl_af == AF_INET) {
			route = &gt_route_default;
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
	if (src != NULL && !gt_ip_addr_is_zero(af, src)) {
		for (i = 0; i < route->rtl_nr_saddrs; ++i) {
			ifa = route->rtl_saddrs[i];
			if (!gt_ip_addr_cmp(af, src, &ifa->ria_addr)) {
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
	struct gt_ip_addr src;

	src.ipa_4 = pref_src_ip4;
	rc = gt_route_get(AF_INET, &src, route);
	return rc;
}

int
gt_route_if_not_empty_txr(struct gt_route_if *ifp, struct gt_dev_pkt *pkt)
{
	int rc;

	if (ifp->rif_dev.dev_nmd == NULL) {
		if (gt_route_if_not_empty_txr_fn == NULL) {
			return -ENOBUFS;
		} else {
			rc = (*gt_route_if_not_empty_txr_fn)(ifp, pkt);
			pkt->pkt_no_dev = 1;
		}
	} else {
		rc = gt_dev_not_empty_txr(&ifp->rif_dev, pkt);
	}
	return rc;
}

void
gt_route_if_rxr_next(struct gt_route_if *ifp, struct netmap_ring *rxr)
{
	struct netmap_slot *slot;

	slot = rxr->slot + rxr->cur;
	ifp->rif_cnt_rx_pkts++;
	ifp->rif_cnt_rx_bytes += slot->len;
	GT_DEV_RXR_NEXT(rxr);
}

void
gt_route_if_tx(struct gt_route_if *ifp, struct gt_dev_pkt *pkt)
{
	ifp->rif_cnt_tx_pkts++;
	ifp->rif_cnt_tx_bytes += pkt->pkt_len;
	if (pkt->pkt_no_dev) {
		(*gt_route_if_tx_fn)(ifp, pkt);
	}
	gt_dev_tx(pkt);
}

int
gt_route_if_tx3(struct gt_route_if *ifp, void *data, int len)
{
	int rc;

	rc = gt_dev_tx3(&ifp->rif_dev, data, len);
	if (rc) {
		ifp->rif_cnt_tx_drop++;
	}
	return rc;
}
