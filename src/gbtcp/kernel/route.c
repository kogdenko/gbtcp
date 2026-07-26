// SPDX-License-Identifier: LGPL-2.1-only

// TODO: Handle interface UP/DOWN

#include <gbtcp/kernel/api.h>
#include <gbtcp/kernel/cli.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/route.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/vector.h>

#define gt_notice(...) gt_notice3(&gt_main->route_logger, ##__VA_ARGS__)
#define gt_info(...) gt_info3(&gt_main->route_logger, ##__VA_ARGS__)
#define gt_err(...) gt_err3(&gt_main->route_logger, ##__VA_ARGS__)

#include <gbtcp/kernel/ip.pb-c.h>

struct route_entry_long {
	struct lptree_rule rtl_rule;
	struct gt_dlist rtl_list;
	int rtl_af;
	struct route_if *rtl_ifp;
	struct ipaddr rtl_via;
	int rtl_nsrcs;
	struct route_if_addr **rtl_srcs;
};

static gt_on_dev_f *gt_on_dev_handlers;

static void route_if_del(struct route_if *);

static int route_src_compar(const void *a, const void *b, void *);

static int route_set_srcs(struct route_entry_long *);

static void route_del(struct route_entry_long *);

static void
route_foreach_set_srcs(struct route_if *ifp)
{
	struct route_entry_long *route;

	GT_DLIST_FOREACH(route, &ifp->rif_routes, rtl_list) {
		route_set_srcs(route);
	}
}

struct gt_dlist *
route_if_head(void)
{
	return &gt_main->route_if_head;
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

// Fixed-signature memdup for gt_read_rss_key's callback; allocates in the
// active cache.
static void *
route_cache_memdup(void *ptr, size_t size)
{
	void *cp;

	cp = gt_malloc(shm_cache(), size, 0);
	if (cp != NULL) {
		memcpy(cp, ptr, size);
	}
	return cp;
}

static int
route_if_add(const char *ifname, u8 dev_io, struct route_if **ifpp)
{
	int rc;
	struct route_if *ifp;

	if (ifpp != NULL) {
		*ifpp = NULL;
	}
	ifp = route_if_get(ifname);
	if (ifp != NULL) {
		if (ifpp != NULL) {
			*ifpp = ifp;
		}
		return -EEXIST;
	}
	ifp = gt_malloc(shm_cache(), sizeof(*ifp), 0);
	if (ifp == NULL) {
		rc = -ENOMEM;
		goto err;
	}
	memset(ifp, 0, sizeof(*ifp));
	gt_dlist_init(&ifp->rif_routes);

	ifp->rif_mtu = 1500;

	gt_strzcpy(ifp->rif_name, ifname, sizeof(ifp->rif_name));

	gt_get_ifhwaddr(&ifp->rif_hwaddr, &ifp->rif_flags, ifp->rif_name);

	rc = sys_if_nametoindex(ifname);
	ifp->rif_index = rc;

	GT_DLIST_INSERT_HEAD(&gt_main->route_if_head, ifp, rif_list);

	ifp->rif_dev_io = dev_io;
	//	PRF_INIT(host);
	//	PRF_ENTER(host);
	rc = gt_dev_init(&ifp->rif_host_dev, dev_io, ifp->rif_name,
			 DEV_QUEUE_HOST, interface_dev_host_rx);
	//	PRF_LEAVE(host);
	if (rc < 0 && rc != -ENOTSUP) {
		goto err;
	}

	rc = gt_get_ifchannels(ifname);
	if (rc < 0) {
		goto err;
	}
	ifp->rif_rss_queue_num = rc;

	if (ifp->rif_rss_queue_num > 1) {
		gt_read_rss_key(ifp->rif_name, &ifp->rif_rss,
				route_cache_memdup);
	}
	update_rss_table();

	gt_on_dev_f handler;
	GT_VEC_FOREACH(handler, gt_on_dev_handlers) {
		(*handler)(1, ifp);
	}

	if (ifpp != NULL) {
		*ifpp = ifp;
	}
	gt_notice(0, "Interface '%s' added", ifname);
	return 0;

err:
	gt_err(-rc, "Failed to add interface '%s'", ifname);
	route_if_del(ifp);
	return rc;
}

static void
route_if_flush_addrs(struct route_if *ifp)
{
	while (ifp->rif_n_addrs) {
		route_ifaddr_del(ifp, &(ifp->rif_addrs[0]->ria_addr));
	}
}

static void
route_if_flush_routes(struct route_if *ifp)
{
	struct route_entry_long *route;

	while (!gt_dlist_is_empty(&ifp->rif_routes)) {
		route = GT_DLIST_FIRST(&ifp->rif_routes,
				       struct route_entry_long, rtl_list);
		route_del(route);
	}
}

static void
route_if_del(struct route_if *ifp)
{
	if (ifp == NULL) {
		return;
	}

	gt_dev_deinit(&ifp->rif_host_dev, 0);

	GT_DLIST_REMOVE(ifp, rif_list);
	ifp->rif_list.dls_next = NULL;

	route_if_flush_routes(ifp);
	route_if_flush_addrs(ifp);

	gt_free_internal(shm_cache(), ifp);
}

int
route_ifaddr_add(struct route_if_addr **ifap, struct route_if *ifp,
		 const struct ipaddr *addr)
{
	int i, rc, size;
	void *new_ptr;
	struct route_if_addr *ifa, *tmp;

	ifa = route_ifaddr_get(AF_INET, addr);
	if (ifa == NULL) {
		ifa = gt_malloc(shm_cache(), sizeof(*ifa), 0);
		if (ifa == NULL) {
			rc = -ENOMEM;
			goto err;
		}
		ifa->ria_addr = *addr;
		ifa->ria_ref_cnt = 0;
		i = rand32() % NEPHEMERAL_PORTS;
		ifa->ria_ephemeral_port = EPHEMERAL_PORT_MIN + i;
		GT_DLIST_INSERT_HEAD(&gt_main->route_addr_head, ifa, ria_list);
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
	new_ptr = gt_realloc(shm_cache(), ifp->rif_addrs, size, 0);
	if (new_ptr == NULL) {
		GT_DLIST_REMOVE(ifa, ria_list);
		gt_free_internal(shm_cache(), ifa);
		rc = -ENOMEM;
		goto err;
	}
	ifp->rif_addrs = new_ptr;
	ifp->rif_addrs[ifp->rif_n_addrs++] = ifa;
	route_foreach_set_srcs(ifp);
	if (ifap != NULL) {
		*ifap = ifa;
	}
	gt_info(0, "Address '%s' added", log_add_ipaddr(AF_INET, &addr->ipa_4));
	return 0;
err:
	gt_err(-rc, "Failed to add address '%s'",
	       log_add_ipaddr(AF_INET, &addr->ipa_4));
	return rc;
}

int
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
					GT_DLIST_REMOVE(ifa, ria_list);
					gt_free_internal(shm_cache(), ifa);
				}
				goto out;
			}
		}
	}
	gt_err(0, "Failed to delete address '%s' (Address not found)",
	       log_add_ipaddr(AF_INET, &addr->ipa_4));
	return -ENOENT;
out:
	gt_notice(0, "Address '%s' deleted",
		  log_add_ipaddr(AF_INET, &addr->ipa_4));
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
		new_ptr = gt_realloc(shm_cache(), route->rtl_srcs, size, 0);
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

int
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
		return -EINVAL;
	}
	if (a->rt_pfx == 0) {
		route = gt_main->route_default;
	} else {
		route = NULL;
	}
	if (route != NULL) {
		return -EEXIST;
	}
	route = gt_malloc(shm_cache(), sizeof(struct route_entry_long),
			  GT_MF_ZERO);
	if (route == NULL) {
		return -ENOMEM;
	}
	rule = (struct lptree_rule *)route;
	rule->lpr_type = LPTREE_RULE;
	if (a->rt_pfx == 0) {
		rule->lpr_key = key;
		rule->lpr_depth = a->rt_pfx;
		gt_main->route_default = route;
	} else {
		rc = lptree_add(&gt_main->route_lptree, rule, key, a->rt_pfx);
		if (rc) {
			gt_free_internal(shm_cache(), route);
			return rc;
		}
	}
	route->rtl_af = a->rt_af;
	route->rtl_ifp = a->rt_ifp;
	route->rtl_via = a->rt_via;
	route->rtl_nsrcs = 0;
	route->rtl_srcs = NULL;
	GT_DLIST_INSERT_HEAD(&route->rtl_ifp->rif_routes, route, rtl_list);
	route_set_srcs(route);
	return 0;
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
	gt_free_internal(shm_cache(), route->rtl_srcs);
	GT_DLIST_REMOVE(route, rtl_list);
	lptree_del(&gt_main->route_lptree, rule);
	gt_notice(0, "Route to '%s/%d' deteled", log_add_ipaddr(AF_INET, &dst),
		  pfx);
}

int
gt_route_del(be32_t dst, int pfx)
{
	int rc;
	struct lptree_rule *rule;
	struct route_entry_long *route;

	if (pfx > 32) {
		rc = -EINVAL;
		goto err;
	}
	if (pfx == 0) {
		route = gt_main->route_default;
	} else {
		rule = lptree_get(&gt_main->route_lptree, ntoh32(dst), pfx);
		route = (struct route_entry_long *)rule;
	}
	if (route == NULL) {
		rc = -ESRCH;
		goto err;
	}
	route_del(route);
	return 0;
err:
	gt_err(-rc, "Failed to delete route to %s/%d",
	       log_add_ipaddr(AF_INET, &dst), pfx);
	return rc;
}

Gt__EthAddress *
gt_api_eth_addr_create(struct gt_api_conn *cp, struct gt_eth_addr *a)
{
	Gt__EthAddress *res;

	res = gt_pbc_alloc(&cp->cn_pbc_allocator.protobuf_allocator,
			   sizeof(*res));
	if (res == NULL) {
		return NULL;
	}
	gt__eth_address__init(res);
	res->eth_bytes.data = gt_pbc_alloc(
		&cp->cn_pbc_allocator.protobuf_allocator, sizeof(*a));
	if (res->eth_bytes.data == NULL) {
		gt_pbc_free(&cp->cn_pbc_allocator.protobuf_allocator, res);
		return NULL;
	}
	memcpy(res->eth_bytes.data, a->eth_u8, sizeof(*a));
	res->eth_bytes.len = sizeof(*a);
	return res;
}

static int
gt_ip_link_details_set(struct gt_api_conn *cp, Gt__IpLinkDetails *rp,
		       struct route_if *ifp)
{
	// Owned by the details message: freed via free_unpacked/gt_pbc_free.
	rp->dev = gt_pbc_strdup(cp, ifp->rif_name);
	if (rp->dev == NULL) {
		return -ENOMEM;
	}

	rp->ifindex = ifp->rif_index;

	rp->hwaddr = gt_api_eth_addr_create(cp, &ifp->rif_hwaddr);
	if (rp->hwaddr == NULL) {
		return -ENOMEM;
	}

	rp->rx_pkts = counter64_get(&ifp->rif_rx_pkts);
	rp->rx_drop = counter64_get(&ifp->rif_rx_drop);
	rp->rx_bytes = counter64_get(&ifp->rif_rx_bytes);
	rp->tx_pkts = counter64_get(&ifp->rif_tx_pkts);
	rp->tx_drop = counter64_get(&ifp->rif_tx_drop);
	rp->tx_bytes = counter64_get(&ifp->rif_tx_bytes);

	return 0;
}

static int
gt_ip_link_dump_api_handler(struct gt_api_conn *cp, Gt__IpLinkDump *rq)
{
	int rc;
	struct route_if *ifp;
	Gt__IpLinkDetails *rp;

	ROUTE_IF_FOREACH(ifp) {
		rp = gt_api_alloc_details(cp, rp, ip_link);
		if (rp == NULL) {
			return -ENOMEM;
		}

		rc = gt_ip_link_details_set(cp, rp, ifp);
		if (rc) {
			gt_api_free_details(cp, rp, ip_link);
			return rc;
		}

		gt_api_send_details(cp, rp, ip_link);
	}

	return 0;
}

GT_API_SERVER_DEFINE_HANDLER(ip_link_dump, gt_ip_link_dump_api_handler);

/*static int
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
	m = mbuf_next(gt_main->route_pool, id);
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
	m = mbuf_get(gt_main->route_pool, id);
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

static int
gt_ip_address_add_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	int rc;
	const char *ifname;
	struct ipaddr *addr;
	struct gt_cli_arg *arg;
	struct route_if *ifp;

	ifname = NULL;
	addr = NULL;
	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "dev")) {
			ifname = arg->arg_value;
		} else if (!strcmp(arg->arg_name, "address")) {
			addr = arg->arg_value;
		}
	}

	assert(ifname != NULL);
	assert(addr != NULL);

	ifp = route_if_get(ifname);
	if (ifp == NULL) {
		return -ENOENT;
	}

	rc = route_ifaddr_add(NULL, ifp, addr);
	return rc;
}

static int
gt_ip_address_flush_cli_handler(void *ctx, struct gt_dlist *arg_head,
				void *udata)
{
	const char *ifname;
	struct gt_cli_arg *arg;
	struct route_if *ifp;

	ifname = NULL;
	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "dev")) {
			ifname = arg->arg_value;
		}
	}

	assert(ifname != NULL);

	ifp = route_if_get(ifname);
	if (ifp == NULL) {
		return 0;
	}

	route_if_flush_addrs(ifp);
	return 0;
}

static int
gt_ip_route_add_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	int rc;
	const char *ifname;
	struct ipaddr *via;
	struct gt_ip_prefix *prefix;
	struct gt_cli_arg *arg;
	struct route_entry rt;

	ifname = NULL;
	prefix = NULL;
	via = NULL;
	memset(&rt, 0, sizeof(rt));

	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "dev")) {
			ifname = arg->arg_value;
		} else if (!strcmp(arg->arg_name, "prefix")) {
			prefix = arg->arg_value;
		} else if (!strcmp(arg->arg_name, "via")) {
			via = arg->arg_value;
		}
	}

	assert(ifname != NULL);
	assert(prefix != NULL);

	rt.rt_ifp = route_if_get(ifname);
	if (rt.rt_ifp == NULL) {
		return -ENOENT;
	}

	rt.rt_af = AF_INET;
	rt.rt_pfx = prefix->len;
	rt.rt_dst = prefix->addr;
	if (via != NULL) {
		rt.rt_via = *via;
	}
	rt.rt_ifa = NULL;

	rc = route_add(&rt);
	return rc;
}

static int
gt_ip_route_flush_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	const char *ifname;
	struct gt_cli_arg *arg;
	struct route_if *ifp;

	ifname = NULL;
	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "dev")) {
			ifname = arg->arg_value;
		}
	}

	assert(ifname != NULL);

	ifp = route_if_get(ifname);
	if (ifp == NULL) {
		return 0;
	}

	route_if_flush_routes(ifp);
	return 0;
}

static int
gt_ip_link_add_api_handler(struct gt_api_conn *cp, Gt__IpLinkAdd *rq)
{
	int rc;
	Gt__IpLinkAddReply *rp;

	if (rq->io >= GT_DEV_IO_MAX) {
		return -EINVAL;
	}

	rc = route_if_add(rq->dev, rq->io, NULL);
	if (rc < 0 && rc != -EEXIST) {
		return rc;
	}

	rp = gt_api_alloc_reply(cp, rp, ip_link_add);
	if (rp == NULL) {
		return -ENOMEM;
	}

	return gt_api_send_reply(cp, rp, ip_link_add);
}

GT_API_SERVER_DEFINE_HANDLER(ip_link_add, gt_ip_link_add_api_handler);

static int
gt_ip_link_add_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	int rc;
	const char *ifname;
	enum gt_dev_io io;
	struct gt_cli_arg *arg;

	ifname = NULL;
	io = 0;

	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "dev")) {
			ifname = arg->arg_value;
		} else if (!strcmp(arg->arg_name, "io")) {
			rc = gt_dev_io_from_str(arg->arg_value);
			if (rc < 0) {
				return rc;
			}
			io = rc;
		}
	}

	assert(ifname != NULL);

	rc = route_if_add(ifname, io, NULL);
	if (rc == -EEXIST) {
		rc = 0;
	}

	return rc;
}

static int
gt_ip_link_show_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	char *s;
	struct route_if *ifp;

	s = NULL;

	GT_DLIST_FOREACH(ifp, &gt_main->route_if_head, rif_list) {
		gt_str_printf(s, "%s\n", ifp->rif_name);
		//	gt_dbg_hexdump_ascii(ifp->rif_rss.rss_key, ifp->rif_rss.rss_key_size);
	}

	gt_cli_output(ctx, s);

	return 0;
}

int
gt_add_on_dev_handler(gt_on_dev_f fn)
{
	int rc;

	rc = gt_vec_add(gt_on_dev_handlers, gt_get_kallocator(), fn);
	return rc;
}

int
gt_route_init(void)
{
	int rc;

	log_scope_init(&gt_main->route_logger, "route");
	gt_main->route_default = NULL;
	gt_dlist_init(&gt_main->route_if_head);
	gt_dlist_init(&gt_main->route_addr_head);
	rc = lptree_init(&gt_main->route_lptree);
	if (rc) {
		goto err;
	}

	gt_api_register_request(&gt_main_conn, ip_link_dump);

	gt_cli_register_command("ip address add", gt_ip_address_add_cli_handler,
				NULL, "<dev string> <address ip4-address>");

	gt_cli_register_command("ip address flush",
				gt_ip_address_flush_cli_handler, NULL,
				"<dev string>");

	gt_cli_register_command(
		"ip route add", gt_ip_route_add_cli_handler, NULL,
		"<dev string> <prefix ip4-prefix> [via ip4-address]");

	gt_cli_register_command("ip route flush", gt_ip_route_flush_cli_handler,
				NULL, "<dev string>");

	gt_api_register_request(&gt_main_conn, ip_link_add);
	gt_cli_register_command("ip link add", gt_ip_link_add_cli_handler, NULL,
				"<dev string> [io string]");

	gt_cli_register_command("ip link show", gt_ip_link_show_cli_handler,
				NULL, "");

	return 0;
err:
	route_mod_deinit();
	return rc;
}

void
route_mod_deinit(void)
{
	lptree_deinit(&gt_main->route_lptree);
}

struct route_if_addr *
route_ifaddr_get(int af, const struct ipaddr *addr)
{
	struct route_if_addr *ifa;

	GT_DLIST_FOREACH(ifa, &gt_main->route_addr_head, ria_list) {
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
	rule = lptree_search(&gt_main->route_lptree, key);
	route = (struct route_entry_long *)rule;
	if (route == NULL) {
		route = gt_main->route_default;
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
route_get_tx_packet(struct route_if *ifp, struct dev_pkt *pkt, int flags)
{
	int i, rc;
	struct dev *dev;

	rc = -ENODEV;
	for (i = 0; i < ifp->rif_rss_queue_num; ++i) {
		dev = &(ifp->rif_dev[current->p_sid][i]);
		if (dev_is_inited(dev)) {
			rc = dev_get_tx_packet(dev, pkt);
			if (rc == 0) {
				break;
			}
		}
	}
	if (rc == -ENODEV && (flags & TX_CAN_REDIRECT)) {
		rc = redirect_dev_get_tx_packet(ifp, pkt);
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
