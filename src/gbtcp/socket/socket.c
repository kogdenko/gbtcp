// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/api.h>
#include <gbtcp/socket/bsd44/tcp_var.h>
#include <gbtcp/socket/bsd44/uipc_socket.h>
#include <gbtcp/kernel/cli.h>
#include <gbtcp/socket/gbtcp/socket.h>
#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/node.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/socket/sockbuf.h>
#include <gbtcp/socket/socket.h>
#include <gbtcp/socket/socket.pb-c.h>
#include <gbtcp/kernel/worker.h>

struct gt_so_main *gt_so_main;

static const struct gt_so_ops gt_gbtcp_so_ops = {
	.so_struct_size = gt_gbtcp_so_struct_size,
	.so_get_err = gt_gbtcp_so_get_err,
	.so_get_events = gt_gbtcp_so_get_events,
	.so_nread = gt_gbtcp_so_nread,
	.so_tx_flush = gt_gbtcp_so_tx_flush,
	.so_socket = gt_gbtcp_so_socket,
	.so_connect = gt_gbtcp_so_connect,
	.so_listen = gt_gbtcp_so_listen,
	.so_accept = gt_gbtcp_so_accept,
	.so_close = gt_gbtcp_so_close,
	.so_recvfrom = gt_gbtcp_so_recvfrom,
	.so_aio_recvfrom = gt_gbtcp_so_aio_recvfrom,
	.so_recvdrain = gt_gbtcp_so_recvdrain,
	.so_sendto = gt_gbtcp_so_sendto,
	.so_ioctl = gt_gbtcp_so_ioctl,
	.so_getsockopt = gt_gbtcp_so_getsockopt,
	.so_setsockopt = gt_gbtcp_so_setsockopt,
	.so_getpeername = gt_gbtcp_so_getpeername,
	.so_rx = gt_gbtcp_so_rx,
};

#if GT_HAVE_BSD44
static const struct gt_so_ops gt_bsd44_so_ops = {
	.so_struct_size = gt_bsd44_so_struct_size,
	.so_get_err = gt_bsd44_so_get_err,
	.so_get_events = gt_bsd44_so_get_events,
	.so_nread = gt_bsd44_so_nread,
	.so_tx_flush = gt_bsd44_so_tx_flush,
	.so_socket = gt_bsd44_so_socket,
	.so_connect = gt_bsd44_so_connect,
	.so_listen = gt_bsd44_so_listen,
	.so_accept = gt_bsd44_so_accept,
	.so_close = gt_bsd44_so_close,
	.so_recvfrom = gt_bsd44_so_recvfrom,
	.so_aio_recvfrom = gt_bsd44_so_aio_recvfrom,
	.so_recvdrain = gt_bsd44_so_recvdrain,
	.so_sendto = gt_bsd44_so_sendto,
	.so_ioctl = gt_bsd44_so_ioctl,
	.so_getsockopt = gt_bsd44_so_getsockopt,
	.so_setsockopt = gt_bsd44_so_setsockopt,
	.so_getpeername = gt_bsd44_so_getpeername,
	.so_rx = gt_bsd44_so_rx,
};
#endif // GT_HAVE_BSD44

static struct gt_sock *
gt_fptoso(struct gt_file *fp)
{
	return container_of(fp, struct gt_sock, sobase_file);
}

Gt__Ip4Address *
gt_api_ip4_address_create(struct gt_api_conn *cp, be32_t a)
{
	Gt__Ip4Address *res;

	res = gt_pbc_alloc(&cp->cn_pbc_allocator.protobuf_allocator,
			   sizeof(*res));
	if (res == NULL) {
		return NULL;
	}
	gt__ip4_address__init(res);
	res->ip4_u32 = a;
	return res;
}

struct gt_socket_details_udata {
	struct gt_api_conn *cp;
	Gt__SocketDetails *rp;
};

static int
gt_socket_details_handler(struct htable *t, struct gt_dlist *slot, void *udata)
{
	int proto;
	socklen_t optlen;
	struct sockaddr_in sockname, peername;
	struct tcp_info tcpi;
	struct gt_file *fp;
	struct gt_sock *so;
	struct service *s;
	Gt__SocketDetails *rp;
	struct gt_socket_details_udata *u;

	u = udata;

	if (t == &gt_so_main->tbl_binded) {
		so = container_of(slot, struct gt_sock, sobase_bind_list);
	} else {
		so = container_of(slot, struct gt_sock, sobase_connect_list);
	}

	rp = gt_api_alloc_details(u->cp, rp, socket);
	if (rp == NULL) {
		return -ENOMEM;
	}

	fp = &so->sobase_file;
	s = service_get_by_sid(fp->fl_worker_index);

	optlen = sizeof(proto);
	gt_so_getsockopt(fp, SOL_SOCKET, SO_PROTOCOL, &proto, &optlen);

	optlen = sizeof(tcpi);
	gt_so_getsockopt(fp, IPPROTO_TCP, TCP_INFO, &tcpi, &optlen);

	optlen = sizeof(sockname);
	gt_so_getsockname(fp, (struct sockaddr *)&sockname, &optlen);

	optlen = sizeof(peername);
	gt_so_getpeername(fp, (struct sockaddr *)&peername, &optlen);

	rp->fd = file_get_fd(fp);
	rp->pid = s->p_pid;
	rp->proto = proto;
	rp->tcp_state = tcpi.tcpi_state;
	rp->src_addr =
		gt_api_ip4_address_create(u->cp, sockname.sin_addr.s_addr);
	rp->dst_addr =
		gt_api_ip4_address_create(u->cp, peername.sin_addr.s_addr);
	rp->src_port = ntoh16(sockname.sin_port);
	rp->dst_port = ntoh16(peername.sin_port);

	u->rp = rp;
	return 0;
}

struct gt_socket_dump_data {
	struct htable *hash;
	struct gt_htable_iterator iterator;
};

static int
gt_socket_details_send(struct gt_api_conn *cp)
{
	int rc;
	struct gt_socket_dump_data *e;
	struct gt_socket_details_udata u;

	e = gt_api_conn_get_udata(cp);
	u.cp = cp;

	while (1) {
		rc = gt_htable_iterate(e->hash, &e->iterator,
				       gt_socket_details_handler, &u);
		if (rc) {
			return rc == -EAGAIN ? 0 : rc;
		}

		rc = gt_api_send_details(cp, u.rp, socket);
		if (rc) {
			return rc;
		}
	}
}

static int
gt_socket_dump_api_handler(struct gt_api_conn *cp, Gt__SocketDump *rq)
{
	struct gt_socket_dump_data *data;

	// Freed by gt_api_free_udata().
	data = gt_malloc_align(shm_cache(), sizeof(*data), GT_L1_CACHE_BYTES,
			       0);
	if (data == NULL) {
		return -ENOMEM;
	}

	memset(&data->iterator, 0, sizeof(data->iterator));
	data->hash = rq->listening ? &gt_so_main->tbl_binded :
				     &gt_so_main->tbl_connected;

	gt_api_conn_set_udata(cp, data);

	return gt_socket_details_send(cp);
}

GT_API_SERVER_DEFINE_HANDLER(socket_dump, gt_socket_dump_api_handler)

static uint32_t
gt_so_hash(void *e)
{
	struct gt_sock *so;
	u32 hash;

	so = (struct gt_sock *)e;
	hash = GT_SO_HASH(so->sobase_faddr, so->sobase_lport, so->sobase_fport);
	return hash;
}

/*static const char *
gt_socket_impl_str(int impl)
{
	switch (impl) {
	case GT_IMPL_GBTCP:
		return "gbtcp";
#if GT_HAVE_BSD44
	case GT_IMPL_BSD44:
		return "bsd44";
#endif // HABE_BSD44
	default:
		return "";
	}
}*/

static const struct gt_so_ops *
gt_socket_impl_from_str(const char *s)
{
	if (!strcmp(s, "gbtcp")) {
		return &gt_gbtcp_so_ops;
#if GT_HAVE_BSD44
	} else if (!strcmp(s, "bsd44")) {
		return &gt_bsd44_so_ops;
#endif // GT_HAVE_BSD44
	} else {
		return NULL;
	}
}

static const struct gt_so_ops *
gt_so_impl(void)
{
	return gt_so_main->so_workers[gt_get_worker_index()].impl;
}

static int
gt_socket_set_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	struct gt_cli_arg *arg;

	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "impl")) {
			if (gt_socket_impl_from_str(arg->arg_value) == NULL) {
				return -EINVAL;
			}
			strncpy(gt_so_main->so_impl_name, arg->arg_value,
				sizeof(gt_so_main->so_impl_name) - 1);
			return 0;
		}
	}

	GT_BUG("Missing required argument");
	return 0;
}

int
gt_socket_module_init(u8 module_id, void **puser)
{
	int i, rc;
	struct gt_so_main *mod;

	mod = gt_malloc(shm_cache(), sizeof(*mod), 0);
	if (mod == NULL) {
		return -ENOMEM;
	}
	memset(mod, 0, sizeof(*mod));

	gt_so_main = mod;
	gt_so_main->so_module_id = module_id;

	log_scope_init(&mod->so_logger, "socket");

	for (i = 0; i < GT_ARRAY_SIZE(mod->so_workers); ++i) {
		gt_dlist_init(&mod->so_workers[i].sow_tx_pending_head);
	}

	rc = htable_init(&mod->tbl_connected, shm_cache(), 65536, gt_so_hash,
			 HTABLE_POWOF2);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}
	rc = htable_init(&mod->tbl_binded, shm_cache(), EPHEMERAL_PORT_MAX,
			 NULL, 0);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	gt_api_register_dump(&gt_main_conn, socket_dump, gt_socket_details_send,
			     gt_api_free_udata);

	mod->tcp_fin_timeout = GT_SEC_PER_MIN * GT_NSEC_PER_SEC;
	mod->tcp_time_wait_timeout = 0;
	strncpy(mod->so_impl_name, "gbtcp", sizeof(mod->so_impl_name) - 1);

	gt_cli_register_command("socket set", gt_socket_set_cli_handler, NULL,
				"<impl string>");

	rc = GT_WORKER_FUNC_REGISTER(module_id, rx, gt_socket_module_rx,
				&mod->so_rx_fn);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer,
				gt_gbtcp_tcp_timer_delack,
				&mod->so_timer_delack_fn);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer,
				gt_gbtcp_tcp_timer_rexmit,
				&mod->so_timer_rexmit_fn);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer,
				gt_gbtcp_tcp_timer_persist,
				&mod->so_timer_persist_fn);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer, gt_gbtcp_tcp_timer_fin,
				&mod->so_timer_fin_fn);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer,
				gt_gbtcp_tcp_timer_time_wait,
				&mod->so_timer_time_wait_fn);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

#if GT_HAVE_BSD44
	rc = GT_WORKER_FUNC_REGISTER(module_id, timer, tcp_REXMT_timo,
				&mod->so_bsd44_timer_fn[TCPT_REXMT]);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer, tcp_PERSIST_timo,
				&mod->so_bsd44_timer_fn[TCPT_PERSIST]);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer, tcp_KEEP_timo,
				&mod->so_bsd44_timer_fn[TCPT_KEEP]);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer, tcp_2MSL_timo,
				&mod->so_bsd44_timer_fn[TCPT_2MSL]);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer, tcp_DELACK_timo,
				&mod->so_bsd44_timer_fn[TCPT_DELACK]);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}
#endif // GT_HAVE_BSD44

	rc = GT_WORKER_FUNC_REGISTER(module_id, tx, gt_socket_module_tx,
				&mod->so_tx_fn);
	if (rc) {
		gt_socket_module_deinit(mod);
		return rc;
	}

	*puser = mod;
	return 0;
}

int
gt_socket_module_postinit(void *mod)
{
	int rc;

	rc = gt_add_rx_callback(&gt_so_main->so_rx_fn);
	if (rc) {
		return rc;
	}
	return gt_add_tx_callback(&gt_so_main->so_tx_fn);
}

void
gt_socket_module_deinit(void *user)
{
	struct gt_so_main *so_main;

	so_main = user;
	htable_deinit(&so_main->tbl_connected);
	htable_deinit(&so_main->tbl_binded);
	gt_free_internal(shm_cache(), so_main);
}

int
gt_socket_module_worker_init(struct service *s, int pid, int tid,
			     struct gt_api_conn *cp)
{
	/*	int rc;
	struct gt_socket_worker *wrk;

	wrk = gt_so_main->so_workers + s->p_sid;
	wrk->impl = gt_socket_impl_from_str(gt_so_main->so_impl_name);

	rc = init_files(s);
	if (rc) {
		return rc;
	}*/

	return 0;
}

void
gt_socket_module_worker_deinit(u8 worker_index)
{
	struct service *s;
	struct gt_socket_worker *dst_wrk, *wrk;

	wrk = gt_so_main->so_workers + worker_index;

	s = service_get_by_sid(worker_index);
	deinit_files(s);

	// Pending TX migrates to the controller's worker, not `current`'s: on
	// the remote-del path they are the same (the controller thread
	// deletes), but a local sibling deletes itself in service_detach()
	// with current already NULL.
	if (gt_controller_service->p_sid == worker_index) {
		return;
	}

	dst_wrk = gt_so_main->so_workers + gt_controller_service->p_sid;

	gt_dlist_splice_tail_init(&dst_wrk->sow_tx_pending_head,
				  &wrk->sow_tx_pending_head);
}

static void
gt_set_sockaddr_safe(void *addr, be32_t s_addr, be16_t port)
{
	struct sockaddr_in *in;

	in = (struct sockaddr_in *)addr;
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = s_addr;
	in->sin_port = port;
}

int
gt_set_sockaddr(struct sockaddr *addr, socklen_t *addrlen, be32_t s_addr,
		be16_t port)
{
	struct sockaddr_in in;

	if (addrlen != NULL) {
		if (*addrlen >= sizeof(in)) {
			gt_set_sockaddr_safe(addr, s_addr, port);
		} else {
			gt_set_sockaddr_safe(&in, s_addr, port);
			memcpy(addr, &in, *addrlen);
		}
		*addrlen = sizeof(in);
	}
	return 0;
}

int
gt_so_route(be32_t laddr, be32_t faddr, struct route_entry *r)
{
	int rc;

	r->rt_dst.ipa_4 = faddr;
	rc = route_get4(laddr, r);
	if (rc) {
		ipstat.ips_noroute++;
	}
	return rc;
}

int
gt_foreach_binded_socket(gt_foreach_socket_f fn, void *udata)
{
	int rc, lport;
	struct htable_bucket *b;
	struct gt_file *fp;
	struct gt_sock *so;

	for (lport = 0; lport < EPHEMERAL_PORT_MAX; ++lport) {
		b = htable_bucket_get(&gt_so_main->tbl_binded, lport);
		GT_DLIST_FOREACH_RCU(so, &b->htb_head, sobase_bind_list) {
			fp = (struct gt_file *)so;
			rc = (*fn)(fp, udata);
			if (rc != 0) {
				return rc;
			}
		}
	}
	return 0;
}

void
gt_so_rmfrom_binded(struct gt_sock *so)
{
	uint16_t lport;
	struct htable_bucket *b;

	if (so->sobase_bind_list.dls_next != NULL) {
		lport = ntoh16(so->sobase_lport);
		assert(lport < gt_so_main->tbl_binded.ht_size);
		b = htable_bucket_get(&gt_so_main->tbl_binded, lport);

		HTABLE_BUCKET_LOCK(b);
		gt_dlist_remove_rcu(&so->sobase_bind_list);
		HTABLE_BUCKET_UNLOCK(b);

		so->sobase_bind_list.dls_next = NULL;
	}
}

struct gt_sock *
gt_so_lookup_binded(struct htable_bucket *b, int proto, be32_t laddr,
		    be32_t faddr, be16_t lport, be16_t fport)
{
	int active, res_active;
	struct gt_sock *so, *res;

	res = NULL;
	res_active = 0;
	GT_DLIST_FOREACH_RCU(so, &b->htb_head, sobase_bind_list) {
		if (so->sobase_proto == proto &&
		    (so->sobase_laddr == 0 || so->sobase_laddr == laddr)) {
			active = !gt_dlist_is_empty(
				&so->sobase_file.fl_aio_head);
			if (res == NULL || (active && !res_active) ||
			    (!(!active && res_active) &&
			     (so->sobase_file.fl_worker_index ==
			      current->p_sid))) {
				res = so;
				res_active = active;
			}
		}
	}
	return res;
}

void
gt_so_addto_connected(struct gt_sock *so, uint32_t *ph)
{
	uint32_t h;
	struct htable_bucket *b;

	h = GT_SO_HASH(so->sobase_faddr, so->sobase_lport, so->sobase_fport);
	b = htable_bucket_get(&gt_so_main->tbl_connected, h);

	HTABLE_BUCKET_LOCK(b);
	gt_dlist_insert_tail_rcu(&b->htb_head, &so->sobase_connect_list);
	HTABLE_BUCKET_UNLOCK(b);

	*ph = h;
}

void
gt_so_rmfrom_connected(struct gt_sock *so)
{
	uint32_t h;
	struct htable_bucket *b;

	if (so->sobase_connect_list.dls_next != NULL) {
		h = GT_SO_HASH(so->sobase_faddr, so->sobase_lport,
			       so->sobase_fport);
		b = htable_bucket_get(&gt_so_main->tbl_connected, h);

		HTABLE_BUCKET_LOCK(b);
		gt_dlist_remove_rcu(&so->sobase_connect_list);
		HTABLE_BUCKET_UNLOCK(b);

		so->sobase_connect_list.dls_next = NULL;
	}
}

struct gt_sock *
gt_so_lookup_connected(struct htable_bucket *b, int proto, be32_t laddr,
		       be32_t faddr, be16_t lport, be16_t fport)
{
	struct gt_sock *so;

	GT_DLIST_FOREACH_RCU(so, &b->htb_head, sobase_connect_list) {
		if (so->sobase_proto == proto && so->sobase_laddr == laddr &&
		    so->sobase_faddr == faddr && so->sobase_lport == lport &&
		    so->sobase_fport == fport) {
			return so;
		}
	}
	return NULL;
}

int
gt_so_lookup(struct gt_sock **sop, int proto, be32_t laddr, be32_t faddr,
	     be16_t lport, be16_t fport)
{
	int sid, i;
	uint32_t h;
	struct htable_bucket *b;
	struct gt_sock *so;

	h = GT_SO_HASH(faddr, lport, fport);
	b = htable_bucket_get(&gt_so_main->tbl_connected, h);
	HTABLE_BUCKET_LOCK(b);
	so = gt_so_lookup_connected(b, proto, laddr, faddr, lport, fport);
	if (so == NULL) {
		HTABLE_BUCKET_UNLOCK(b);
		b = NULL;
		i = hton16(lport);
		if (i >= gt_so_main->tbl_binded.ht_size) {
			return IN_BYPASS;
		}
		b = htable_bucket_get(&gt_so_main->tbl_binded, i);
		so = gt_so_lookup_binded(b, proto, laddr, faddr, lport, fport);
		if (so == NULL) {
			return IN_BYPASS;
		}
	}
	sid = so->sobase_file.fl_worker_index;
	if (b != NULL) {
		HTABLE_BUCKET_UNLOCK(b);
	}
	if (sid != current->p_sid) {
		return sid;
	}
	*sop = so;
	return IN_OK;
}

void
gt_so_base_init(struct gt_sock *so)
{
	so->sobase_bind_list.dls_next = NULL;
	so->sobase_connect_list.dls_next = NULL;
}

int
gt_so_struct_size(void)
{
	int size, tmp;

	size = tmp = gt_gbtcp_so_ops.so_struct_size();
#if GT_HAVE_BSD44
	tmp = gt_bsd44_so_ops.so_struct_size();
	if (size < tmp) {
		size = tmp;
	}
#endif

	return size;
}

int
gt_so_get(int fd, struct gt_file **fpp)
{
	int rc;
	struct gt_file *fp;

	rc = file_get(fd, &fp);
	if (rc) {
		return rc;
	} else if (fp->fl_type != FILE_SOCK) {
		return -ENOTSOCK;
	} else {
		*fpp = fp;
		return 0;
	}
}

int
gt_so_get_err(struct gt_file *fp)
{
	int rc;

	rc = gt_so_impl()->so_get_err(fp);

	return rc;
}

short
gt_so_get_events(struct gt_file *fp)
{
	short events;

	events = gt_so_impl()->so_get_events(fp);

	return events;
}

int
gt_so_nread(struct gt_file *fp)
{
	int rc;

	rc = gt_so_impl()->so_nread(fp);

	return rc;
}

void
gt_so_tx_flush(void)
{
	int rc;

	rc = gt_so_impl()->so_tx_flush();

	GT_UNUSED(rc);
}

int
gt_so_socket6(struct gt_file **fpp, int fd, int domain, int type, int flags,
	      int ipproto)
{
	int rc, proto;

	if (domain != AF_INET) {
		return -ENOTSUP;
	}

	switch (type) {
	case SOCK_STREAM:
		if (ipproto != 0 && ipproto != IPPROTO_TCP) {
			return -EINVAL;
		}
		proto = IPPROTO_TCP;
		break;

	case SOCK_DGRAM:
		if (ipproto != 0 && ipproto != IPPROTO_UDP) {
			return -EINVAL;
		}
		proto = IPPROTO_UDP;
		return -ENOTSUP;

	default:
		return -ENOTSUP;
	}

	rc = gt_so_impl()->so_socket(fpp, fd, domain, type, proto);

	if (rc < 0) {
		return rc;
	}

	if (flags & SOCK_NONBLOCK) {
		(*fpp)->fl_blocked = 0;
	}

	file_open(*fpp);
	rc = file_get_fd(*fpp);

	return rc;
}

int
gt_so_connect(struct gt_file *fp, const struct sockaddr_in *faddr_in,
	      struct sockaddr_in *laddr_in)
{
	int rc;
	struct gt_sock *so;

	rc = gt_so_impl()->so_connect(fp, faddr_in);

	if (rc == 0) {
		so = gt_fptoso(fp);

		laddr_in->sin_family = AF_INET;
		laddr_in->sin_port = so->sobase_lport;
		laddr_in->sin_addr.s_addr = so->sobase_laddr;
	}

	return rc;
}

int
gt_so_bind(struct gt_file *fp, const struct sockaddr_in *addr)
{
	be16_t lport;
	socklen_t optlen;
	struct gt_sock *so;
	struct htable_bucket *b;
	struct tcp_info tcpi;

	so = gt_fptoso(fp);

	optlen = sizeof(struct tcp_info);
	gt_so_getsockopt(fp, IPPROTO_TCP, TCP_INFO, &tcpi, &optlen);
	if (tcpi.tcpi_state != GT_TCPS_CLOSED) {
		return -EINVAL;
	}

	lport = hton16(addr->sin_port);
	if (lport == 0) {
		return -EINVAL;
	}

	if (so->sobase_laddr != 0 || so->sobase_lport != 0) {
		return -EINVAL;
	}

	if (lport >= gt_so_main->tbl_binded.ht_size) {
		return -EADDRNOTAVAIL;
	}

	so->sobase_laddr = addr->sin_addr.s_addr;
	so->sobase_lport = addr->sin_port;

	b = htable_bucket_get(&gt_so_main->tbl_binded, lport);
	HTABLE_BUCKET_LOCK(b);
	GT_DLIST_INSERT_TAIL(&b->htb_head, so, sobase_bind_list);
	HTABLE_BUCKET_UNLOCK(b);

	return 0;
}

int
gt_so_bind_ephemeral(struct gt_sock *so, be32_t faddr, be16_t fport)
{
	int i, n, rc, eport;
	uint32_t h;
	be16_t lport;
	be32_t laddr;
	struct gt_sock *tmp;
	struct route_entry r;
	struct htable_bucket *b;

	if (so->sobase_lport) {
		// NOTE: We do not support connect() for already binded socket
		return -ENOTSUP;
	}
	if (so->sobase_fport) {
		return -EALREADY;
	}

	rc = gt_so_route(0, faddr, &r);
	if (rc) {
		return rc;
	}
	laddr = r.rt_ifa->ria_addr.ipa_4;

	n = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1;
	for (i = 0; i < n; ++i) {
		eport = r.rt_ifa->ria_ephemeral_port;
		if (eport == EPHEMERAL_PORT_MAX) {
			r.rt_ifa->ria_ephemeral_port = EPHEMERAL_PORT_MIN;
		} else {
			r.rt_ifa->ria_ephemeral_port++;
		}
		lport = hton16(eport);
		rc = gt_worker_rss_is_symmetric(r.rt_ifp, laddr, faddr, lport,
						fport);
		if (!rc) {
			continue;
		}
		h = GT_SO_HASH(faddr, lport, fport);
		b = htable_bucket_get(&gt_so_main->tbl_connected, h);
		HTABLE_BUCKET_LOCK(b);
		tmp = gt_so_lookup_connected(b, so->sobase_proto, laddr, faddr,
					     lport, fport);
		if (tmp == NULL) {
			so->sobase_laddr = laddr;
			so->sobase_faddr = faddr;
			so->sobase_lport = lport;
			so->sobase_fport = fport;
			gt_dlist_insert_tail_rcu(&b->htb_head,
						 &so->sobase_connect_list);
			HTABLE_BUCKET_UNLOCK(b);
			return 0;
		}
		HTABLE_BUCKET_UNLOCK(b);
	}

	return -EADDRINUSE;
}

int
gt_so_listen(struct gt_file *fp, int backlog)
{
	int rc;

	rc = gt_so_impl()->so_listen(fp, backlog);

	return rc;
}

int
gt_so_accept(struct gt_file **fpp, struct gt_file *lfp, struct sockaddr *addr,
	     socklen_t *addrlen, int flags)
{
	int rc;
	struct gt_sock *so;

	rc = gt_so_impl()->so_accept(fpp, lfp);

	if (rc == 0) {
		so = gt_fptoso(*fpp);

		gt_set_sockaddr(addr, addrlen, so->sobase_faddr,
				so->sobase_fport);

		file_open(*fpp);

		if (flags & SOCK_NONBLOCK) {
			(*fpp)->fl_blocked = 0;
		}

		rc = file_get_fd(*fpp);
	}

	return rc;
}

void
gt_so_close(struct gt_file *fp)
{
	int rc;

	rc = gt_so_impl()->so_close(fp);

	GT_UNUSED(rc);
}

int
gt_so_recvfrom(struct gt_file *fp, const struct iovec *iov, int iovcnt,
	       int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc = gt_so_impl()->so_recvfrom(fp, iov, iovcnt, flags, addr, addrlen);

	return rc;
}

int
gt_so_aio_recvfrom(struct gt_file *fp, struct iovec *iov, int flags,
		   struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc = gt_so_impl()->so_aio_recvfrom(fp, iov, flags, addr, addrlen);

	return rc;
}

int
gt_so_recvdrain(struct gt_file *fp, int len)
{
	int rc;

	rc = gt_so_impl()->so_recvdrain(fp, len);

	return rc;
}

int
gt_so_sendto(struct gt_file *fp, const struct iovec *iov, int iovcnt, int flags,
	     const struct sockaddr_in *dest_addr)
{
	int rc;

	rc = gt_so_impl()->so_sendto(fp, iov, iovcnt, flags, dest_addr);

	if (rc == -EPIPE && (flags & MSG_NOSIGNAL) == 0) {
		raise(SIGPIPE);
	}

	return rc;
}

int
gt_so_ioctl(struct gt_file *fp, unsigned long request, uintptr_t arg)
{
	int rc;

	rc = gt_so_impl()->so_ioctl(fp, request, arg);

	return rc;
}

int
gt_so_getsockopt(struct gt_file *fp, int level, int optname, void *optval,
		 socklen_t *optlen)
{
	int rc;

	rc = gt_so_impl()->so_getsockopt(fp, level, optname, optval, optlen);

	return rc;
}

int
gt_so_setsockopt(struct gt_file *fp, int level, int optname, const void *optval,
		 socklen_t optlen)
{
	int rc;

	rc = gt_so_impl()->so_setsockopt(fp, level, optname, optval, optlen);

	return rc;
}

int
gt_so_getsockname(struct gt_file *fp, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;
	struct gt_sock *so;

	so = gt_fptoso(fp);

	rc = gt_set_sockaddr(addr, addrlen, so->sobase_laddr, so->sobase_lport);

	return rc;
}

int
gt_so_getpeername(struct gt_file *fp, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc = gt_so_impl()->so_getpeername(fp, addr, addrlen);

	return rc;
}

int
gt_socket_module_rx(struct route_if *ifp, void *data, int len)
{
	return gt_so_impl()->so_rx(ifp, data, len);
}

void
gt_socket_module_worker_start(void *m)
{
	int rc;
	struct gt_socket_worker *wrk;

	gt_so_main = m;
	wrk = gt_so_main->so_workers + gt_get_worker_index();

	rc = init_files(wrk);
	if (rc) {
		gt_dbg("FAILED!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		//		return rc;
	}

	wrk->impl = gt_socket_impl_from_str(gt_so_main->so_impl_name);
}

void
gt_socket_module_worker_stop(void)
{
	// gt_so_main is the shared socket-module object used by every
	// service-thread in this process; clearing it on a per-thread detach
	// would break siblings. It is set idempotently in worker_attach.
}

void
gt_socket_module_tx(void)
{
	gt_so_tx_flush();
}
