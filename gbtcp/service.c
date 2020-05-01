#include "internals.h"

#define GT_SERVICE_STACK_SIZE (1024 * 1024)

#ifdef __linux__
#define GT_SERVICE_WAITPID_OPTIONS __WALL
#else /* __linux__ */
#define GT_SERVICE_WAITPID_OPTIONS 0
#endif /* __linux__ */

struct service_mod {
	struct log_scope log_scope;
};

struct gt_service_sock {
	struct dlist ss_list;
	struct gt_sockcb ss_socb;
};

int gt_service_pid;

//static struct dev gt_service_pipe;
//static int gt_service_ctl_child_close_listen_socks;
//static int gt_service_subscribed;
//static int gt_service_status = GT_SERVICE_NONE;
//static int gt_service_epoch;
static struct service_mod *curmod;

#ifdef __linux__
static int (*gt_service_clone_fn)(void *);
#else /* __linux__ */
#endif /* __linux__ */

static int gt_service_in(struct route_if *ifp, uint8_t *data, int len);

static void gt_service_if_in(struct route_if *ifp, uint8_t *data, int len);

void gt_service_rxtx(struct dev *dev, short revents);

//static int gt_service_dev_init(struct log *log, struct route_if *ifp);

//static int gt_service_route_if_set_link_status(struct log *log,
//	struct route_if *ifp, int add);

//static int gt_service_route_if_not_empty_txr(struct route_if *ifp,
//	struct dev_pkt *pkt);


//static int gt_service_sync(struct log *log);

//static void gt_service_clean(struct log *log);

static void gt_service_in_parent();

static void gt_service_in_child(struct log *log);

static int gt_service_clone_fn_locked(void *arg);

#if 0
static int
gt_service_ctl_status(struct log *log, void *udata, const char *new,
	struct strbuf *out)
{
	int rc, status;

	strbuf_addf(out, "%s", gt_service_status_str(gt_service_status));
	if (new == NULL) {
		return 0;
	} else if (!strcmp(new, "active")) {
		status = GT_SERVICE_ACTIVE;
	} else if (!strcmp(new, "shadow")) {
		status = GT_SERVICE_SHADOW;
	} else if (!strcmp(new, "none")) {
		status = GT_SERVICE_NONE;
	} else {
		return -EINVAL;
	} 
	rc = gt_service_set_status(log, status);
	return rc;
}
#endif

int
service_mod_init(struct log *log, void **pp)
{
	int rc;
	struct service_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "service");
//	sysctl_add_int(log, GT_CTL_SERVICE_CHILD_CLOSE_LISTEN_SOCKS, SYSCTL_LD,
//	               &gt_service_ctl_child_close_listen_socks, 0, 1);
//	sysctl_add(log, GT_CTL_SERVICE_STATUS, SYSCTL_WR,
//	           NULL, NULL, gt_service_ctl_status);	
	return 0;
}

int
service_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
service_mod_deinit(struct log *log, void *raw_mod)
{
	struct service_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
service_mod_detach(struct log *log)
{
	curmod = NULL;
}

const char *
gt_service_status_str(int status)
{
	switch (status) {
	case GT_SERVICE_ACTIVE: return "active";
	case GT_SERVICE_SHADOW: return "shadow";
	case GT_SERVICE_NONE: return "none";
	default:
		BUG;
		return "";
	}
}

static int
gt_service_in(struct route_if *ifp, uint8_t *data, int len)
{
	int rc;
	struct gt_sock_tuple so_tuple;
	struct gt_inet_context ctx;

	rc = gt_inet_eth_in(&ctx, ifp, data, len);
	if (rc == GT_INET_OK &&
	    (ctx.inp_ipproto == IPPROTO_UDP ||
	     ctx.inp_ipproto == IPPROTO_TCP)) {
		so_tuple.sot_laddr = ctx.inp_ip4_h->ip4h_daddr;
		so_tuple.sot_faddr = ctx.inp_ip4_h->ip4h_saddr;
		so_tuple.sot_lport = ctx.inp_udp_h->udph_dport;
		so_tuple.sot_fport = ctx.inp_udp_h->udph_sport;
		rc = gt_sock_in(ctx.inp_ipproto, &so_tuple, &ctx.inp_tcb,
		                ctx.inp_payload);
	} else if (rc == GT_INET_BCAST && 
	           ctx.inp_ipproto == IPPROTO_ICMP && ctx.inp_eno &&
	           (ctx.inp_emb_ipproto == IPPROTO_UDP ||
	            ctx.inp_emb_ipproto == IPPROTO_TCP)) {
		so_tuple.sot_laddr = ctx.inp_emb_ip4_h->ip4h_saddr;
		so_tuple.sot_faddr = ctx.inp_emb_ip4_h->ip4h_daddr;
		so_tuple.sot_lport = ctx.inp_emb_udp_h->udph_sport;
		so_tuple.sot_fport = ctx.inp_emb_udp_h->udph_dport;
		gt_sock_in_err(ctx.inp_emb_ipproto, &so_tuple, ctx.inp_eno);
	}
	return rc;
}

static void
gt_service_if_in(struct route_if *ifp, uint8_t *data, int len)
{
	int rc;
//	struct gt_service_msg msg;

	rc = gt_service_in(ifp, data, len);
	switch (rc) {
	case GT_INET_OK:
	case GT_INET_DROP:
		break;
	case GT_INET_BYPASS:
	case GT_INET_BCAST:
//		msg.svcm_cmd = rc;
//		msg.svcm_if_idx = ifp->rif_idx;
//		memcpy(data + len, &msg, sizeof(msg));
//		len += sizeof(msg);
//		dev_tx3(&gt_service_pipe, data, len);
		break;
	default:
		BUG;
		break;
	}
}

#if 0
static int
gt_service_pipe_in(uint8_t *data, int len)
{
	int cmd;
	struct gt_service_msg *msg;
	struct route_if *ifp;

	if (len < sizeof(*msg)) {
		return -EINVAL;
	}
	msg = (struct gt_service_msg *)(data + len - sizeof(*msg));
	len -= sizeof(*msg);
	ifp = gt_route_if_get_by_idx(msg->svcm_if_idx);
	if (ifp == NULL) {
		return -EINVAL;
	}
	cmd = msg->svcm_cmd;
	switch (cmd) {
	case GT_INET_BYPASS:
//		dev_tx3(&ifp->rif_dev, data, len);
		return 0;
	case GT_INET_BCAST:
		gt_service_in(ifp, data, len);
		return 0;
	default:
		return -EINVAL;
	}
}
#endif

#if 0
static void
service_pipe_rxtx(struct dev *dev, short revents)
{
	int i, n;
	void *data;
	struct netmap_slot *slot;
	struct netmap_ring *rxr;

	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			gt_service_pipe_in(data, slot->len);
			DEV_RXR_NEXT(rxr);
		}
	}
}
#endif

void
gt_service_rxtx(struct dev *dev, short revents)
{
	int i, n, len;
	void *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
	struct route_if *ifp;

	ifp = dev->dev_udata;
	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			//DEV_RX_PREFETCH(rxr);
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			gt_service_if_in(ifp, data, len);
			gt_route_if_rxr_next(ifp, rxr);
		}
	}
}

/*static int
gt_service_route_if_set_link_status(struct log *log,
	struct route_if *ifp, int add)
{
	int rc;

	rc = 0;
	if (add) {
		if (gt_service_status == GT_SERVICE_ACTIVE) {
			LOG_TRACE(log);
			rc = gt_service_dev_init(log, ifp);
		}
	} else {
		dev_deinit(&ifp->rif_dev);
	}
	return rc;
}

static int
gt_service_route_if_not_empty_txr(struct route_if *ifp, struct dev_pkt *pkt)
{
	int rc;

	rc = dev_not_empty_txr(&gt_service_pipe, pkt);
	return rc;
}

void
gt_service_route_if_tx(struct route_if *ifp, struct dev_pkt *pkt)
{
	struct gt_service_msg *msg;

	msg = (struct gt_service_msg *)(pkt->pkt_data + pkt->pkt_len);
	msg->svcm_cmd = GT_INET_OK;
	msg->svcm_if_idx = ifp->rif_idx;
	pkt->pkt_len += sizeof(*msg);
}*/

#if 0
static int
gt_service_set_status(struct log *log, int status)
{
	int rc, tmp_fd;
	struct file *fp;
//	struct route_if *ifp;

	if (gt_service_status == status) {
		return 0;
	}
	LOG_TRACE(log);
	LOGF(log, 7, LOG_INFO, 0, "hit; status=%s",
	     gt_service_status_str(status));
	if (gt_service_pid == 0) {
		return -ESRCH;
	}
	if (status != GT_SERVICE_ACTIVE && status != GT_SERVICE_SHADOW) {
		return -EINVAL;
	}
	if (status == GT_SERVICE_SHADOW) {
		FILE_FOREACH_SAFE(fp, tmp_fd) {
			if (fp->fl_type == FILE_SOCK) {	
				file_close(fp, GT_SOCK_GRACEFULL);
			}
		}
//		GT_ROUTE_IF_FOREACH(ifp) {
//			dev_deinit(&ifp->rif_dev);
//		}
		gt_service_status = GT_SERVICE_SHADOW;
		return 0;
	} else {
		rc = 0;
		gt_service_status = GT_SERVICE_ACTIVE;
		return rc;
	}
}
#endif

#if 0
static int
gt_service_sub(struct log *log)
{
	int rc;
	
	ASSERT(!gt_service_subscribed);
	LOG_TRACE(log);
	rc = sysctl_sub(log, gt_service_unsub_handler);
	if (rc == 0) {
		gt_service_subscribed = 1;
	}
	return rc;
}
#endif

/*static int
gt_service_sync(struct log *log)
{
	int i, rc;
	static const char *names[] = {
		GT_CTL_ROUTE_IF_LIST,
		GT_CTL_ROUTE_ROUTE_LIST,
		GT_CTL_ROUTE_ADDR_LIST,
		NULL,
	};

	LOG_TRACE(log);
	for (i = 0; names[i] != NULL; ++i) {
		rc = sysctl_sync(log, names[i]);
		if (rc) {
			return rc;
		}
	}
	return 0;
}*/

#if 0
static int
gt_service_add(struct log *log)
{
	int i, rc, arg, args[3];
	unsigned int rss_q_id, rss_q_cnt, port_pairity;
	char *endptr;
	struct iovec iov[3 + RSSKEYSIZ];
	char buf[128 + 3 * RSSKEYSIZ];

	LOG_TRACE(log);
	snprintf(buf, sizeof(buf), "%d", gt_service_pid);
	rc = usysctl(log, 0, GT_CTL_SERVICE_ADD, buf, sizeof(buf), buf);
	if (rc < 0) {
		return rc;
	} else if (rc > 0) {
		LOGF(log, 7, LOG_ERR, rc, "err rpl");
		return -rc;
	}
	rc = gt_strsplit(buf, ",:", iov, ARRAY_SIZE(iov));
	if (rc != ARRAY_SIZE(iov)) {
		goto err;
	}
	for (i = 0; i < 3; ++i) {
		arg = strtoul(iov[i].iov_base, &endptr, 10);
		if (*endptr != ',') {
			goto err;
		}
		args[i] = arg;
	}
	rss_q_id = args[0];
	rss_q_cnt = args[1];
	port_pairity = args[2];
	for (i = 0; i < RSSKEYSIZ; ++i) {
		arg = strtoul(iov[i + 3].iov_base, &endptr, 16);
		if (*endptr != ':' && *endptr != '\0') {
			goto err;
		}
		if (arg > 255) {
			goto err;
		}
		gt_route_rss_key[i] = arg;
	}
	
	if (rss_q_cnt == 0 || rss_q_cnt > GT_SERVICE_COUNT_MAX ||
	    rss_q_id > rss_q_cnt ||
	    port_pairity > 1) {
		LOGF(log, 7, LOG_ERR, 0,
		     "bad rpl; rss_q_id=%d, rss_q_cnt=%d, port_pairity=%d",
		     rss_q_id, rss_q_cnt, port_pairity);
		return -EINVAL;
	}
	gt_route_rss_q_id = rss_q_id;
	gt_route_rss_q_cnt = rss_q_cnt;
	gt_route_port_pairity = port_pairity;
	return 0;
err:
	LOGF(log, 7, LOG_ERR, 0, "invalid rpl; rpl=%s", buf);
	return -EINVAL;
}
#endif

int route_create_devs(struct log *log);


int
service_start(struct log *log)
{
	assert(current);
#if 1
	printf("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS %d\n", getpid());
	if (gt_route_rss_q_id != -1)
		return 0;
	assert(gt_route_rss_q_id == -1);
	gt_route_rss_q_id = 0;
	printf("OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOKKKKKKKKKKKKKKKKKKKKKKKK %d\n", gt_route_rss_q_id);
	route_create_devs(log);

//	     gt_route_rss_q_cnt, gt_route_port_pairity);
	return 0;
#else
	int rc;
	char buf[NM_IFNAMSIZ];

	if (gt_service_pid) {
		return 0;
	}
	LOG_TRACE(log);
	LOGF(log, 7, LOG_INFO, 0, "hit; epoch=%d", gt_service_epoch);
//	gt_route_if_set_link_status_fn = gt_service_route_if_set_link_status;
	//gt_route_if_not_empty_txr_fn = gt_service_route_if_not_empty_txr;
	//gt_route_if_tx_fn = gt_service_route_if_tx;
	gt_service_status = GT_SERVICE_ACTIVE;
	gt_service_pid = gt_application_pid;
	snprintf(buf, sizeof(buf), "gbtcp.%d}0", gt_service_pid);
	rc = dev_init(log, &gt_service_pipe, buf, service_pipe_rxtx);
	printf("service pipe inited %d\n", rc);
	if (rc) {
		goto err1;
	}
	rc = sysctl_bind(log, gt_service_pid);
	if (rc) {
		goto err2;
	}
	rc = gt_service_sub(log);
	if (rc) {
		goto err3;
	}
	rc = gt_service_add(log);
	if (rc) {
		goto err4;
	}
	//gt_service_sync(log);
	gt_sock_no_opened_fn = gt_service_del;
	LOGF(log, 7, LOG_INFO, 0,
	     "ok; pid=%d, rss_q_id=%d, rss_q_cnt=%d, port_pairity=%d",
	     gt_service_pid, gt_route_rss_q_id,
	     gt_route_rss_q_cnt, gt_route_port_pairity);
	return 0;
err4:
	sysctl_unsub_me();
err3:
	sysctl_unbind();
err2:
	dev_deinit(&gt_service_pipe);
err1:
	gt_service_pid = 0;
	gt_service_status = GT_SERVICE_NONE;
	//gt_route_if_set_link_status_fn = NULL;
	//gt_route_if_not_empty_txr_fn = NULL;
	//gt_route_if_tx_fn = NULL;
	return rc;
#endif
}

#if 0
static void
gt_service_clean(struct log *log)
{
	LOG_TRACE(log);
	LOGF(log, 7, LOG_INFO, 0, "hit");
	gt_service_epoch++;
	dev_deinit(&gt_service_pipe);
	sysctl_unbind();
	sysctl_unsub_me();
	gt_route_mod_clean(log);
	gt_service_pid = 0;
	gt_service_subscribed = 0;
	gt_service_status = GT_SERVICE_NONE;
	//gt_route_if_set_link_status_fn = NULL;
	//gt_route_if_not_empty_txr_fn = NULL;
	//gt_route_if_tx_fn = NULL;
}
#endif

#if 0
static int
gt_service_del_cb(struct log *log, void *udata, int eno, char *old)
{
	uintptr_t epoch;

	if (eno) {
		epoch = (uintptr_t)udata;
		if (gt_service_epoch == epoch) {
			gt_service_clean(log);
		}
	}
	return 0;
}
#endif

#if 0
static void
gt_service_del()
{
	int rc, pid;
	uintptr_t udata;
	char buf[32];
	struct log *log;

	log = log_trace0();
	LOGF(log, 7, LOG_INFO, 0, "hit");
	gt_sock_no_opened_fn = NULL;
	rc = sysctl_binded_pid(log);
	if (rc > 0) {
		pid = rc;
		snprintf(buf, sizeof(buf), "%d", pid);
		udata = gt_service_epoch;
		rc = usysctl_r(log, 0, GT_CTL_SERVICE_DEL,
		               (void *)udata, gt_service_del_cb, buf);
		if (rc < 0) {
			gt_service_clean(log);
			return;
		}
	}
	if (gt_service_subscribed == 0) {
		gt_service_clean(log);
	}
}
#endif

#if 0
static void
gt_service_unsub_handler()
{
	int tmp_fd;
	struct file *fp;
	struct log *log;

	gt_service_subscribed = 0;
	if (gt_service_status != GT_SERVICE_ACTIVE) {
		FILE_FOREACH_SAFE(fp, tmp_fd) {
			if (fp->fl_type == FILE_SOCK) {
				file_close(fp, GT_SOCK_RESET);
			}
		}
	}
	if (gt_sock_nr_opened == 0) {
		log = log_trace0();
		gt_service_clean(log);
	}
}
#endif

static void
gt_service_in_parent()
{
}

#if 0
static void
gt_service_listen(struct log *log, struct dlist *head)
{
	int rc, fd, type;
	struct sockaddr_in addr;
	struct gt_service_sock *sso;

	DLIST_FOREACH(sso, head, ss_list) {
		type = SOCK_STREAM;
		if (sso->ss_socb.socb_flags & O_NONBLOCK) {
			type |= SOCK_NONBLOCK;
		} 
		rc = api_socket(log, sso->ss_socb.socb_fd, AF_INET, type, 0);
		if (rc < 0) {
			continue;
		}
		fd = rc;
		addr.sin_family = AF_INET;
		addr.sin_port = sso->ss_socb.socb_lport;
		addr.sin_addr.s_addr = sso->ss_socb.socb_laddr;
		rc = api_bind(log, fd, (struct sockaddr *)&addr,
		                 sizeof(addr));
		if (rc) {
			api_close(fd);
			continue;
		}
		rc = api_listen(log, fd, sso->ss_socb.socb_backlog);
		if (rc) {
			api_close(fd);
			continue;
		}
	}
}
#endif

static void
gt_service_in_child(struct log *log)
{
#if 0
	int rc;
	struct dlist so_head;
	struct gt_sock *so;
	struct gt_service_sock *sso;

	LOG_TRACE(log);
	gt_service_epoch = 0;
	dlist_init(&so_head);
	if (!gt_service_ctl_child_close_listen_socks) {
		GT_SOCK_FOREACH_BINDED(so) {
			if (so->so_state != GT_TCP_S_LISTEN) {
				continue;
			}
			rc = sys_malloc(log, (void **)&sso, sizeof(*sso));
			if (rc) {
				break;
			}
			gt_sock_get_sockcb(so, &sso->ss_socb);
			DLIST_INSERT_TAIL(&so_head, sso, ss_list);
		}
	}
	/*
	 * Free and zero stack to prevent calling `waitpid`.
	 * `stop_polling` do not wait process if stack == NULL
	 */
	gt_service_clean(log);
	service_deinit(log);
	service_init();
	log = log_trace0();
	gt_service_listen(log, &so_head);
	while (!dlist_is_empty(&so_head)) {
		sso = DLIST_FIRST(&so_head, struct gt_service_sock, ss_list);
		DLIST_REMOVE(sso, ss_list);
		free(sso);
	}
#endif
	assert(0);
}

int
gt_service_fork(struct log *log)
{
	int rc, pid;
	LOG_TRACE(log);
	rc = sys_fork(log);
	if (rc >= 0) {
		pid = rc;
		if (pid == 0) {
			gt_service_in_child(log);
		} else {
			gt_service_in_parent();
		}
	}
	return rc;
}

#ifdef __linux__
static int
gt_service_clone_fn_locked(void *arg)
{
	int (*fn)(void *);
	struct log *log;

	log = log_trace0();
	gt_service_in_child(log);
	fn = gt_service_clone_fn;
	GT_GLOBAL_UNLOCK;
	return (*fn)(arg);
}

int
gt_service_clone(int (*fn)(void *), void *child_stack,
                 int flags, void *arg,
                 void *ptid, void *tls, void *ctid)
{
	int rc, clone_vm;

	clone_vm = flags & CLONE_VM;
	if (clone_vm) {
		if ((flags & CLONE_FILES) == 0 ||
		    (flags & CLONE_THREAD) == 0) {
			return -EINVAL;
		}
	} else {
		if ((flags & CLONE_FILES) != 0 ||
		    (flags & CLONE_THREAD) != 0) {
			return -EINVAL;
		}
	}
	if (clone_vm) {
		rc = (*sys_clone_fn)(fn, child_stack, flags, arg,
		                     ptid, tls, ctid);
	} else {
		gt_service_clone_fn = fn;
		rc = (*sys_clone_fn)(gt_service_clone_fn_locked,
		                     child_stack, flags,
		                     arg, ptid, tls, ctid);
		if (rc == -1) {
			rc = -errno;
		} else {
			gt_service_in_parent();
		}
	}
	return rc;
}
#endif /* __linux__ */
