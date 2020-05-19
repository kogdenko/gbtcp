// GPL2 license
#include "internals.h"


struct service_mod {
	struct log_scope log_scope;
};

static struct service_mod *curmod;
static struct spinlock service_init_lock;

#ifdef __linux__
static int (*service_clone_fn)(void *);
#else /* __linux__ */
#endif /* __linux__ */

extern struct init_hdr *ih;

struct proc *current;

int
service_mod_init(struct log *log, void **pp)
{
	int rc;
	struct service_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc == 0) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "service");
	}
	return rc;
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


void
proc_init()
{
	dlsym_all();
	rd_nanoseconds();
	srand48(time(NULL));
	log_init_early();
}

int
service_is_appropriate_rss(struct route_if *ifp, struct sock_tuple *so_tuple)
{
	int i, rss_qid;

	if (ifp->rif_rss_nq == 1) {
		return 1;
	}
	rss_qid = -1;
	for (i = 0; i < ifp->rif_rss_nq; ++i) {
		if (ih->ih_rss_table[i] == current->p_id) {
			if (rss_qid == -1) {
				rss_qid = route_if_calc_rss_qid(ifp, so_tuple);
			}
			if (i == rss_qid) {
				return 1;
			}
		}
	}
	return 0;
}


static int
wait_controller_init(struct log *log, int pipe_fd[2])
{
	int rc, msg;
	uint64_t to;

	to = 4 * NANOSECONDS_SECOND;
	rc = read_timed(log, pipe_fd[0], &msg, sizeof(msg), &to);
	if (rc == 0) {
		LOGF(log, LOG_ERR, 0, "peer closed;");
		return -EPIPE;
	} else if (rc == sizeof(msg)) {
		if (msg >= 0) {
			return msg;
		} else {
			rc = msg;
			LOGF(log, LOG_ERR, -rc, "failed;");
			return rc;
		}
	} else if (rc > 0) {
		LOGF(log, LOG_ERR, 0, "truncated reply; len=%d", rc);
		return -EINVAL;
	} else {
		return rc;
	}
}

static int
service_start_controller(struct log *log, const char *p_name)
{
	int rc, pipe_fd[2];

	LOG_TRACE(log);
	rc = sys_pipe(log, pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork(log);
	if (rc < 0) {
		return rc;
	} else if (rc == 0) {
		log = log_trace0();
		sys_close(log, pipe_fd[0]);
		rc = controller_init(1, p_name);
		send_full_buf(log, pipe_fd[1], &rc, sizeof(rc), MSG_NOSIGNAL);
		sys_close(log, pipe_fd[1]);
		if (rc == 0) {
			controller_loop();
		}
		return rc;
	}
	rc = wait_controller_init(log, pipe_fd);
	sys_close(log, pipe_fd[0]);
	sys_close(log, pipe_fd[1]);
	return rc;
}

int
service_attach(struct log *log, int fd)
{
	int i, rc, pid;
	struct proc *s;
	char buf[GT_SYSCTL_BUFSIZ];

	rc = sysctl_connect(log, fd);
	if (rc) {
		return rc;
	}
	rc = sysctl_req(log, fd, SYSCTL_CONTROLLER_SERVICE_INIT, buf, "~");
	if (rc) {
		return rc;
	}
	rc = shm_attach(log, (void **)&ih);
	if (rc) {
		return rc;
	}
	if (ih->ih_version != IH_VERSION) {
		shm_detach(log);
		return -EINVAL;
	}
	set_hz(ih->ih_hz);
	pid = getpid();
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		s = ih->ih_services + i;
		if (s->p_pid == pid) {
			spinlock_lock(&s->p_lock);
			current = s;
			dbg("current %d %d", s->p_id, s->p_dirty_rss_table);
			return 0;
		}
	}
	shm_detach(log);
	return -ENOENT;
}

int
service_init_locked(struct log *log)
{
	int rc, fd, pid;
	char p_comm[PROC_COMM_MAX];
	struct sockaddr_un a;

	// Check again under the lock
	if (current != NULL) {
		return 0;
	}
	pid = getpid();
	rc = proc_get_comm(log, p_comm, pid);
	if (rc) {
		return rc;
	}
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(log, &a, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = service_attach(log, fd);
	if (rc) {
		rc = service_start_controller(log, p_comm);
		if (rc < 0) {
			goto err;
		}
		rc = service_attach(log, fd);
		if (rc) {
			goto err;
		}
	}
	mod_foreach_mod_attach(log, ih);
	strzcpy(current->p_comm, p_comm, sizeof(current->p_comm));
	current->p_fd[P_SERVICE] = fd;
	spinlock_unlock(&current->p_lock);
	return 0;
err:
	if (fd >= 0) {
		sys_close(log, fd);
		fd = -1;
	}
	return rc;
}

int
service_init()
{
	int rc;
	struct log *log;

	spinlock_lock(&service_init_lock);
	if (current != NULL) {
		spinlock_unlock(&service_init_lock);
		return 0;
	}
	proc_init();
	log = log_trace0();
	LOGF(log, LOG_INFO, 0, "hit;");
	rc = service_init_locked(log);
	if (rc) {
		LOGF(log, LOG_ERR, -rc, "failed;");
	} else {
		LOGF(log, LOG_INFO, 0, "ok; current=%p", current);
	}
	spinlock_unlock(&service_init_lock);
	return rc;
}

static int
service_in(struct route_if *ifp, uint8_t *data, int len)
{
	int rc;
	struct sock_tuple so_tuple;
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
service_if_in(struct route_if *ifp, uint8_t *data, int len)
{
	int rc;
//	struct gt_service_msg msg;

	rc = service_in(ifp, data, len);
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

void
service_rxtx(struct dev *dev, short revents)
{
	int i, n, len;
	void *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
	struct route_if *ifp;

	ifp = dev->dev_ifp;
	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			//DEV_RX_PREFETCH(rxr);
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			service_if_in(ifp, data, len);
			route_if_rxr_next(ifp, rxr);
		}
	}
}

static void
service_update_dev(struct log *log, struct proc *s,
	struct route_if *ifp, int rss_qid)
{
	int id, ifflags;
	char dev_name[NM_IFNAMSIZ];
	struct dev *dev;

	ifflags = READ_ONCE(ifp->rif_flags);
	id = READ_ONCE(ih->ih_rss_table[rss_qid]);
	dev = &(ifp->rif_dev[s->p_id][rss_qid]);
	if ((ifflags & IFF_UP) &&
	    id == s->p_id &&
	    !dev_is_inited(dev)) {
		snprintf(dev_name, sizeof(dev_name), "%s-%d",
		         ifp->rif_name, rss_qid);
		dev_init(log, dev, dev_name, service_rxtx);
		dev->dev_ifp = ifp;
	} else {
		dev_deinit(log, dev);
	}
}

void
service_update_rss_table(struct log *log, struct proc *s)
{
	int i;
	struct route_if *ifp;

	LOG_TRACE(log);
	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < ifp->rif_rss_nq; ++i) {
			service_update_dev(log, s, ifp, i);
		}
	}
	s->p_dirty_rss_table = 0;
}

void
service_clean_rss_table(struct proc *s)
{
	int i;
	struct dev *dev;
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
			dev = &(ifp->rif_dev[s->p_id][i]);
			dev_clean(dev);
		}
	}
}

static void
service_in_parent()
{
}

static void
service_in_child(struct log *log)
{
	current = NULL;
	dbg("a");
	LOGF(log, LOG_ERR, 0, "IN CHILD");
}

int
service_fork(struct log *log)
{
	int rc;

	LOG_TRACE(log);
	rc = sys_fork(log);
	if (rc == 0) {
		dbg("inchild");
		service_in_child(log);
	} else if (rc > 0) {
		service_in_parent();
	}
	return rc;
}

#ifdef __linux__
static int
service_clone_fn_locked(void *arg)
{
	int (*fn)(void *);
	struct log *log;

	log = log_trace0();
	service_in_child(log);
	fn = service_clone_fn;
	assert(0);
//	GT_GLOBAL_UNLOCK; ???
	return (*fn)(arg);
}

int
service_clone(int (*fn)(void *), void *child_stack,
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
		service_clone_fn = fn;
		rc = (*sys_clone_fn)(service_clone_fn_locked,
		                     child_stack, flags,
		                     arg, ptid, tls, ctid);
		if (rc == -1) {
			rc = -errno;
		} else {
			service_in_parent();
		}
	}
	return rc;
}
#endif // __linux__
