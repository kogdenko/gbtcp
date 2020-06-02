// gpl2 license
#include "internals.h"

struct service_mod {
	struct log_scope log_scope;
};

#define SERVICE_RX 0
#define SERVICE_TX 1
#define SERVICE_BYPASS 2

struct service_msg {
	uint16_t msg_type;
	uint16_t msg_ifindex;
};

static struct service_mod *curmod;
static struct spinlock service_attach_lock;
static int service_sysctl_fd = -1;
static int service_pid_fd = -1;
static struct dev service_vale;

struct service *current;

int
service_mod_init(void **pp)
{
	int rc;

	rc = shm_malloc(pp, sizeof(*curmod));
	if (rc == 0) {
		curmod = *pp;
		log_scope_init(&curmod->log_scope, "service");
	}
	return rc;
}

int
service_mod_attach(void *p)
{
	curmod = p;
	return 0;
}

void
service_mod_deinit()
{
	if (curmod != NULL) {
		log_scope_deinit(&curmod->log_scope);
		shm_free(curmod);
		curmod = NULL;
	}
}

void
service_mod_detach()
{
	curmod = NULL;
}

void
gt_init()
{
	dlsym_all();
	rd_nanoseconds();
	srand48(time(NULL));
	log_init_early();
}

int
service_can_connect(struct route_if *ifp, be32_t laddr, be32_t faddr,
	be16_t lport, be16_t fport)
{
	int i, rss_qid;
	uint32_t h;

	if (ifp->rif_rss_nq == 1) {
		return 1;
	}
	rss_qid = -1;
	for (i = 0; i < ifp->rif_rss_nq; ++i) {
		if (ih->ih_rss_table[i] == current->p_id) {
			if (rss_qid == -1) {
				h = rss_hash4(laddr, faddr, lport, fport,
				              ifp->rif_rss_key);
				rss_qid = h % ifp->rif_rss_nq;
			}
			if (i == rss_qid) {
				return 1;
			}
		}
	}
	return 0;
}

static int
service_read_pipe(int fd)
{
	int rc, msg;
	uint64_t to;

	to = 4 * NANOSECONDS_SECOND;
	rc = read_timed(fd, &msg, sizeof(msg), &to);
	if (rc == 0) {
		ERR(0, "peer closed;");
		return -EPIPE;
	} else if (rc == sizeof(msg)) {
		if (msg >= 0) {
			return msg;
		} else {
			rc = msg;
			ERR(-rc, "failed;");
			return rc;
		}
	} else if (rc > 0) {
		ERR(0, "truncated reply; len=%d", rc);
		return -EINVAL;
	} else {
		return rc;
	}
}

static int
service_start_controller(const char *p_comm)
{
	int rc, pipe_fd[2];

	rc = sys_pipe(pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork();
	if (rc == 0) {
		sys_close(pipe_fd[0]);
		sys_close(service_sysctl_fd);
		rc = controller_init(1, p_comm);
		write_full_buf(pipe_fd[1], &rc, sizeof(rc));
		sys_close(pipe_fd[1]);
		if (rc == 0) {
			controller_loop();
		}
		exit(EXIT_SUCCESS);
	} else if (rc > 0) {
		sys_close(pipe_fd[1]);
		rc = service_read_pipe(pipe_fd[0]);
		sys_close(pipe_fd[0]);
	}
	return rc;
}

static int
service_in(struct in_context *p)
{
	int rc, ipproto;

	rc = eth_in(p);
	ASSERT(rc < 0);
	if (rc != IN_OK) {
		return rc;
	}
	ipproto = p->in_ipproto;
	if (ipproto == IPPROTO_UDP || ipproto == IPPROTO_TCP) {
		rc = so_in(ipproto, p,
		           p->in_ih->ih_daddr, p->in_ih->ih_saddr,
		           p->in_uh->uh_dport, p->in_uh->uh_sport);
	} else if (ipproto == IPPROTO_ICMP && p->in_errnum &&
	           (p->in_emb_ipproto == IPPROTO_UDP ||
	            p->in_emb_ipproto == IPPROTO_TCP)) {
		rc = so_in_err(p->in_emb_ipproto, p,
		               p->in_ih->ih_daddr, p->in_ih->ih_saddr,
		               p->in_uh->uh_dport, p->in_uh->uh_sport);
	}
	return rc;
}

static void
service_rssq_rxtx_one(struct route_if *ifp, void *data, int len)
{
	int rc;
	struct eth_hdr *eh;
	struct dev_pkt pkt;
	struct in_context p;
	struct service_msg *msg;

	in_context_init(&p, data, len);
	p.in_ifp = ifp;
	p.in_tcps = &current->p_tcps;
	p.in_udps = &current->p_udps;
	p.in_ips = &current->p_ips;
	p.in_icmps = &current->p_icmps;
	p.in_arps = &current->p_arps;
	rc = service_in(&p);
	if (rc >= 0) {
		dbg("redir");
		ASSERT(rc < GT_SERVICES_MAX);
		eh = data;
		eh->eh_saddr.ea_bytes[5] = current->p_id;
		eh->eh_daddr.ea_bytes[5] = rc;
		rc = dev_not_empty_txr(&service_vale, &pkt);
		if (rc) {
			counter64_inc(&ifp->rif_rx_drop);
			return;
		}
		DEV_PKT_COPY(pkt.pkt_data, data, len);
		msg = (struct service_msg *)((u_char *)pkt.pkt_data + len);
		msg->msg_type = SERVICE_RX;
		msg->msg_ifindex = ifp->rif_index;
		pkt.pkt_len = len + sizeof(*msg);
		dev_tx(&pkt);
		counter64_inc(&ifp->rif_tx_redir);
	}
}

void
service_rssq_rxtx(struct dev *dev, short revents)
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
			dev_prefetch(rxr);
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			service_rssq_rxtx_one(ifp, data, len);
			route_if_rxr_next(ifp, rxr);
		}
	}
}

static void
service_vale_rxtx(struct dev *dev, short revents)
{
	struct netmap_ring *rxr;

	DEV_FOREACH_RXRING(rxr, dev) {
		DEV_RXR_NEXT(rxr);
	}
}

static void
service_detach(int forked)
{
	int i;
	struct dev *dev;
	struct route_if *ifp;

	service_deinit(forked);
	sys_close(service_sysctl_fd);
	service_sysctl_fd = -1;
	sys_close(service_pid_fd);
	service_pid_fd = -1;
	if (current != NULL) {
		ROUTE_IF_FOREACH(ifp) {
			for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
				dev = &(ifp->rif_dev[current->p_id][i]);
				dev_deinit(dev, forked);
			}
		}
		current = NULL;
	}
	shm_detach();
	foreach_mod_detach();
}

int
service_init(const char *p_comm)
{
	int rc;
	char buf[NM_IFNAMSIZ];

	current->p_kpps = 0;
	current->p_pkts = 0;
	current->p_pkts_time = nanoseconds;
	strzcpy(current->p_comm, p_comm, sizeof(current->p_comm));
	snprintf(buf, sizeof(buf), "vale_gt:%d", current->p_id);
	rc = dev_init(&service_vale, buf, service_vale_rxtx);
	return rc;
}

void
service_deinit()
{
	dev_deinit(&service_vale, 0);
}

int
service_attach()
{
	int i, rc, pid;
	struct sockaddr_un a;
	char pid_filename[32];
	char p_comm[PROC_COMM_MAX];
	char buf[GT_SYSCTL_BUFSIZ];
	struct service *s;

	spinlock_lock(&service_attach_lock);
	if (current != NULL) {
		// Check again under the lock
		spinlock_unlock(&service_attach_lock);
		return 0;
	}
	gt_init();
	ERR(0, "hit;");
	pid = getpid();
	rc = read_comm(p_comm, pid);
	if (rc) {
		goto err;
	}
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(&a, 0);
	if (rc < 0) {
		goto err;
	}
	service_sysctl_fd = rc;
	rc = sysctl_connect(service_sysctl_fd);
	if (rc) {
		rc = service_start_controller(p_comm);
		if (rc) {
			goto err;
		}
		rc = sysctl_connect(service_sysctl_fd);
		if (rc) {
			goto err;
		}
	}
	rc = sysctl_req(service_sysctl_fd,
	                SYSCTL_CONTROLLER_SERVICE_ATTACH, buf, "~");
	if (rc) {
		if (rc > 0) {
			rc = -rc;
		}
		goto err;
	}
	rc = shm_attach((void **)&ih);
	if (rc) {
		goto err;
	}
	if (ih->ih_version != IH_VERSION) {
		rc = -EPROTO;
		goto err;
	}
	set_hz(ih->ih_hz);
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		s = ih->ih_services + i;
		if (s->p_pid == pid) {
			current = s;
			break;
		}
	}
	if (current == NULL) {
		rc = -ENOENT;
		goto err;
	}
	foreach_mod_attach(ih);
	snprintf(pid_filename, sizeof(pid_filename), "%d.pid", current->p_id);
	rc = pid_file_open(pid_filename);
	if (rc < 0) {
		goto err;
	}
	service_pid_fd = rc;
	rc = pid_file_acquire(service_pid_fd, pid);
	if (rc != pid) {
		goto err;
	}
	rc = service_init(p_comm);
	if (rc) {
		goto err;
	}
//	service_update(current);
	ERR(0, "ok; current=%p", current);
	spinlock_unlock(&service_attach_lock);
	return 0;
err:
	service_detach(0);
	ERR(-rc, "failed;");
	spinlock_unlock(&service_attach_lock);
	return rc;
}

static void
service_update_dev(struct route_if *ifp, int rss_qid)
{
	int id, ifflags;
	char dev_name[NM_IFNAMSIZ];
	struct dev *dev;

	ifflags = READ_ONCE(ifp->rif_flags);
	id = READ_ONCE(ih->ih_rss_table[rss_qid]);
	dev = &(ifp->rif_dev[current->p_id][rss_qid]);
	if ((ifflags & IFF_UP) && id == current->p_id) {
		if (!dev_is_inited(dev)) {
			snprintf(dev_name, sizeof(dev_name), "%s-%d",
			         ifp->rif_name, rss_qid);
			dev_init(dev, dev_name, service_rssq_rxtx);
			dev->dev_ifp = ifp;
		}
	} else {
		dev_deinit(dev, 0);
	}
}

void
service_update()
{
	int i;
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < ifp->rif_rss_nq; ++i) {
			service_update_dev(ifp, i);
		}
	}
	current->p_dirty = 0;
}

void
service_inc_pkts()
{
	uint64_t dt;

	current->p_pkts++;
	dt = nanoseconds - current->p_pkts_time;
	if (dt >= NANOSECONDS_MILLISECOND) {
		current->p_kpps = current->p_pkts;
		current->p_pkts_time = nanoseconds;
		current->p_pkts = 0;
		if (dt > 2 * NANOSECONDS_MILLISECOND) {
			// Gap in more then 1 millisecond
			current->p_kpps = 1;
		}
	}
}

static void
service_in_parent(int pipe_fd[2])
{
	sys_close(pipe_fd[1]);
	service_read_pipe(pipe_fd[0]);
	sys_close(pipe_fd[0]);
}

static void
service_in_child(int pipe_fd[2])
{
	int rc;

	sys_close(pipe_fd[0]);
	service_detach(1);
	rc = 0;
	write_full_buf(pipe_fd[1], &rc, sizeof(rc));
	sys_close(pipe_fd[1]);
}

int
service_fork()
{
	int rc, pipe_fd[2];

	rc = sys_pipe(pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork();
	if (rc == 0) {
		service_in_child(pipe_fd);
	} else if (rc > 0) {
		service_in_parent(pipe_fd);
	} else {
		sys_close(pipe_fd[0]);
		sys_close(pipe_fd[1]);
	}
	return rc;
}

#ifdef __linux__
struct service_clone_udata {
	void *arg;
	int (*fn)(void *);
	int pipe_fd[2];
};

static int
service_clone_fn(void *arg)
{
	struct service *s;
	struct service_clone_udata *udata;

	udata = arg;
	s = current;
	service_in_child(udata->pipe_fd);
	spinlock_unlock(&s->p_lock);
	return (*udata->fn)(udata->arg);
}

int
service_clone(int (*fn)(void *), void *child_stack,
	int flags, void *arg, void *ptid, void *tls, void *ctid)
{
	int rc, clone_vm, clone_files, clone_thread;
	struct service_clone_udata udata;

	clone_vm = flags & CLONE_VM;
	clone_files = flags & CLONE_FILES;
	clone_thread = flags & CLONE_THREAD;
	if (clone_vm) {
		if (clone_files == 0 || clone_thread == 0) {
			return -EINVAL;
		}
	} else {
		if (clone_files || clone_thread) {
			return -EINVAL;
		}
	}
	if (clone_vm) {
		rc = (*sys_clone_fn)(fn, child_stack, flags, arg,
		                     ptid, tls, ctid);
	} else {
		udata.fn = fn;
		udata.arg = arg;
		rc = sys_pipe(udata.pipe_fd);
		if (rc) {
			return rc;
		}
		rc = (*sys_clone_fn)(service_clone_fn,
		                     child_stack, flags,
		                     &udata, ptid, tls, ctid);
		if (rc == -1) {
			rc = -errno;
			sys_close(udata.pipe_fd[0]);
			sys_close(udata.pipe_fd[1]);
		} else {
			service_in_parent(udata.pipe_fd);
		}
	}
	return rc;
}
#endif // __linux__
