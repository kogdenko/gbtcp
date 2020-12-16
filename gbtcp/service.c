// GPL v2
#include "internals.h"

#define CURMOD service

struct service_msg {
	uint16_t msg_type;
	uint16_t msg_ifindex;
	struct eth_addr msg_orig_saddr;
	struct eth_addr msg_orig_daddr;
};

static struct spinlock service_attach_lock;
static int service_sysctl_fd = -1;
static int service_pid_fd = -1;
static struct dev service_vale;
static int service_signal_guard = 1;
static int service_autostart_controller = 1;

struct shm_hdr *shared;
struct service *current;
sigset_t current_sigprocmask;
int current_sigprocmask_set;

static int
service_pipe(int fd[2])
{
	int rc;

	rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	assert(rc == 0);
	return rc;
}

static void
service_pipe_send(int fd, int msg)
{
	send_record(fd, &msg, sizeof(msg), MSG_NOSIGNAL);
}

static int
service_pipe_recv(int fd)
{
	int rc, msg;
	uint64_t to;

	to = 4 * NSEC_SEC;
	rc = read_timed(fd, &msg, sizeof(msg), &to);
	if (rc == 0) {
		ERR(0, "peer closed;");
		return -EPIPE;
	} else if (rc == sizeof(msg)) {
		if (msg >= 0) {
			if (msg > 0) {
				ERR(msg, "error;");
			} else {
				NOTICE(0, "ok;");
			}
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
service_start_controller_nolog(const char *p_comm)
{
	int rc, pipe_fd[2];

	rc = service_pipe(pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork();
	if (rc == 0) {
		sys_close(pipe_fd[0]);
		sys_close(service_sysctl_fd);
		rc = controller_init(1, p_comm);
		service_pipe_send(pipe_fd[1], rc);
		sys_close(pipe_fd[1]);
		if (rc == 0) {
			while (!controller_done) {
				controller_process();
			}
		}
		exit(EXIT_SUCCESS);
	} else if (rc > 0) {
		// child created by fork become zombie after daemon()
		sys_waitpid(-1, NULL, 0);
		sys_close(pipe_fd[1]);
		rc = service_pipe_recv(pipe_fd[0]);
		sys_close(pipe_fd[0]);
	}
	return rc;
}

static int
service_start_controller(const char *p_comm)
{
	int rc;

	NOTICE(0, "hit;");
	rc = service_start_controller_nolog(p_comm);
	if (rc < 0) {
		ERR(-rc, "failed;");
	} else if (rc > 0) {
		WARN(rc, "error;");
	} else {
		NOTICE(0, "ok;");
	}
	return rc;
}

static int
service_rx(struct in_context *p)
{
	int rc, ipproto;

	rc = eth_input(p);
	assert(rc < 0);
	if (rc != IN_OK) {
		return rc;
	}
	ipproto = p->in_ipproto;
	if (ipproto == IPPROTO_UDP || ipproto == IPPROTO_TCP) {
		rc = so_input(ipproto, p,
		              p->in_ih->ih_daddr, p->in_ih->ih_saddr,
		              p->in_uh->uh_dport, p->in_uh->uh_sport);
	} else if (ipproto == IPPROTO_ICMP && p->in_errnum &&
	           (p->in_emb_ipproto == IPPROTO_UDP ||
	            p->in_emb_ipproto == IPPROTO_TCP)) {
		rc = so_input_err(p->in_emb_ipproto, p,
		                  p->in_ih->ih_daddr, p->in_ih->ih_saddr,
		                  p->in_uh->uh_dport, p->in_uh->uh_sport);
	} else {
		rc = IN_DROP;
	}
	return rc;
}

static int
vale_transmit5(struct route_if *ifp, int msg_type, u_char sid,
	void *data, int len)
{
	int rc;
	struct dev_pkt pkt;

	rc = dev_not_empty_txr(&service_vale, &pkt, TX_CAN_RECLAIM);
	if (rc == 0) {
		DEV_PKT_COPY(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		pkt.pkt_sid = sid;
		vale_transmit(ifp, msg_type, &pkt);
	}
	return rc;
}

static void
service_rssq_rx_one(struct route_if *ifp, void *data, int len)
{
	int rc;
	u_char sid;
	struct in_context p;

	in_context_init(&p, data, len);
	p.in_ifp = ifp;
	p.in_tcps = &current->p_tcps;
	p.in_udps = &current->p_udps;
	p.in_ips = &current->p_ips;
	p.in_icmps = &current->p_icmps;
	p.in_arps = &current->p_arps;
	rc = service_rx(&p);
	if (rc == IN_BYPASS) {
		if (current->p_sid == CONTROLLER_SID) {
			transmit_to_host(ifp, data, len);
		} else {
			vale_transmit5(ifp, SERVICE_MSG_BYPASS,
			               CONTROLLER_SID, data, len);
		}
	} else if (rc >= 0) {
		current->p_ips.ips_delivered++;
		sid = rc;
		rc = vale_transmit5(ifp, SERVICE_MSG_RX, sid, data, len);
		if (rc) {
			counter64_inc(&ifp->rif_rx_drop);
			return;
		}
	} else if (rc == IN_OK) {
		current->p_ips.ips_delivered++;
	}
	counter64_inc(&ifp->rif_rx_pkts);
	counter64_add(&ifp->rif_rx_bytes, len);
}

static void
service_vale_rx_one(void *data, int len)
{
	int rc;
	struct tcp_stat tcps;
	struct udp_stat udps;
	struct ip_stat ips;
	struct icmp_stat icmps;
	struct arp_stat arps;
	struct eth_hdr *eh;
	struct eth_addr a;
	struct route_if *ifp;
	struct service_msg *msg;
	struct in_context p;
	struct dev_pkt pkt;

	if (len < sizeof(*msg) + sizeof(*eh)) {
		return;
	}
	eh = data;
	memset(&a, 0, sizeof(a));
	a.ea_bytes[5] = current->p_sid;
	if (memcmp(a.ea_bytes, eh->eh_daddr.ea_bytes, sizeof(a))) {
		return;
	}
	msg = (struct service_msg *)((u_char *)data + len - sizeof(*msg));
	ifp = route_if_get_by_index(msg->msg_ifindex);
	if (ifp == NULL) {
		return;
	}
	eh->eh_saddr = msg->msg_orig_saddr;
	eh->eh_daddr = msg->msg_orig_daddr;	
	len -= sizeof(*msg);
	switch (msg->msg_type) {
	case SERVICE_MSG_RX:
		in_context_init(&p, data, len);
		p.in_tcps = &tcps;
		p.in_udps = &udps;
		p.in_ips = &ips;
		p.in_icmps = &icmps;
		p.in_arps = &arps;
		service_rx(&p);
		break;
	case SERVICE_MSG_TX:
		rc = route_not_empty_txr(ifp, &pkt, TX_CAN_RECLAIM);
		if (rc == 0) {
			DEV_PKT_COPY(pkt.pkt_data, data, len);
			pkt.pkt_len = len;
			route_transmit(ifp, &pkt);
		} else {
			counter64_inc(&ifp->rif_tx_drop);
		}
		break;
	case SERVICE_MSG_BYPASS:
		if (current->p_sid == CONTROLLER_SID) {
			transmit_to_host(ifp, data, len);
		}
		break;
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
			service_rssq_rx_one(ifp, data, len);
			DEV_RXR_NEXT(rxr);
		}
	}
}

static void
service_vale_rxtx(struct dev *dev, short revents)
{
	int i, n, len;
	void *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;

	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			dev_prefetch(rxr);
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			service_vale_rx_one(data, len);
			DEV_RXR_NEXT(rxr);
		}
	}
}

int
service_pid_file_acquire(int sid, int pid)
{
	int rc, fd;
	char path[PATH_MAX];

	pid_file_path(path, sid);
	rc = pid_file_open(path);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = pid_file_acquire(fd, pid);
	if (rc >= 0 && rc != pid) {
		rc = -EBUSY;
	}
	if (rc < 0) {
		sys_close(fd);
		return rc;
	} else {
		return fd;
	}
}

struct service *
service_get_by_sid(u_int sid)
{
	assert(sid < ARRAY_SIZE(shared->shm_services));
	return shared->shm_services + sid;
}

int
service_init_shared(struct service *s, int pid, int fd)
{
	int rc;

	NOTICE(0, "hit; pid=%d", pid);
	assert(current->p_sid == CONTROLLER_SID);
	WRITE_ONCE(s->wmm_rcu_epoch, 1);
	smp_wmb();
	s->p_pid = pid;
	dlist_init(&s->p_tx_head);
	s->p_sid = s - shared->shm_services;
	s->p_need_update_rss_bindings = 0;
	s->p_rss_nq = 0;
	s->p_rr_redir = 0;
	s->p_fd = fd;
	s->p_start_time = shared_ns();
	s->p_okpps = 0;
	s->p_okpps_time = 0;
	s->p_opkts = 0;
	init_worker_mem(s);
	rc = init_timers(s);
	if (rc) {
		return rc;
	}
	rc = init_files(s);
	if (rc) {
		return rc;
	}
	return 0;
}

void
service_deinit_shared(struct service *s, int full)
{
	int i;
	struct dev *dev;
	struct route_if *ifp;

	NOTICE(0, "hit; pid=%d", s->p_pid);
	assert(current->p_sid == CONTROLLER_SID);
	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
			dev = &(ifp->rif_dev[s->p_sid][i]);
			memset(dev, 0, sizeof(*dev));
		}
	}
	deinit_files(s);
	if (current != s && !dlist_is_empty(&s->p_tx_head)) {
		dlist_splice_tail_init(&current->p_tx_head, &s->p_tx_head);
	}
	if (current != s) {
		migrate_timers(current, s);
	}
	if (full) {
		deinit_timers(s);
	}
	smp_wmb();
	WRITE_ONCE(s->wmm_rcu_epoch, 0);
	s->p_pid = 0;
}

int
service_init_private()
{
	int rc;
	char buf[NM_IFNAMSIZ];

	snprintf(buf, sizeof(buf), "vale_gt:%d", current->p_pid);
	rc = dev_init(&service_vale, buf, service_vale_rxtx);
	return rc;
}

void
service_deinit_private()
{
	dev_deinit(&service_vale);
}

int
service_attach(const char *fn_name)
{
	int rc, pid;
	struct sockaddr_un a;
	char p_comm[SERVICE_COMM_MAX];
	char buf[GT_SYSCTL_BUFSIZ];
	sigset_t sigprocmask_block;
	struct service *s;

	spinlock_lock(&service_attach_lock);
	// check again under the lock
	if (current != NULL) {
		spinlock_unlock(&service_attach_lock);
		return 0;
	}
	ERR(0, "hit; from=%s", fn_name);
	pid = getpid();
	rc = read_proc_comm(p_comm, pid);
	if (rc) {
		goto err;
	}
	gt_init(p_comm, 0);
	NOTICE(0, "hit2; from=%s", fn_name);
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(&a);
	if (rc < 0) {
		goto err;
	}
	service_sysctl_fd = rc;
	rc = sysctl_connect(service_sysctl_fd);
	if (rc) {
		if (!service_autostart_controller) {
			goto err;
		}
		WARN(0, "Can't connect to controller. Try to start one");
		rc = service_start_controller(p_comm);
		if (rc) {
			goto err;
		}
		rc = sysctl_connect(service_sysctl_fd);
		if (rc) {
			goto err;
		}
	}
	if (service_signal_guard) {
		sigfillset(&sigprocmask_block);
		rc = sys_sigprocmask(SIG_BLOCK, &sigprocmask_block,
	        	             &current_sigprocmask);
		if (rc) {
			goto err;
		}
		current_sigprocmask_set = 1;
	}
	rc = sysctl_req(service_sysctl_fd, SYSCTL_CONTROLLER_ADD, buf, "~");
	if (rc) {
		if (rc > 0) {
			rc = -rc;
		}
		goto err;
	}
	rc = shm_attach();
	if (rc) {
		goto err;
	}
	set_hz(shared->shm_hz);
	SERVICE_FOREACH(s) {
		if (s->p_pid == pid) {
			current = s;
			break;
		}
	}
	if (current == NULL) {
		rc = -ENOENT;
		goto err;
	}
	init_worker_mem(current);
	rc = service_pid_file_acquire(current->p_sid, pid);
	if (rc < 0) {
		goto err;
	}
	service_pid_fd = rc;
	rc = service_init_private();
	if (rc) {
		goto err;
	}
	ERR(0, "ok; current=%p", current);
	spinlock_unlock(&service_attach_lock);
	return 0;
err:
	service_detach();
	ERR(-rc, "failed;");
	spinlock_unlock(&service_attach_lock);
	return rc;
}

void
service_detach()
{
	int i;
	struct dev *dev;
	struct route_if *ifp;

	NOTICE(0, "hit;");
	service_deinit_private();
	sys_close(service_sysctl_fd);
	service_sysctl_fd = -1;
	sys_close(service_pid_fd);
	service_pid_fd = -1;
	if (current != NULL) {
		ROUTE_IF_FOREACH(ifp) {
			for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
				dev = &(ifp->rif_dev[current->p_sid][i]);
				dev_close_fd(dev);
			}
		}
		current = NULL;
	}
	shm_detach();
	clean_fd_events();
	if (current_sigprocmask_set) {
		current_sigprocmask_set = 0;
		sys_sigprocmask(SIG_SETMASK, &current_sigprocmask, NULL);
	}
}

void
service_unlock()
{
	rcu_update();
	spinlock_unlock(&current->p_lock);
}

void
service_account_opkt()
{
	uint64_t dt;

	current->p_opkts++;
	dt = nanoseconds - current->p_okpps_time;
	if (dt >= NSEC_MSEC) {
		if (dt > 2 * NSEC_MSEC) {
			// Gap in more then 1 millisecond
			WRITE_ONCE(current->p_okpps, 0);
		} else {
			WRITE_ONCE(current->p_okpps, current->p_opkts);
		}
		current->p_okpps_time = nanoseconds;
		current->p_opkts = 0;
	}
}

static void
service_update_rss_binding(struct route_if *ifp, int rss_qid)
{
	int id, ifflags;
	char dev_name[NM_IFNAMSIZ];
	struct dev *dev;

	ifflags = READ_ONCE(ifp->rif_flags);
	id = READ_ONCE(shared->shm_rss_table[rss_qid]);
	dev = &(ifp->rif_dev[current->p_sid][rss_qid]);
	if ((ifflags & IFF_UP) && id == current->p_sid) {
		if (!dev_is_inited(dev)) {
			snprintf(dev_name, sizeof(dev_name), "%s-%d",
			         ifp->rif_name, rss_qid);
			dev_init(dev, dev_name, service_rssq_rxtx);
			dev->dev_ifp = ifp;
		}
	} else {
		dev_deinit(dev);
	}
}

void
service_update_rss_bindings()
{
	int i;
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < ifp->rif_rss_nq; ++i) {
			service_update_rss_binding(ifp, i);
		}
	}
	current->p_need_update_rss_bindings = 0;
}

int
service_can_connect(struct route_if *ifp, be32_t laddr, be32_t faddr,
	be16_t lport, be16_t fport)
{
	int i, sid, rss_qid;
	uint32_t h;

	if (ifp->rif_rss_nq == 1) {
		return 1;
	}
	rss_qid = -1;
	for (i = 0; i < ifp->rif_rss_nq; ++i) {
		sid = READ_ONCE(shared->shm_rss_table[i]);
		if (sid == current->p_sid) {
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

int
vale_not_empty_txr(struct route_if *ifp, struct dev_pkt *pkt, int flags)
{
	int i, n, rc;
	u_char s[GT_RSS_NQ_MAX];

	n = 0;
	for (i = 0; i < ifp->rif_rss_nq; ++i) {
		s[n] = READ_ONCE(shared->shm_rss_table[i]);
		if (s[n] != SERVICE_ID_INVALID) {
			n++;
		}
	}
	if (n == 0) {
		return -ENODEV;
	}
	rc = dev_not_empty_txr(&service_vale, pkt, flags);
	if (rc) {
		return rc;
	}
	if (current->p_rr_redir >= n) {
		current->p_rr_redir = 0;
	}
	pkt->pkt_sid = s[current->p_rr_redir];
	current->p_rr_redir++;
	return 0;
}

void
vale_transmit(struct route_if *ifp, int msg_type, struct dev_pkt *pkt)
{
	struct eth_hdr *eh;
	struct service_msg *msg;

	msg = (struct service_msg *)((u_char *)pkt->pkt_data + pkt->pkt_len);
	eh = (struct eth_hdr *)pkt->pkt_data;
	msg->msg_orig_saddr = eh->eh_saddr;
	msg->msg_orig_daddr = eh->eh_daddr;
	memset(eh->eh_saddr.ea_bytes, 0, sizeof(eh->eh_saddr));
	memset(eh->eh_daddr.ea_bytes, 0, sizeof(eh->eh_daddr));
	eh->eh_saddr.ea_bytes[5] = current->p_sid;
	eh->eh_daddr.ea_bytes[5] = pkt->pkt_sid;
	msg->msg_type = msg_type;
	msg->msg_ifindex = ifp->rif_index;
	pkt->pkt_len += sizeof(*msg);
	//dbg_rl(1, "redir");
	dev_transmit(pkt);
}

int
service_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;
	sigset_t tmp;

	if (!current_sigprocmask_set) {
		rc = sys_sigprocmask(how, set, oldset);
	} else {
		// unblock
		sys_sigprocmask(SIG_SETMASK, &current_sigprocmask, &tmp);
		rc = sys_sigprocmask(how, set, oldset);
		sys_sigprocmask(SIG_SETMASK, &tmp, &current_sigprocmask);
	}
	return rc;
}

static void
service_in_parent(int pipe_fd[2])
{
	sys_close(pipe_fd[1]);
	// wait service_in_child done
	service_pipe_recv(pipe_fd[0]);
	sys_close(pipe_fd[0]);
}

static int
service_dup_so(struct sock *oldso)
{
	int rc, fd, flags;
	struct sockaddr_in a;
	struct sock *newso;

	fd = oldso->so_fd;
	flags = oldso->so_blocked ? SOCK_NONBLOCK : 0;
	rc = so_socket6(&newso, fd, AF_INET,
	                SOCK_STREAM, flags, 0);
	if (rc < 0) {
		return rc;
	}
	a.sin_family = AF_INET;
	a.sin_port = oldso->so_lport;
	a.sin_addr.s_addr = oldso->so_laddr;
	rc = so_bind(newso, &a);
	if (rc) {
		goto err;
	}
	rc = so_listen(newso, 0);
	if (rc) {
		goto err;
	}
	newso->so_blocked = oldso->so_blocked;
	INFO(0, "ok; fd=%d", fd);
	return 0;
err:
	WARN(-rc, "failed; fd=%d", fd);
	so_close(newso);
	return rc;
}

static void
service_in_child0()
{
	int rc, parent_sid, flag;
	struct sock *so;

	flag = 0;
	parent_sid = current->p_sid;
	SO_FOREACH_BINDED(so) {
		if (so->so_sid == parent_sid &&
		    so->so_ipproto == SO_IPPROTO_TCP &&
		    so->so_state == GT_TCPS_LISTEN) {
			flag = 1;
			break;
		}
	};
	service_detach();
	if (!flag) {
		return;
	}
	rc = service_attach("in_child");
	if (rc) {
		return;
	}
	flag = 0;
	SO_FOREACH_BINDED(so) {
		if (so->so_sid == parent_sid &&
		    so->so_ipproto == SO_IPPROTO_TCP &&
		    so->so_state == GT_TCPS_LISTEN) {
			rc = service_dup_so(so);
			if (rc == 0) {
				flag = 1;
			}
		}
	}
	if (!flag) {
		service_detach();
	}
}

static void
service_in_child(int pipe_fd[2])
{
	NOTICE(0, "hit;");
	sys_close(pipe_fd[0]);
	service_in_child0();
	service_pipe_send(pipe_fd[1], 0);
	sys_close(pipe_fd[1]);
}

int
service_fork()
{
	int rc, pipe_fd[2];

	NOTICE(0, "hit;");
	rc = service_pipe(pipe_fd);
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
static int (*service_clone_fn)(void *);
static int service_clone_pipe_fd[2];

static int
service_clone_in_child(void *arg)
{
	service_in_child(service_clone_pipe_fd);
	return (*service_clone_fn)(arg);
}

int
service_clone(int (*fn)(void *), void *child_stack,
	int flags, void *arg, void *ptid, void *tls, void *ctid)
{
	int rc, clone_vm, clone_files, clone_thread;

	clone_vm = flags & CLONE_VM;
	clone_files = flags & CLONE_FILES;
	clone_thread = flags & CLONE_THREAD;
	NOTICE(0, "hit; flags=%s", log_add_clone_flags(flags));
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
		// Just a thread
		rc = sys_clone(fn, child_stack, flags, arg, ptid, tls, ctid);
	} else {
		service_clone_fn = fn;
		rc = service_pipe(service_clone_pipe_fd);
		if (rc) {
			return rc;
		}
		rc = sys_clone(service_clone_in_child, child_stack, flags, arg,
		               ptid, tls, ctid);
		if (rc == -1) {
			rc = -errno;
			sys_close(service_clone_pipe_fd[0]);
			sys_close(service_clone_pipe_fd[1]);
		} else {
			service_in_parent(service_clone_pipe_fd);
		}
	}
	return rc;
}
#endif // __linux__
