// gpl2
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
static int service_sigprocmask_set;
static struct dev service_vale;
static int service_rcu_max;
static struct dlist service_rcu_active_head;
static struct dlist service_rcu_shadow_head;
static u_int service_rcu[GT_SERVICES_MAX];

struct shm_init_hdr *shm_ih;
struct service *current;
sigset_t service_sigprocmask;

static int
service_pipe_read(int fd)
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

	rc = sys_pipe(pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork();
	if (rc == 0) {
		sys_close(pipe_fd[0]);
		sys_close(service_sysctl_fd);
		rc = init_sched(1, p_comm);
		write_record(pipe_fd[1], &rc, sizeof(rc));
		sys_close(pipe_fd[1]);
		if (rc == 0) {
			sched_loop();
		}
		exit(EXIT_SUCCESS);
	} else if (rc > 0) {
		// child created by fork become zombie after daemon()
		sys_waitpid(-1, NULL, 0);
		sys_close(pipe_fd[1]);
		rc = service_pipe_read(pipe_fd[0]);
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

	rc = eth_in(p);
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
		if (current->p_sid == SCHED_SID) {
			transmit_to_host(ifp, data, len);
		} else {
			vale_transmit5(ifp, SERVICE_MSG_BYPASS,
			               SCHED_SID, data, len);
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
		if (current->p_sid == SCHED_SID) {
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
	char buf[32];

	snprintf(buf, sizeof(buf), "%d.pid", sid);
	rc = pid_file_open(buf);
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
	assert(sid < ARRAY_SIZE(shm_ih->ih_services));
	return shm_ih->ih_services + sid;
}

int
service_init_shared(struct service *s, int pid, int fd)
{
	int i, rc;

	NOTICE(0, "hit; pid=%d", pid);
	assert(current->p_sid == CONTROLLER_SID);
	s->p_pid = pid;
	s->p_sid = s - shm_ih->ih_services;
	s->p_need_update_rss_bindings = 0;
	s->p_rss_nq = 0;
	s->p_rr_redir = 0;
	s->p_fd = fd;
	service_store_epoch(s, 1);
	s->p_start_time = shm_ns;
	s->p_okpps = 0;
	s->p_okpps_time = 0;
	s->p_opkts = 0;
	assert(s->p_mbuf_garbage_max == 0);
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		dlist_init(s->p_mbuf_garbage_head + i);
	}
	rc = init_timers(s);
	if (rc) {
		return rc;
	}
	rc = service_init_arp(s);
	if (rc) {
		return rc;
	}
	rc = service_init_file(s);
	if (rc) {
		return rc;
	}
	rc = service_init_tcp(s);
	if (rc) {
		return rc;
	}
	return 0;
}

void
service_deinit_shared(struct service *s, int full)
{
	int i;
	struct dlist tofree;
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
	service_deinit_file(s);
	migrate_timers(current, s);
	if (full) {
		service_deinit_tcp(s);
		service_deinit_arp(s);
		deinit_timers(s);
	}
	dlist_init(&tofree);
	shm_lock();
	shm_garbage_push(s);
	shm_garbage_push(current);
	shm_garbage_pop(&tofree, s->p_sid);
	shm_garbage_pop(&tofree, current->p_sid);
	shm_unlock();
	mbuf_free_direct_list(&tofree);
	service_store_epoch(s, 0);
	s->p_pid = 0;
}

int
service_init_private()
{
	int rc;
	char buf[NM_IFNAMSIZ];

	dlist_init(&service_rcu_active_head);
	dlist_init(&service_rcu_shadow_head);
	service_rcu_max = 0;
	memset(service_rcu, 0, sizeof(service_rcu));
	snprintf(buf, sizeof(buf), "vale_gt:%d", current->p_pid % 1000);
	rc = dev_init(&service_vale, buf, service_vale_rxtx);
	return rc;
}

void
service_deinit_private()
{
	dev_deinit(&service_vale);
}

int
service_attach()
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
	ERR(0, "hit;");
	pid = getpid();
	rc = read_proc_comm(p_comm, pid);
	if (rc) {
		goto err;
	}
	gt_init(p_comm, 0);
	NOTICE(0, "hit2;");
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
	sigfillset(&sigprocmask_block);
	rc = sys_sigprocmask(SIG_BLOCK, &sigprocmask_block,
	                     &service_sigprocmask);
	if (rc) {
		goto err;
	}
	service_sigprocmask_set = 1;
	rc = sysctl_req(service_sysctl_fd, SYSCTL_SCHED_ADD, buf, "~");
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
	set_hz(shm_ih->ih_hz);
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
	shm_ih = NULL;
	shm_detach();
	clean_fd_events();
	if (service_sigprocmask_set) {
		service_sigprocmask_set = 0;
		sys_sigprocmask(SIG_SETMASK, &service_sigprocmask, NULL);
	}
}

static void
service_rcu_reload()
{
	int i;
	struct service *s;

	dlist_replace_init(&service_rcu_active_head, &service_rcu_shadow_head);
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		s = shm_ih->ih_services + i;
		if (s != current) {
			service_rcu[i] = service_load_epoch(s);
			if (service_rcu[i]) {
				service_rcu_max = i + 1;
			}
		}
	}
	//if (service_rcu_max == 0) {
	//	service_rcu_free();
	//}
}

void
mbuf_free_rcu(struct mbuf *m)
{
	DLIST_INSERT_TAIL(&service_rcu_shadow_head, m, mb_list);
	if (service_rcu_max == 0) {
		assert(dlist_is_empty(&service_rcu_active_head));
		service_rcu_reload();
	}
}

static void
service_rcu_free()
{
	struct dlist *head;
	struct mbuf *m;

	head = &service_rcu_active_head;
	while (!dlist_is_empty(head)) {
		m = DLIST_FIRST(head, struct mbuf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mbuf_free(m);
	}
}

static void
service_rcu_check()
{
	u_int i, epoch, rcu_max;
	struct service *s;

	rcu_max = 0;
	for (i = 0; i < service_rcu_max; ++i) {
		s = shm_ih->ih_services + i;
		if (service_rcu[i]) {
			epoch = service_load_epoch(s);
			if (service_rcu[i] != epoch) {
				service_rcu[i] = 0;
			} else {
				rcu_max = i + 1;
			}
		}
	}
	service_rcu_max = rcu_max;
	if (service_rcu_max == 0) {
		service_rcu_free();
		if (!dlist_is_empty(&service_rcu_shadow_head)) {
			service_rcu_reload();
		}
	}
}

void
service_unlock()
{
	u_int epoch;

	epoch = current->p_epoch;
	epoch++;
	if (epoch == 0) {
		epoch = 1;
	}
	service_store_epoch(current, epoch);
	service_rcu_check();
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
	id = READ_ONCE(shm_ih->ih_rss_table[rss_qid]);
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
		sid = READ_ONCE(shm_ih->ih_rss_table[i]);
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
		s[n] = READ_ONCE(shm_ih->ih_rss_table[i]);
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
	dev_transmit(pkt);
}

static void
service_in_parent(int pipe_fd[2])
{
	sys_close(pipe_fd[1]);
	// wait service_in_child done
	service_pipe_read(pipe_fd[0]);
	sys_close(pipe_fd[0]);
}

static int
service_dup_so(struct sock *oldso)
{
	int rc, fd, flags;
	struct sockaddr_in a;
	struct sock *newso;

	fd = so_get_fd(oldso);
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
	int rc, n, psid;
	struct sock *so;

	n = 0;
	psid = current->p_sid;
	SO_FOREACH_BINDED(so) {
		if (so->so_sid == psid &&
		    so->so_ipproto == SO_IPPROTO_TCP &&
		    so->so_state == GT_TCPS_LISTEN) {
			n++;
			break;
		}
	};
	service_detach();
	if (n == 0) {
		return;
	}
	rc = service_attach();
	if (rc) {
		return;
	}
	n = 0;
	SO_FOREACH_BINDED(so) {
		if (so->so_sid == psid &&
		    so->so_ipproto == SO_IPPROTO_TCP &&
		    so->so_state == GT_TCPS_LISTEN) {
			rc = service_dup_so(so);
			if (rc == 0) {
				n++;
			}
		}
	}
	if (n == 0) {
		service_detach();
	}
}

static void
service_in_child(int pipe_fd[2])
{
	int rc;

	NOTICE(0, "hit;");
	sys_close(pipe_fd[0]);
	service_in_child0();
	rc = 0;
	write_record(pipe_fd[1], &rc, sizeof(rc));
	sys_close(pipe_fd[1]);
}

int
service_fork()
{
	int rc, pipe_fd[2];

	NOTICE(0, "hit;");
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

	NOTICE(0, "hit;");
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
