// GPL v2
#include "internals.h"

#define CURMOD service

struct service_msg {
	uint16_t msg_type;
	uint16_t msg_ifindex;
	struct eth_addr msg_orig_saddr;
	struct eth_addr msg_orig_daddr;
};

static int worker_sysctl_fd = -1;
 int worker_pid_fd = -1;
//static struct dev service_vale;

struct shm_hdr *shared;
struct process *current;
__thread struct cpu *current_cpu;
char current_name[PROC_NAME_MAX];
__thread int current_cpu_id = -1;

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
	struct timespec to;

	to.tv_sec = 4;
	to.tv_nsec = 0;
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
		return -EINVAL;
	} else {
		return rc;
	}
}

static int
service_start_controller()
{
	int rc, pipe_fd[2];

	rc = service_pipe(pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork();
	if (rc == 0) {
		sys_close(&pipe_fd[0]);
		sys_close(&worker_sysctl_fd);
		rc = controller_init(1, 0, current_name);
		service_pipe_send(pipe_fd[1], rc);
		sys_close(&pipe_fd[1]);
		if (rc == 0) {
			while (!controller_done) {
				controller_process();
			}
		}
		exit(EXIT_SUCCESS);
	} else if (rc > 0) {
		// child created by fork become zombie after daemon()
		sys_waitpid(-1, NULL, 0);
		sys_close(&pipe_fd[1]);
		rc = service_pipe_recv(pipe_fd[0]);
		sys_close(&pipe_fd[0]);
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
	assert(0);
#if 0
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
#else
	return 0;
#endif
}

static void
service_rssq_rx_one(struct route_if *ifp, void *data, int len)
{
	int rc;
	u_char sid;
	struct in_context p;

	in_context_init(&p, data, len);
	p.in_ifp = ifp;
	p.in_tcps = &current_cpu->p_tcps;
	p.in_udps = &current_cpu->p_udps;
	p.in_ips = &current_cpu->p_ips;
	p.in_icmps = &current_cpu->p_icmps;
	p.in_arps = &current_cpu->p_arps;
	rc = service_rx(&p);
	if (rc == IN_BYPASS) {
		/*if (current_cpu_id == DAEMON_CPU_ID) {
			transmit_to_host(ifp, data, len);
		} else {
			vale_transmit5(ifp, SERVICE_MSG_BYPASS,
				DAEMON_CPU_ID, data, len);
		}*/
	} else if (rc >= 0) {
		current_cpu->p_ips.ips_delivered++;
		sid = rc;
		rc = vale_transmit5(ifp, SERVICE_MSG_RX, sid, data, len);
		if (rc) {
			counter64_inc(&ifp->rif_rx_drop);
			return;
		}
	} else if (rc == IN_OK) {
		current_cpu->p_ips.ips_delivered++;
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
	a.ea_bytes[5] = current->ps_pid;
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
		if (current_cpu_id == AUX_CPU_ID) {
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

void
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
service_init_shared(struct cpu *cpu, int pid, int fd)
{
	int rc, cpu_id;

	cpu_id = cpu - shared->msb_cpus;
	smp_wmb();
	cpu->p_pid = pid;
	dlist_init(&cpu->p_tx_head);
	cpu->p_fd = fd;
	cpu->p_start_time = nanosecond;
	init_mem(cpu_id);
	rc = init_timers(cpu);
	if (rc) {
		return rc;
	}
	rc = init_files(cpu);
	if (rc) {
		return rc;
	}
	return 0;
}

#if 0
void
service_deinit_shared(struct service *s, int full)
{
//	int i;
//	struct dev *dev;
//	struct route_if *ifp;

	assert(current->p_sid == CONTROLLER_SID);
	/*ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
			dev = &(ifp->rif_dev[s->p_sid][i]);
			memset(dev, 0, sizeof(*dev));
		}
	}*/

	deinit_files(s);
	if (current != s) {
		dlist_splice_tail_init(&current->p_tx_head, &s->p_tx_head);
	}
	if (current != s) {
		migrate_timers(current, s);
	}
	if (full) {
		deinit_timers(s);
	}
	deinit_worker_mem(s);
	s->p_pid = 0;
}


int
service_init_private()
{
	int rc;
	char buf[NM_IFNAMSIZ];

	snprintf(buf, sizeof(buf), "vale_gt:%d", current->ps_pid);
	rc = dev_init(&service_vale, buf, service_vale_rxtx);
	return rc;
}

void
service_deinit_private()
{
	dev_deinit(&service_vale);
}
#endif

int
attach_worker()
{
	int rc, pid;
	struct sockaddr_un a;
	char path[PATH_MAX];
//	char buf[GT_SYSCTL_BUFSIZ];
//	struct service *s;

	dbg("a");
	pid = getpid();
	rc = read_proc_name(current_name, pid);
	if (rc) {
		goto err;
	}
	rc = init_log();
	if (rc) {
		goto err;
	}
	dbg("a500");

	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(&a);
	dbg("a1000");
	if (rc < 0) {
		goto err;
	}
	worker_sysctl_fd = rc;
	rc = sysctl_connect(worker_sysctl_fd);
	if (rc) {
		dbg("!!!");
		WARN(0, "starting controller");
		rc = service_start_controller();
		if (rc) {
			goto err;
		}
		rc = sysctl_connect(worker_sysctl_fd);
		if (rc) {
			goto err;
		}
	}

	snprintf(path, sizeof(path), "%s/%d.pid", PID_PATH, pid);
	rc = pid_file_acquire(path, pid, 0);
	if (rc < 0) {
		goto err;
	} 
	worker_pid_fd = rc;


	rc = shm_attach();
	if (rc) {
		goto err;
	}
	dbg("Ready!!!!");
	return 0;
err:
	return rc;
}

#if 0
void
service_detach()
{
//	int i;
//	struct dev *dev;
//	struct route_if *ifp;

	///service_deinit_private();
	sys_close(service_sysctl_fd);
	service_sysctl_fd = -1;
	sys_close(service_pid_fd);
	service_pid_fd = -1;
	if (current != NULL) {
/*		ROUTE_IF_FOREACH(ifp) {
			for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
				dev = &(ifp->rif_dev[current->p_sid][i]);
				dev_close_fd(dev);
			}
		}
		current = NULL;*/
	}
	shm_detach();
	clean_fd_events();
	// TODO: deinit_signals() if no worker in process
}
#endif

void
service_unlock()
{
	rcu_update();
	spinlock_unlock(&current_cpu->p_lock);
}

/*
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
}*/

int
service_can_connect(struct route_if *ifp, be32_t laddr, be32_t faddr,
	be16_t lport, be16_t fport)
{
#if 0
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
#endif
	assert(0);
	return -EINVAL;
}

int
vale_not_empty_txr(struct route_if *ifp, struct dev_pkt *pkt, int flags)
{
#if 0
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
#endif
	assert(0);
	return -EINVAL;
}

void
vale_transmit(struct route_if *ifp, int msg_type, struct dev_pkt *pkt)
{
	assert(0);
#if 0
	struct eth_hdr *eh;
	struct service_msg *msg;

	msg = (struct service_msg *)((u_char *)pkt->pkt_data + pkt->pkt_len);
	eh = (struct eth_hdr *)pkt->pkt_data;
	msg->msg_orig_saddr = eh->eh_saddr;
	msg->msg_orig_daddr = eh->eh_daddr;
	memset(eh->eh_saddr.ea_bytes, 0, sizeof(eh->eh_saddr));
	memset(eh->eh_daddr.ea_bytes, 0, sizeof(eh->eh_daddr));
	eh->eh_saddr.ea_bytes[5] = current->ps_pid;
	eh->eh_daddr.ea_bytes[5] = pkt->pkt_sid;
	msg->msg_type = msg_type;
	msg->msg_ifindex = ifp->rif_index;
	pkt->pkt_len += sizeof(*msg);
	//dbg_rl(1, "redir");
	dev_transmit(pkt);
#endif
}

static void
service_in_parent(int pipe_fd[2])
{
	sys_close(&pipe_fd[1]);
	// wait service_in_child done
	service_pipe_recv(pipe_fd[0]);
	sys_close(&pipe_fd[0]);
}

#if 0
static int
service_dup_so(struct sock *oldso)
{
	int rc, fd, flags;
	struct sockaddr_in a;
	struct sock *newso;

	fd = oldso->so_fd;
	flags = oldso->so_blocked ? SOCK_NONBLOCK : 0;
	rc = so_socket6(&newso, fd, AF_INET, SOCK_STREAM, flags, 0);
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
#endif

static void
service_in_child0()
{
	assert(0);
#if 0
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
#endif
}

static void
service_in_child(int pipe_fd[2])
{
	sys_close(&pipe_fd[0]);
	service_in_child0();
	service_pipe_send(pipe_fd[1], 0);
	sys_close(&pipe_fd[1]);
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
		sys_close(&pipe_fd[0]);
		sys_close(&pipe_fd[1]);
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
			sys_close(&service_clone_pipe_fd[0]);
			sys_close(&service_clone_pipe_fd[1]);
		} else {
			service_in_parent(service_clone_pipe_fd);
		}
	}
	return rc;
}
#endif // __linux__



//========================================
struct process *
proc_add(int pid, int flag)
{
	int i;
	struct route_if *ifp;
	struct process *p;

	DLIST_FOREACH(p, &shared->shm_proc_head, ps_list) {
		if (p->ps_pid == pid) {
			current = p;
			return p;
		}
	}
	p = mem_alloc(sizeof(*p));
	memset(p->ps_percpu, 0, sizeof(p->ps_percpu));
	for (i = 0; i < CPU_NUM; ++i) {
		fd_thread_init(&p->ps_percpu[i].ps_fd_thread);
	}
	p->ps_pid = pid;
	DLIST_INSERT_TAIL(&shared->shm_proc_head, p, ps_list);
	
	current = p;

	if (flag) {
		for (i = 0; i < N_INTERFACES_MAX; ++i) {
			ifp = route_if_get(i);
			if (ifp != NULL) {
				proc_add_interface(p, ifp);
			}
		}
	}

	return p;
}

int
proc_add_interface(struct process *p, struct route_if *ifp)
{
	int rc, if_id, cpu_id, queue_id, n_queues;
	struct dev *dev;
	struct process_percpu *ppc;
	char dev_name[256];

	dbg("current_cpu_id=%d", current_cpu_id);

	if_id = ifp->rif_id;
	n_queues = ifp->rif_n_queues;
	for (queue_id = 0; queue_id < n_queues; ++queue_id) {
		cpu_id = ifp->if_queue_cpu[queue_id];
		ppc = p->ps_percpu + cpu_id;
		dev = &ppc->ps_interface_dev[if_id];

		dbg("cpu_id %d - %d", cpu_id, queue_id);

		sprintf(dev_name, "%s-%d", ifp->rif_name, queue_id);
		rc = dev_init(dev, cpu_id, dev_name, service_rssq_rxtx);
		UNUSED(rc);
		assert(rc == 0);
		dev->dev_ifp = ifp;
	}
	return 0;
}
