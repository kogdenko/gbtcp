// GPL v2 License
#include "internals.h"

#define CURMOD service

#define MSG_ETHTYPE 0x0101

struct service_msg {
	uint16_t msg_type;
	uint16_t msg_ifindex;
	be16_t msg_orig_type;
	struct eth_addr msg_orig_saddr;
	struct eth_addr msg_orig_daddr;
};

static struct spinlock service_attach_lock;
static int service_sysctl_fd = -1;
static int service_pid_fd = -1;
static struct dev service_redirect_dev;
static int service_rcu_max;
static int service_signal_guard = 1;
static int service_autostart_controller = 1;
static struct dlist service_rcu_active_head;
static struct dlist service_rcu_shadow_head;
static u_int service_rcu[GT_SERVICES_MAX];

extern struct shm_hdr *shared;
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
service_peer_send(int fd, int msg)
{
	send_record(fd, &msg, sizeof(msg), MSG_NOSIGNAL);
}

static int
service_peer_recv(int fd)
{
	int rc, msg;
	uint64_t to;

	to = 4 * NSEC_SEC;
	rc = read_timed(fd, &msg, sizeof(msg), &to);
	if (rc == 0) {
		ERR(0, "Service peer closed");
		return -EPIPE;
	} else if (rc == sizeof(msg)) {
		if (msg >= 0) {
			if (msg > 0) {
				ERR(msg, "Service peer error");
			}
			return msg;
		} else {
			rc = msg;
			ERR(-rc, "Service peer failed");
			return rc;
		}
	} else if (rc > 0) {
		ERR(0, "Service peer truncated (%d) reply ", rc);
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
		service_peer_send(pipe_fd[1], rc);
		sys_close(pipe_fd[1]);
		if (rc == 0) {
			controller_start(0);
		}
		exit(EXIT_SUCCESS);
	} else if (rc > 0) {
		// Child process created by fork() become zombie after daemon()
		sys_waitpid(-1, NULL, 0);
		sys_close(pipe_fd[1]);
		rc = service_peer_recv(pipe_fd[0]);
		sys_close(pipe_fd[0]);
	}
	return rc;
}

static int
service_start_controller(const char *p_comm)
{
	int rc;

	NOTICE(0, "Starting controller");
	rc = service_start_controller_nolog(p_comm);
	if (rc < 0) {
		ERR(-rc, "Failed to start controller");
	} else if (rc > 0) {
		WARN(rc, "Unable to start controller due to initialization error");
	} else {
		NOTICE(0, "Controller started");
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
redirect_dev_transmit5(struct route_if *ifp, int msg_type, u_char sid, const void *data, int len)
{
	int rc;
	struct dev_pkt pkt;

	rc = dev_get_tx_packet(&service_redirect_dev, &pkt);
	if (rc == 0) {
		memcpy(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		pkt.pkt_sid = sid;
		redirect_dev_transmit(ifp, msg_type, &pkt);
	}
	return rc;
}

static void
service_rssq_rx(struct dev *dev, void *data, int len)
{
	int in, rc;
	u_char sid;
	struct in_context p;
	struct route_if *ifp;

	ifp = dev->dev_ifp;
	in_context_init(&p, data, len);
	p.in_ifp = ifp;
	p.in_tcps = &current->p_tcps;
	p.in_udps = &current->p_udps;
	p.in_ips = &current->p_ips;
	p.in_icmps = &current->p_icmps;
	p.in_arps = &current->p_arps;
	in = service_rx(&p);
	if (in == IN_BYPASS) {
		if (current->p_sid == CONTROLLER_SID) {
			transmit_to_host(ifp, data, len);
		} else {
			rc = redirect_dev_transmit5(ifp, SERVICE_MSG_BYPASS,
				CONTROLLER_SID, data, len);
			if (rc) {
				// TODO: increment counter
			}
		}
	} else if (in >= 0) {
		current->p_ips.ips_delivered++;
		sid = in;
		rc = redirect_dev_transmit5(ifp, SERVICE_MSG_RX, sid, data, len);
		if (rc) {
			counter64_inc(&ifp->rif_rx_drop);
			return;
		}
	} else if (in == IN_OK) {
		current->p_ips.ips_delivered++;
	}
	counter64_inc(&ifp->rif_rx_pkts);
	counter64_add(&ifp->rif_rx_bytes, len);
}

static void
service_redirect_dev_rx(struct dev *dev, void *data, int len)
{
	int rc, dst_sid;
	struct tcp_stat tcps;
	struct udp_stat udps;
	struct ip_stat ips;
	struct icmp_stat icmps;
	struct arp_stat arps;
	struct eth_hdr *eh;
	struct route_if *ifp;
	struct service_msg *msg;
	struct in_context p;
	struct dev_pkt pkt;

	if (len < sizeof(*eh)) {
		// TODO: counter
	}
	eh = data;
	if (eh->eh_type != MSG_ETHTYPE) {
		return;
	}
	if (len < sizeof(*msg) + sizeof(*eh)) {
		// TODO: counter
		return;
	}
	dst_sid = eh->eh_daddr.ea_bytes[5];
	if (dst_sid != current->p_sid) {
		// TODO: counter
		return;
	}
	msg = (struct service_msg *)((u_char *)data + len - sizeof(*msg));
	ifp = route_if_get_by_index(msg->msg_ifindex);
	if (ifp == NULL) {
		return;
	}
	eh->eh_type = msg->msg_orig_type;
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
		rc = route_get_tx_packet(ifp, &pkt, 0);
		if (rc == 0) {
			memcpy(pkt.pkt_data, data, len);
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

#ifdef HAVE_VALE
static int
service_init_shared_redirect_dev(struct service *s)
{
	return 0;
}

static void
service_deinit_shared_redirect_dev(struct service *s)
{
}

static void
service_redirect_dev_init(struct service *s)
{
	int rc;
	char buf[IFNAMSIZ];

	snprintf(buf, sizeof(buf), "vale_gt:%d", s->p_pid);
	rc = dev_init(&service_redirect_dev, buf, DEV_QUEUE_NONE, service_redirect_dev_rx);
	return rc;
}
#else // HAVE_VALE
static void
service_peer_rx(struct dev *dev, void *data, int len)
{
	int rc;
	u_char dst_sid, src_sid;
	struct eth_hdr *eh;
	struct dev_pkt pkt;
	struct service *s;

	if (len < sizeof(*eh)) {
		// TODO: counter
		return;
	}
	eh = data;
	if (eh->eh_type != MSG_ETHTYPE) {
		return;
	}
	s = container_of(dev, struct service, p_veth_peer);
	src_sid = s->p_sid;
	dst_sid = eh->eh_daddr.ea_bytes[5];
	if (dst_sid >= GT_SERVICES_MAX || service_get_by_sid(dst_sid)->p_pid == 0) {
		// TODO: counter
		dbg("BAD Packet ?????");
		return;
	}
	// TODO: check dst_sid
	if (dst_sid == src_sid) {
		return;
	}
	if (dst_sid == current->p_sid) {
		service_redirect_dev_rx(NULL, data, len);
		return;
	}
	s = shared->shm_services + dst_sid;
	if (s->p_pid == 0) {
		return;
	}
	rc = dev_get_tx_packet(&s->p_veth_peer, &pkt);
	if (rc == 0) {
		DEV_PKT_COPY(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		dev_transmit(&pkt);
	}
}

#define SERVICE_VETHF "gtv%c%d"

static int
service_init_shared_redirect_dev(struct service *s)
{
	int i, rc, added, ifindex, flags;
	char ifname[2][IFNAMSIZ];

	added = 0;
	snprintf(ifname[0], IFNAMSIZ, SERVICE_VETHF, 's', s->p_pid);
	snprintf(ifname[1], IFNAMSIZ, SERVICE_VETHF, 'c', s->p_pid);
	rc = netlink_veth_add(ifname[0], ifname[1]);
	if (rc < 0) {
		goto err;
	}
	added = 1;
	for (i = 0; i < ARRAY_SIZE(ifname); ++i) {
		rc = sys_if_nametoindex(ifname[i]);
		if (rc < 0) {
			goto err;
		}
		ifindex = rc;
		rc = netlink_link_get_flags(ifindex);
		if (rc < 0) {
			goto err;
		}
		flags = rc;
		rc = netlink_link_up(ifindex, ifname[i], flags);
		if (rc < 0) {
			goto err;
		}
	}
	rc = dev_init(&s->p_veth_peer, ifname[1], 0, service_peer_rx);
	if (rc < 0) {
		goto err;
	}
	return rc;
err:
	ERR(-rc, "Failed to create device for redirecting packets");
	if (added) {
		netlink_link_del(ifname[1]);
	}
	return rc;
}

static void
service_deinit_shared_redirect_dev(struct service *s)
{
	char peer[IFNAMSIZ];

	dev_deinit(&s->p_veth_peer);
	snprintf(peer, sizeof(peer), SERVICE_VETHF, 'c', s->p_pid);
	netlink_link_del(peer);
}

static int
service_redirect_dev_init(struct service *s)
{
	int rc;
	char buf[IFNAMSIZ];

	snprintf(buf, sizeof(buf), SERVICE_VETHF, 's', s->p_pid);
	rc = dev_init(&service_redirect_dev, buf, 0, service_redirect_dev_rx);
	return rc;
}
#endif // HAVE_VALE

int
service_init_shared(struct service *s, int pid, int fd)
{
	int i, rc;

	assert(current->p_sid == CONTROLLER_SID && "Controller should call this function");
	s->p_pid = pid;
	dlist_init(&s->p_tx_head);
	s->p_sid = s - shared->shm_services;
	s->p_need_update_rss_bindings = 0;
	s->p_rss_nq = 0;
	s->p_rr_redir = 0;
	s->p_fd = fd;
	service_store_epoch(s, 1);
	s->p_start_time = shared_ns();
	s->p_okpps = 0;
	s->p_okpps_time = 0;
	s->p_opkts = 0;
	assert(s->p_mbuf_garbage_max == 0);
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		dlist_init(s->p_mbuf_garbage_head + i);
	}
	rc = init_timers(s);
	if (rc) {
		goto err;
	}
	rc = service_init_arp(s);
	if (rc) {
		goto err;
	}
	rc = init_files(s);
	if (rc) {
		goto err;
	}
	rc = service_init_tcp(s);
	if (rc) {
		goto err;
	}
	rc = service_init_shared_redirect_dev(s);
	if (rc) {
		goto err;
	}
	return 0;
err:
	service_deinit_shared(s, 0);
	return rc;
}

void
service_deinit_shared(struct service *s, int full)
{
	int i;
	struct dlist tofree;
	struct dev *dev;
	struct route_if *ifp;

	assert(current->p_sid == CONTROLLER_SID);
	service_deinit_shared_redirect_dev(s);
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

	dlist_init(&service_rcu_active_head);
	dlist_init(&service_rcu_shadow_head);
	service_rcu_max = 0;
	memset(service_rcu, 0, sizeof(service_rcu));
	rc = service_redirect_dev_init(current);
	return rc;
}

void
service_deinit_private()
{
	dev_deinit(&service_redirect_dev);
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
	// Check (current != NULL) again under the lock
	if (current != NULL) {
		spinlock_unlock(&service_attach_lock);
		return 0;
	}
	pid = getpid();
	rc = read_proc_comm(p_comm, pid);
	if (rc) {
		goto err;
	}
	gt_init(p_comm, 0);
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(&a);
	if (rc < 0) {
		goto err;
	}
	service_sysctl_fd = rc;
	rc = sysctl_connect(service_sysctl_fd);
	if (rc) {
		WARN(0, "Failed connect to controller");
		if (!service_autostart_controller) {
			goto err;
		}
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
	rc = service_pid_file_acquire(current->p_sid, pid);
	if (rc < 0) {
		goto err;
	}
	service_pid_fd = rc;
	rc = service_init_private();
	if (rc) {
		goto err;
	}
	ERR(0, "Service attached");
	spinlock_unlock(&service_attach_lock);
	return 0;
err:
	service_detach();
	ERR(-rc, "Failed to attach service");
	spinlock_unlock(&service_attach_lock);
	return rc;
}

void
service_detach()
{
	int i;
	struct dev *dev;
	struct route_if *ifp;

	service_deinit_private();
	sys_close(service_sysctl_fd);
	service_sysctl_fd = -1;
	sys_close(service_pid_fd);
	service_pid_fd = -1;
	if (current != NULL) {
		ROUTE_IF_FOREACH(ifp) {
			for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
				dev = &(ifp->rif_dev[current->p_sid][i]);
				// FIXME: Do we really need this ???
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
	NOTICE(0, "Service detached");
}

static void
service_rcu_reload()
{
	int i;
	struct service *s;

	dlist_replace_init(&service_rcu_active_head, &service_rcu_shadow_head);
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		s = shared->shm_services + i;
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
		s = shared->shm_services + i;
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
service_update_rss_binding(struct route_if *ifp, int queue_id)
{
	int id, ifflags;
	struct dev *dev;

	ifflags = READ_ONCE(ifp->rif_flags);
	id = READ_ONCE(shared->shm_rss_table[queue_id]);
	dev = &(ifp->rif_dev[current->p_sid][queue_id]);
	if ((ifflags & IFF_UP) && id == current->p_sid) {
		if (!dev_is_inited(dev)) {
			dev_init(dev, ifp->rif_name, queue_id, service_rssq_rx);
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
		for (i = 0; i < ifp->rif_rss_queue_num; ++i) {
			service_update_rss_binding(ifp, i);
		}
	}
	current->p_need_update_rss_bindings = 0;
}

int
service_can_connect(struct route_if *ifp, be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	int i, sid, rss_qid;
	uint32_t h;

	if (ifp->rif_rss_queue_num == 1) {
		return 1;
	}
	rss_qid = -1;
	for (i = 0; i < ifp->rif_rss_queue_num; ++i) {
		sid = READ_ONCE(shared->shm_rss_table[i]);
		if (sid == current->p_sid) {
			if (rss_qid == -1) {
				h = rss_hash4(laddr, faddr, lport, fport,
				              ifp->rif_rss_key);
				rss_qid = h % ifp->rif_rss_queue_num;
			}
			if (i == rss_qid) {
				return 1;
			}
		}
	}
	return 0;
}

int
redirect_dev_get_tx_packet(struct route_if *ifp, struct dev_pkt *pkt)
{
	int i, n, rc;
	u_char s[GT_RSS_NQ_MAX];

	n = 0;
	for (i = 0; i < ifp->rif_rss_queue_num; ++i) {
		s[n] = READ_ONCE(shared->shm_rss_table[i]);
		if (s[n] != SERVICE_ID_INVALID) {
			n++;
		}
	}
	if (n == 0) {
		return -ENODEV;
	}
	rc = dev_get_tx_packet(&service_redirect_dev, pkt);
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
redirect_dev_transmit(struct route_if *ifp, int msg_type, struct dev_pkt *pkt)
{
	struct eth_hdr *eh;
	struct service_msg *msg;

	msg = (struct service_msg *)((u_char *)pkt->pkt_data + pkt->pkt_len);
	eh = (struct eth_hdr *)pkt->pkt_data;
	msg->msg_orig_type = eh->eh_type;
	msg->msg_orig_saddr = eh->eh_saddr;
	msg->msg_orig_daddr = eh->eh_daddr;
	eh->eh_type = MSG_ETHTYPE;
	memset(eh->eh_saddr.ea_bytes, 0, sizeof(eh->eh_saddr));
	memset(eh->eh_daddr.ea_bytes, 0, sizeof(eh->eh_daddr));
	eh->eh_saddr.ea_bytes[5] = current->p_sid;
	assert(pkt->pkt_sid < GT_SERVICES_MAX);
	eh->eh_daddr.ea_bytes[5] = pkt->pkt_sid;
	msg->msg_type = msg_type;
	msg->msg_ifindex = ifp->rif_index;
	pkt->pkt_len += sizeof(*msg);
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
	// Wait to service_in_child() done
	// NOTE: Unlock to not catch deadlock with controller.
	// See controller_process() scheduler part.
	SERVICE_UNLOCK;
	service_peer_recv(pipe_fd[0]);
	SERVICE_LOCK;
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
	INFO(0, "service: Duplicate socket, fd=%d", fd);
	return 0;
err:
	WARN(-rc, "service: Failed to duplicate socket, fd=%d", fd);
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
	rc = service_attach();
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
	NOTICE(0, "This is service child process");
	sys_close(pipe_fd[0]);
	service_in_child0();
	service_peer_send(pipe_fd[1], 0);
	sys_close(pipe_fd[1]);
}

int
service_fork()
{
	int rc, pipe_fd[2];

	NOTICE(0, "service: fork()");
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
	NOTICE(0, "service: clone('%s')", log_add_clone_flags(flags));
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
