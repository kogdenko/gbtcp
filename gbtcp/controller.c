// gpl2
#include "internals.h"

#define CURMOD controller

static struct sysctl_conn *controller_conn;
static int controller_pid_fd = -1;
static int sid_max = 0;
static int quit_no_services = 1;

int controller_done;

static struct service *
service_get_by_pid(int pid)
{
	int i;

	for (i = 0; i <= sid_max; ++i) {
		if (shared->shm_services[i].p_pid == pid) {
			return shared->shm_services + i;
		}
	}
	return NULL;
}

static void
host_rx_one(struct route_if *ifp, void *data, int len)
{
	int rc;
	struct dev_pkt pkt;

	rc = route_not_empty_txr(ifp, &pkt, TX_CAN_RECLAIM|TX_CAN_REDIRECT);
	if (rc == 0) {
		DEV_PKT_COPY(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		route_transmit(ifp, &pkt);
	}
}

void
host_rxtx(struct dev *dev, short revents)
{
	int i, n;
	void *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
	struct route_if *ifp;

	ifp = container_of(dev, struct route_if, rif_host_dev);
	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			host_rx_one(ifp, data, slot->len);
			DEV_RXR_NEXT(rxr);
		}
	}
}

int
transmit_to_host(struct route_if *ifp, void *data, int len)
{
	int rc;
	struct dev_pkt pkt;

	rc = dev_not_empty_txr(&ifp->rif_host_dev, &pkt, TX_CAN_RECLAIM);
	if (rc == 0) {
		DEV_PKT_COPY(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		dev_transmit(&pkt);
	}
	return rc;
}

static int
controller_clean_kill(int fd)
{
	int rc, pid;

	rc = pid_file_acquire(fd, 0);
	if (rc <= 0) {
		return rc;
	}
	pid = rc;
	rc = sys_kill(pid, SIGKILL);
	if (rc == 0) {
		rc = sys_flock(fd, LOCK_EX);
		if (rc < 0) {
			return rc;
		}
	} else if (rc == -ESRCH) {
		rc = 0;
	}
	return rc;
}

static int
controller_clean()
{
	int rc, fd, id;
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *entry;

	rc = sys_opendir(&dir, PID_PATH);
	if (rc) {
		return rc;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.pid", &id);
		if (rc != 1 || id == CONTROLLER_SID) {
			continue;
		}
		snprintf(path, sizeof(path), "%s/%s", PID_PATH, entry->d_name);
		rc = pid_file_open(path);
		if (rc < 0) {
			sys_closedir(dir);
			return rc;
		}
		fd = rc;
		rc = controller_clean_kill(fd);
		if (rc) {
			sys_closedir(dir);
			return rc;
		}
		sys_unlink(path);
	}
	sys_closedir(dir);
	rc = sys_opendir(&dir, SYSCTL_SOCK_PATH);
	if (rc) {
		return rc;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.sock", &id);
		if (rc == 1) {
			snprintf(path, sizeof(path), "%s/%s",
			         SYSCTL_SOCK_PATH, entry->d_name);
			sys_unlink(path);
		}
	}
	sys_closedir(dir);
	return 0;
}

static void
controller_lock_service(struct service *s)
{
	int rc;

	rc = spinlock_trylock(&s->p_lock);
	if (rc == 0) {
		ERR(0, "deadlocked; pid=%d", s->p_pid);
		exit(69);
	}
}

static void
controller_lock_service_safe(struct service *s)
{
	int i, b, rc;

	while (1) {
		for (i = 0; i < 1000; ++i) {
			rc = spinlock_trylock(&s->p_lock);
			if (rc) {
				return;
			}
			cpu_pause();
		}
		rc = sys_recv(s->p_fd, &b, sizeof(b), MSG_PEEK|MSG_DONTWAIT);
		if (rc == 0 || (rc < 0 && rc != -EAGAIN)) {
			// connection closed - service not running
			controller_lock_service(s);
			return;
		}
	}
}

static void
controller_unlock_service(struct service *s)
{
	spinlock_unlock(&s->p_lock);
}

static void
controller_check_service_deadlock(struct service *s)
{
	controller_lock_service(s);
	controller_unlock_service(s);	
}

static void
update_rss_bindings(struct service *s)
{
	if (s == current) {
		service_update_rss_bindings(s);
	} else {
		controller_lock_service_safe(s);
		s->p_need_update_rss_bindings = 1;
		controller_unlock_service(s);
	}
}

static void
controller_sched_alg(struct service **ppick, struct service **pkick)
{
	int i;
	struct service *s, *pick, *kick;
	
	pick = kick = NULL;
	for (i = 1; i <= sid_max; ++i) {
		s = shared->shm_services + i;
		if (s->p_pid) {
			if (pick == NULL ||
			    pick->p_rss_nq > s->p_rss_nq) {
				pick = s;
			}
			if (kick == NULL ||
			    kick->p_rss_nq < s->p_rss_nq) {
				kick = s;
			}
		}
	}
	if (pick == NULL) {
		pick = current;
	}
	if (kick == NULL || current->p_rss_nq) {
		kick = current;
	} else {
		if (kick->p_rss_nq <= pick->p_rss_nq + 1 &&
		    kick->p_start_time >= pick->p_start_time) {
			// do not preempt
			kick = pick;
		}
	}
	if (ppick != NULL) {
		*ppick = pick;
	}
	if (pkick != NULL) {
		*pkick = kick;
	}
}

static void
set_rss_binding(u_int rss_qid, int sid)
{
	assert(rss_qid < GT_RSS_NQ_MAX);
	assert(sid == SERVICE_ID_INVALID || sid < GT_SERVICES_MAX);
	if (shared->shm_rss_table[rss_qid] != sid) {
		if (sid == SERVICE_ID_INVALID) {
			NOTICE(0, "clear; rss_qid=%d", rss_qid);
		} else {
			NOTICE(0, "hit; rss_qid=%d, pid=%d",
			       rss_qid, shared->shm_services[sid].p_pid);
		}
	}
	WRITE_ONCE(shared->shm_rss_table[rss_qid], sid);
}

static void
controller_sched_balance()
{
	int i;
	struct service *pick, *kick;

	controller_sched_alg(&pick, &kick);
	if (pick == current ||
	    pick == kick ||
	    kick->p_rss_nq == 0) {
		return;
	}
	for (i = 0; i < shared->shm_rss_nq; ++i) {
		if (shared->shm_rss_table[i] == kick->p_sid) {
			set_rss_binding(i, pick->p_sid);
			kick->p_rss_nq--;
			pick->p_rss_nq++;
			update_rss_bindings(kick);
			update_rss_bindings(pick);
			return;
		}
	}
}

static void
controller_del_service(struct service *s)
{
	int i, sid, rss_nq;
	struct sockaddr_un a;
	struct service *new;

	NOTICE(0, "hit; pid=%d", s->p_pid);
	sid = s->p_sid;
	rss_nq = s->p_rss_nq;
	controller_check_service_deadlock(s);
	sysctl_make_sockaddr_un(&a, s->p_pid);
	sys_unlink(a.sun_path);
	service_deinit_shared(s, 0);
	sid_max = 0;
	SERVICE_FOREACH(s) {
		if (s->p_pid) {
			sid_max = MAX(sid_max, s->p_sid);
		}
	}
	if (rss_nq) {
		controller_sched_alg(&new, NULL);
		for (i = 0; i < shared->shm_rss_nq; ++i) {
			if (shared->shm_rss_table[i] == sid) {
				set_rss_binding(i, new->p_sid);
				assert(rss_nq > 0);
				rss_nq--;
				new->p_rss_nq++;
			}
		}
		assert(rss_nq == 0);
		update_rss_bindings(new);
	}
	if (sid_max == 0 && quit_no_services) {
		controller_done = 1;
	}
}

static void
controller_add_service(struct service *s, int pid, struct sysctl_conn *cp)
{
	int fd;

	assert(s != current);
	fd = sysctl_conn_fd(cp);
	NOTICE(0, "hit; pid=%d, fd=%d", pid, fd);
	service_init_shared(s, pid, fd);
	sid_max = MAX(sid_max, s->p_sid);
}

static void
rss_table_reduce(int rss_nq)
{
	int i, n;
	u_char id;
	struct service *s;

	n = shared->shm_rss_nq;
	WRITE_ONCE(shared->shm_rss_nq, rss_nq);
	for (i = rss_nq; i < n; ++i) {
		id = shared->shm_rss_table[i];
		set_rss_binding(i, SERVICE_ID_INVALID);
		assert(id < GT_SERVICES_MAX);
		s = shared->shm_services + id;
		assert(s->p_rss_nq > 0);
		s->p_rss_nq--;
		if (s->p_rss_nq == 0) {
			update_rss_bindings(s);
		}
	}
}

static void
rss_table_expand(int rss_nq)
{
	int i; 
	struct service *s;

	controller_sched_alg(&s, NULL);
	for (i = shared->shm_rss_nq; i < rss_nq; ++i) {
		set_rss_binding(i, s->p_sid);
		s->p_rss_nq++;
	}
	WRITE_ONCE(shared->shm_rss_nq, rss_nq);
}

void
update_rss_table()
{
	int i, rss_nq;
	struct route_if *ifp;
	struct service *s;

	rss_nq = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_flags & IFF_UP) {
			if (rss_nq < ifp->rif_rss_nq) {
				rss_nq = ifp->rif_rss_nq;
			}
		}
	}
	if (shared->shm_rss_nq > rss_nq) {
		rss_table_reduce(rss_nq);
	} else if (shared->shm_rss_nq < rss_nq)  {
		rss_table_expand(rss_nq);
	}
	if (current->p_rss_nq) {
		update_rss_bindings(current);
	}
	for (i = 0; i <= sid_max; ++i) {
		s = shared->shm_services + i;
		if (s->p_pid && s->p_rss_nq) {
			update_rss_bindings(s);
		}
	}
}

static int
sysctl_controller_add(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *old)
{
	int i, pid;
	struct service *s;

	if (new == NULL) {
		return 0;
	}
	if (cp == NULL || cp->scc_peer_pid == 0) {
		return -EPERM;
	}
	pid = cp->scc_peer_pid;
	s = service_get_by_pid(pid);
	if (s != NULL) {
		return -EEXIST;
	}
	for (i = 0; i < ARRAY_SIZE(shared->shm_services); ++i) {
		s = shared->shm_services + i;
		if (s->p_pid == 0) {
			controller_add_service(s, pid, cp);
			return 0;
		}
	}
	return -ENOENT;
}

static int
sysctl_controller_service_list_next(void *udata, const char *ident,
	struct strbuf *out)
{
	int i;

	if (ident == NULL) {
		i = 0;
	} else {
		i = strtoul(ident, NULL, 10) + 1;
	}
	for (; i < ARRAY_SIZE(shared->shm_services); ++i) {
		if (shared->shm_services[i].p_pid) {
			strbuf_addf(out, "%d", i);
			return 0;
		}
	}
	return -ENOENT;
}

static int
sysctl_controller_service_list(void *udata, const char *ident,
	const char *new, struct strbuf *out)
{
	int i;
	u_int okpps;
	struct service *s;

	if (ident == NULL) {
		i = 0;
	} else {
		i = strtoul(ident, NULL, 10);
	}
	if (i >= ARRAY_SIZE(shared->shm_services)) {
		return -ENOENT;
	}
	s = shared->shm_services + i;
	if (!s->p_pid) {
		return -ENOENT;
	} else {
		okpps = READ_ONCE(s->p_okpps);
		strbuf_addf(out, "%d,%d,%u", s->p_pid, s->p_rss_nq, okpps);
		return 0;
	}
}

static void
service_conn_close(struct sysctl_conn *cp)
{
	int pid;
	struct service *s;

	pid = cp->scc_peer_pid;
	if (pid == 0) {
		return;
	}
	s = service_get_by_pid(pid);
	if (s != NULL) {
		controller_del_service(s);
	}
}

static int
controller_bind(int pid)
{
	int rc, fd;
	struct sockaddr_un a;

	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(&a);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sys_listen(fd, 0);
	if (rc) {
		sys_close(fd);
		return rc;
	}
	rc = sysctl_conn_open(&controller_conn, fd);
	if (rc) {
		sys_close(fd);
		return rc;	
	}
	sys_unlink(SYSCTL_CONTROLLER_PATH);
	rc = sys_symlink(a.sun_path, SYSCTL_CONTROLLER_PATH);
	if (rc) {
		sysctl_conn_close(controller_conn);
		return rc;
	}
	controller_conn->scc_accept_conn = 1;
	controller_conn->scc_close_fn = service_conn_close;
	return 0;
}

static void
controller_unbind(int pid)
{
	struct sockaddr_un a;

	sysctl_conn_close(controller_conn);
	controller_conn = NULL;
	sysctl_make_sockaddr_un(&a, pid);
	sys_unlink(a.sun_path);
	sys_unlink(SYSCTL_CONTROLLER_PATH);
}

int
controller_init(int daemonize, const char *service_comm)
{
	int i, rc, pid;
	uint64_t hz;

	gt_init("controller", 0);
	gt_preload_passthru = 1;
	shared = NULL;
	if (daemonize) {
		rc = sys_daemon(1, 1);
		if (rc) {
			goto err;
		}
	}
	pid = getpid();
	rc = service_pid_file_acquire(CONTROLLER_SID, pid);
	if (rc < 0) {
		goto err;
	}
	controller_pid_fd = rc;
	rc = controller_clean();
	if (rc) {
		goto err;
	}
	rc = sysctl_root_init();
	if (rc) {
		goto err;
	}
	rc = shm_init();
	if (rc) {
		goto err;
	}
	hz = sleep_compute_hz();
	set_hz(hz);
	shared->shm_hz = hz;
	shared->shm_rss_nq = 0;
	rc = sysctl_read_file(1, service_comm);
	if (rc) {
		goto err;
	}
	for (i = 0; i < ARRAY_SIZE(shared->shm_rss_table); ++i) {
		shared->shm_rss_table[i] = SERVICE_ID_INVALID;
	}
	current = shared->shm_services + CONTROLLER_SID;
	rc = service_init_shared(current, pid, 0);
	if (rc) {
		goto err;
	}
	rc = service_init_private();
	if (rc) {
		goto err;
	}
	rc = controller_bind(pid);
	if (rc) {
		goto err;
	}
	rc = sysctl_read_file(0, service_comm);
	if (rc) {
		goto err;
	}
	sysctl_add(SYSCTL_CONTROLLER_ADD, SYSCTL_WR, NULL, NULL,
	           sysctl_controller_add);
	sysctl_add_list(GT_SYSCTL_CONTROLLER_SERVICE_LIST, SYSCTL_RD, NULL,
	                sysctl_controller_service_list_next,
	                sysctl_controller_service_list);
	NOTICE(0, "ok;");
	return 0;
err:
	ERR(-rc, "failed;");
	controller_deinit();
	return rc;
}

void
controller_deinit()
{
	int pid;

	pid = getpid();
	controller_unbind(pid);
	if (current != NULL) {
		service_deinit_private();
		service_deinit_shared(current, 1);
		current = NULL;
	}
	shm_deinit();
	sysctl_root_deinit();
	sys_close(controller_pid_fd);
	controller_pid_fd = -1;
}

void
controller_process()
{
	rd_nanoseconds();
	WRITE_ONCE(shared->shm_ns, nanoseconds);
	wait_for_fd_events();
	if (1) {
		controller_sched_balance();
	}

}
