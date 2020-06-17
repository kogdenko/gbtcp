#include "internals.h"

#define CURMOD controller

static struct service *services[GT_SERVICES_MAX];
static int n_services;
static struct sysctl_conn *controller_listen;
static int controller_pid_fd = -1;
static int controller_quit_no_services = 1;
static int controller_done;

void
controller_host_rxtx(struct dev *dev, short revents)
{
	int i, n, rc, len;
	u_char *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
	struct dev_pkt pkt;
	struct route_if *ifp;

	ifp = container_of(dev, struct route_if, rif_host_dev);
	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			data = (u_char *)NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			rc = route_if_not_empty_txr(ifp, &pkt);
			if (rc == 0) {
				DEV_PKT_COPY(pkt.pkt_data, data, len);
				pkt.pkt_len = len;
				route_if_tx(ifp, &pkt);
			}
			DEV_RXR_NEXT(rxr);
		}
	}
}

int
controller_bypass(struct route_if *ifp, void *data, int len)
{
	int rc;
	struct dev_pkt pkt;

	rc = dev_not_empty_txr(&ifp->rif_host_dev, &pkt);
	if (rc == 0) {
		DEV_PKT_COPY(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		dev_tx(&pkt);
	}
	return rc;
}

static int
controller_clean()
{
	int i, n, rc, fd, pid, npids, again;
	uint64_t to;
	int pids[GT_SERVICES_MAX];
	DIR *dir;
	struct dirent *entry;
	struct pid_wait pw;

	again = 0;
	pid_wait_init(&pw, PID_WAIT_NONBLOCK);
	rc = sys_opendir(&dir, PID_PATH);
	if (rc) {
		goto out;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.pid", &i);
		if (rc != 1) {
			continue;
		}
		rc = pid_file_open(entry->d_name);
		if (rc < 0) {
			continue;
		}
		fd = rc;
		rc = pid_file_acquire(fd, 0);
		sys_close(fd);
		if (rc <= 0) {
			continue;
		}
		pid = rc;
		rc = pid_wait_add(&pw, pid);
		if (rc == -ENOSPC) {
			again = 1;
			break;
		} else if (rc < 0) {
			closedir(dir);
			goto out;
		}
	}
	closedir(dir);
	npids = 0;
	n = ARRAY_SIZE(pids);
	to = 3 * NSEC_SEC;
	while (to && !pid_wait_is_empty(&pw)) {
		rc = pid_wait_kill(&pw, SIGKILL, pids, n - npids);
		if (rc > 0) {
			npids += rc;
		}
		rc = pid_wait_read(&pw, &to, pids + npids, n - npids);
		if (rc > 0) {
			npids += rc;
		}
	}
	if (!pid_wait_is_empty(&pw)) {
		rc = -ETIMEDOUT;
		goto out;
	}
	rc = 0;
out:
	pid_wait_deinit(&pw);
	if (rc) {
		ERR(-rc, "failed;");
		return rc;
	} else {
		return again;
	}
}

static struct service *
controller_service_get(int pid)
{
	int i;

	for (i = 0; i < n_services; ++i) {
		if (services[i]->p_pid == pid) {
			return services[i];
		}
	}
	return NULL;
}

static void
controller_service_lock_detached(struct service *s)
{
	int rc;

	rc = spinlock_trylock(&s->p_lock);
	if (rc == 0) {
		ERR(0, "deadlocked; pid=%d", s->p_pid);
		exit(EXIT_FAILURE);
	}
}

static void
controller_service_lock(struct service *s)
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
			// Connection closed
			controller_service_lock_detached(s);
			return;
		}
	}
}

static void
controller_service_unlock(struct service *s)
{
	spinlock_unlock(&s->p_lock);
}

static void
controller_service_check_deadlock(struct service *s)
{
	controller_service_lock_detached(s);
	controller_service_unlock(s);
}

static void
controller_service_update(struct service *s)
{
	if (s == current) {
		service_update(s);
	} else {
		controller_service_lock(s);
		s->p_dirty = 1;
		controller_service_unlock(s);
	}
}

static void
controller_balance_get(struct service **ppoor, struct service **prich)
{
	int i;
	struct service *s, *poor, *rich;

	if (n_services) {
		poor = rich = services[0];
	} else {
		poor = rich = current;
	}
	for (i = 1; i < n_services; ++i) {
		s = services[i];
		if (poor->p_rss_nq > s->p_rss_nq) {
			poor = s;
		} else if (poor->p_rss_nq == s->p_rss_nq) {
			if (poor->p_tx_kpps < s->p_tx_kpps) {
				poor = s;
			}
		}
		if (rich->p_rss_nq < s->p_rss_nq) {
			rich = s;
		} else if (rich->p_rss_nq == s->p_rss_nq) {
			if (rich->p_tx_kpps > s->p_tx_kpps) {
				rich = s;
			}
		}
	}
	if (ppoor) {
		*ppoor = poor;
	}
	if (prich) {
		*prich = rich;
	}
}

static void
controller_rss_table_set(u_int rss_qid, int sid)
{
	assert(rss_qid < GT_RSS_NQ_MAX);
	assert(sid == SERVICE_ID_INVALID || sid < GT_SERVICES_MAX);
	if (shm_ih->ih_rss_table[rss_qid] != sid) {
		if (sid == SERVICE_ID_INVALID) {
			NOTICE(0, "clear; rss_qid=%d", rss_qid);
		} else {
			NOTICE(0, "hit; rss_qid=%d, pid=%d",
			       rss_qid, shm_ih->ih_services[sid].p_pid);
		}
	}
	WRITE_ONCE(shm_ih->ih_rss_table[rss_qid], sid);
}

static void
controller_balance()
{
	int i;
	struct service *poor, *rich;

	controller_balance_get(&poor, &rich);
	if (poor == current) {
		return;
	}
	if (rich->p_rss_nq == 1) {
		return;
	}
	if (poor->p_rss_nq > 0) {
		return;
	}
//	if (rich->p_kpps < 1000) {
//		return;
//	}
//	if (poor->p_kpps > (rich->p_kpps >> 3)) {
//		return;
//	}
	// TODO: find best quited qid
	for (i = 0; i < shm_ih->ih_rss_nq; ++i) {
		if (shm_ih->ih_rss_table[i] == rich->p_sid) {
			controller_rss_table_set(i, poor->p_sid);
			rich->p_rss_nq--;
			poor->p_rss_nq++;
			controller_service_update(rich);
			controller_service_update(poor);
			return;
		}
	}
}

static void
controller_service_del(struct service *s)
{
	int i;
	struct service *new;

	NOTICE(0, "hit; pid=%d", s->p_pid);
	if (s != current) {
		for (i = 0; i < n_services; ++i) {
			if (services[i] == s) {
				break;
			}
		}
		assert(i < n_services);
		services[i] = services[--n_services];
		if (!n_services) {
			if (controller_quit_no_services) {
				controller_done = 1;
			}
		}
	}
	if (s->p_rss_nq) {
		controller_balance_get(&new, NULL);
		for (i = 0; i < shm_ih->ih_rss_nq; ++i) {
			if (shm_ih->ih_rss_table[i] == s->p_sid) {
				controller_rss_table_set(i, new->p_sid);
				assert(s->p_rss_nq > 0);
				s->p_rss_nq--;
				new->p_rss_nq++;
			}
		}
		assert(s->p_rss_nq == 0);
		controller_service_update(s);
		controller_service_update(new);
	}
}

static void
controller_service_add(struct service *s, int pid, struct sysctl_conn *cp)
{
	int fd;

	assert(s != current);
	assert(n_services < ARRAY_SIZE(services));
	fd = sysctl_conn_fd(cp);
	NOTICE(0, "hit; pid=%d, fd=%d", pid, fd);
	service_init_shared(s, pid, fd);
	services[n_services++] = s;
}

static void
controller_rss_table_reduce(int rss_nq)
{
	int i, n;
	u_char id;
	struct service *s;

	n = shm_ih->ih_rss_nq;
	WRITE_ONCE(shm_ih->ih_rss_nq, rss_nq);
	for (i = rss_nq; i < n; ++i) {
		id = shm_ih->ih_rss_table[i];
		controller_rss_table_set(i, SERVICE_ID_INVALID);
		assert(id < GT_SERVICES_MAX);
		s = shm_ih->ih_services + id;
		assert(s->p_rss_nq > 0);
		s->p_rss_nq--;
		if (s->p_rss_nq == 0) {
			controller_service_update(s);
		}
	}
}

static void
controller_rss_table_expand(int rss_nq)
{
	int i; 
	struct service *s;

	controller_balance_get(&s, NULL);
	for (i = shm_ih->ih_rss_nq; i < rss_nq; ++i) {
		controller_rss_table_set(i, s->p_sid);
		s->p_rss_nq++;
	}
	WRITE_ONCE(shm_ih->ih_rss_nq, rss_nq);
}

void
controller_update_rss_table()
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
	if (shm_ih->ih_rss_nq > rss_nq) {
		controller_rss_table_reduce(rss_nq);
	} else if (shm_ih->ih_rss_nq < rss_nq)  {
		controller_rss_table_expand(rss_nq);
	}
	if (current->p_rss_nq) {
		controller_service_update(current);
	}
	for (i = 0; i < n_services; ++i) {
		s = services[i];
		if (s->p_rss_nq) {
			controller_service_update(s);
		}
	}
}

static int
sysctl_controller_service_attach(struct sysctl_conn *cp, void *udata,
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
	s = controller_service_get(pid);
	if (s != NULL) {
		return -EEXIST;
	}
	for (i = 0; i < ARRAY_SIZE(shm_ih->ih_services); ++i) {
		s = shm_ih->ih_services + i;
		if (s->p_pid == 0) {
			controller_service_add(s, pid, cp);
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
	for (; i < ARRAY_SIZE(shm_ih->ih_services); ++i) {
		if (shm_ih->ih_services[i].p_pid) {
			strbuf_addf(out, "%d", i);
			return 0;
		}
	}
	return -ENOENT;
}

static int
sysctl_controller_service_list(void *udata, const char *ident, const char *new,
	struct strbuf *out)
{
	int i;
	u_int tx_kpps;
	struct service *s;

	if (ident == NULL) {
		i = 0;
	} else {
		i = strtoul(ident, NULL, 10);
	}
	if (i >= ARRAY_SIZE(shm_ih->ih_services)) {
		return -ENOENT;
	}
	s = shm_ih->ih_services + i;
	if (!s->p_pid) {
		return -ENOENT;
	} else {
		tx_kpps = READ_ONCE(s->p_tx_kpps);
		strbuf_addf(out, "%d,%d,%u", s->p_pid, s->p_rss_nq, tx_kpps);
		return 0;
	}
}

static void
controller_service_conn_close(struct sysctl_conn *cp)
{
	int pid;
	struct service *s;

	pid = cp->scc_peer_pid;
	if (pid == 0) {
		return;
	}
	s = controller_service_get(pid);
	if (s != NULL) {
		controller_service_check_deadlock(s);
		controller_service_del(s);
		service_deinit_shared(s, 0);
	}
}

static int
controller_bind(int pid)
{
	int rc, fd;
	struct sockaddr_un a;

	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(&a, 1);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sysctl_conn_open(&controller_listen, fd);
	if (rc) {
		sys_close(fd);
		return rc;	
	}
	sys_unlink(SYSCTL_CONTROLLER_PATH);
	rc = sys_symlink(a.sun_path, SYSCTL_CONTROLLER_PATH);
	if (rc) {
		sysctl_conn_close(controller_listen);
		return rc;
	}
	controller_listen->scc_accept_conn = 1;
	controller_listen->scc_close_fn = controller_service_conn_close;
	return 0;
}

int
controller_init(int daemonize, const char *service_comm)
{
	int i, rc, pid;
	uint64_t hz;

	gt_init("controller", 0);
	gt_preload_passthru = 1;
	shm_ih = NULL;
	if (daemonize) {
		rc = sys_daemon(1, 1);
		if (rc) {
			goto err;
		}
	}
	// FIXME:
	do {
		rc = controller_clean();
	} while (rc == 1);
	if (rc) {
		goto err;
	}
	pid = getpid();
	rc = service_pid_file_acquire(CONTROLLER_SID, pid);
	if (rc < 0) {
		goto err;
	}
	controller_pid_fd = rc;
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
	shm_ih->ih_hz = hz;
	shm_ih->ih_rss_nq = 0;
	sysctl_read_file(1, service_comm);
	for (i = 0; i < ARRAY_SIZE(shm_ih->ih_rss_table); ++i) {
		shm_ih->ih_rss_table[i] = SERVICE_ID_INVALID;
	}
	current = shm_ih->ih_services + CONTROLLER_SID;
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
	sysctl_read_file(0, service_comm);
	sysctl_add(SYSCTL_CONTROLLER_SERVICE_ATTACH, SYSCTL_WR, NULL, NULL,
	           sysctl_controller_service_attach);
	sysctl_add_list(GT_SYSCTL_CONTROLLER_SERVICE_LIST, SYSCTL_RD, NULL,
	                sysctl_controller_service_list_next,
	                sysctl_controller_service_list);
	NOTICE(0, "ok; pid=%d", pid);
	return 0;
err:
	if (current != NULL) {
		service_deinit_private();
		service_deinit_shared(current, 1);
		current = NULL;
	}
	shm_deinit();
	sysctl_root_deinit();
	sys_close(controller_pid_fd);
	controller_pid_fd = -1;
	return rc;
}

void
controller_loop()
{
	while (!controller_done) {
		wait_for_fd_events();
		controller_balance();
	}
	NOTICE(0, "done;");
}
