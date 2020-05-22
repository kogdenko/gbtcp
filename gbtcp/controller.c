#include "internals.h"

struct controller_mod {
	struct log_scope log_scope;
};

static struct controller_mod *curmod;
static struct service *services[GT_SERVICE_COUNT_MAX];
static int nservices;
static struct sysctl_conn *controller_listen;
static struct pid_file controller_pid_file;

struct init_hdr *ih;

#define controller (ih->ih_services)



static int
controller_terminate(struct log *log)
{
	int i, n, rc, pid, npids, again;
	uint64_t to;
	int pids[GT_SERVICE_COUNT_MAX];
	struct sockaddr_un a;
	DIR *dir;
	struct dirent *entry;
	struct pid_wait pw;

	LOG_TRACE(log);
restart:
	again = 0;
	pid_wait_init(log, &pw, PID_WAIT_NONBLOCK);
	rc = sys_opendir(log, &dir, SYSCTL_PATH);
	if (rc) {
		return rc;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.sock", &pid);
		if (rc != 1) {
			continue;
		}
		rc = sysctl_can_connect(log, pid);
		if (rc < 0) {
			closedir(dir);
			goto out;
		} else if (rc) {
			rc = pid_wait_add(log, &pw, pid);
			if (rc == -ENOSPC) {
				again = 1;
				break;
			} else if (rc < 0) {
				closedir(dir);
				goto out;
			}
		}
	}
	closedir(dir);
	npids = 0;
	n = ARRAY_SIZE(pids);
	to = 3 * NANOSECONDS_SECOND;
	while (to && !pid_wait_is_empty(&pw)) {
		rc = pid_wait_kill(log, &pw, SIGKILL, pids, n - npids);
		if (rc > 0) {
			npids += rc;
		}
		rc = pid_wait_read(log, &pw, &to, pids + npids, n - npids);
		if (rc > 0) {
			npids += rc;
		}
	}
	for (i = 0; i < npids; ++i) {
		sysctl_make_sockaddr_un(&a, pids[i]);
		sys_unlink(log, a.sun_path);
	}
	if (pid_wait_is_empty(&pw)) {
		rc = 0;
	} else {
		LOGF(log, LOG_ERR, -ETIMEDOUT, "failed;");
		rc = -ETIMEDOUT;
	}
out:
	pid_wait_deinit(log, &pw);
	if (rc == 0 && again) {
		goto restart;
	}
	return rc;
}

static struct service *
controller_service_get(int pid)
{
	int i;

	for (i = 0; i < nservices; ++i) {
		if (services[i]->p_pid == pid) {
			return services[i];
		}
	}
	return NULL;
}

static void
controller_service_lock_detached(struct log *log, struct service *s)
{
	int rc;

	rc = spinlock_trylock(&s->p_lock);
	if (rc == 0) {
		die(log, 0, "Deadlock!!!; pid=%d", s->p_pid);
	}
}

static void
controller_service_lock(struct log *log, struct service *s)
{
	int i, x, rc, fd;

	LOG_TRACE(log);
	fd = s->p_fd[P_CONTROLLER];
	while (1) {
		for (i = 0; i < 1000; ++i) {
			rc = spinlock_trylock(&s->p_lock);
			if (rc) {
				return;
			}
			cpu_pause();
		}
		rc = sys_recv(log, fd, &x, 1, MSG_PEEK|MSG_DONTWAIT);
		if (rc <= 0) {
			// Connection closed
			controller_service_lock_detached(log, s);
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
controller_service_check_deadlock(struct log *log, struct service *s)
{
	controller_service_lock_detached(log, s);
	controller_service_unlock(s);
}

static void
controller_service_update_rss_table(struct log *log, struct service *s)
{
	if (s == controller) {
		service_update_rss_table(log, s);
	} else {
		controller_service_lock(log, s);
		s->p_dirty_rss_table = 1;
		controller_service_unlock(s);
	}
}

static void
controller_balance_get(struct service **ppoor, struct service **prich)
{
	int i;
	struct service *s, *poor, *rich;

	if (nservices) {
		poor = rich = services[0];
	} else {
		poor = rich = controller;
	}
	for (i = 1; i < nservices; ++i) {
		s = services[i];
		if (poor->p_rss_nq > s->p_rss_nq) {
			poor = s;
		} else if (poor->p_rss_nq == s->p_rss_nq) {
			if (poor->p_pps < s->p_pps) {
				poor = s;
			}
		}
		if (rich->p_rss_nq < s->p_rss_nq) {
			rich = s;
		} else if (rich->p_rss_nq == s->p_rss_nq) {
			if (rich->p_pps > s->p_pps) {
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
controller_service_del(struct log *log, struct service *s)
{
	int i;
	struct service *x;

	LOG_TRACE(log);
	NOTICE(0, "hit; pid=%d", s->p_pid);
	if (s != controller) {
		for (i = 0; i < nservices; ++i) {
			if (services[i] == s) {
				break;
			}
		}
		ASSERT(i < nservices);
		services[i] = services[--nservices];
	}
	if (s->p_rss_nq) {
		controller_balance_get(&x, NULL);
		for (i = 0; i < ih->ih_rss_nq; ++i) {
			if (ih->ih_rss_table[i] == s->p_id) {
				WRITE_ONCE(ih->ih_rss_table[i], x->p_id);
				ASSERT(s->p_rss_nq > 0);
				s->p_rss_nq--;
				x->p_rss_nq++;
			}
		}
		ASSERT(s->p_rss_nq == 0);
		controller_service_update_rss_table(log, x);
	} 
}

static void
controller_service_add(struct log *log, struct service *s, int pid)
{
	ASSERT(s != controller);
	ASSERT(nservices < ARRAY_SIZE(services));
	dbg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	NOTICE(0, "hit; pid=%d", pid);
	services[nservices++] = s;
	s->p_pid = pid;
	s->p_dirty_rss_table = 0;
	s->p_rss_nq = 0;
	if (controller->p_rss_nq) {
		ASSERT(nservices == 1);
		LOG_TRACE(log);
		controller_service_del(log, controller);
	}
}

static void
controller_rss_table_reduce(struct log *log, int rss_nq)
{
	int i, n;
	u_char id;
	struct service *s;

	n = ih->ih_rss_nq;
	WRITE_ONCE(ih->ih_rss_nq, rss_nq);
	for (i = rss_nq; i < n; ++i) {
		id = ih->ih_rss_table[i];
		WRITE_ONCE(ih->ih_rss_table[i], -1);
		ASSERT(id < GT_SERVICE_COUNT_MAX);
		s = ih->ih_services + id;
		ASSERT(s->p_rss_nq > 0);
		s->p_rss_nq--;
		if (s->p_rss_nq == 0) {
			controller_service_update_rss_table(log, s);
		}
	}
}

static void
controller_rss_table_expand(struct log *log, int rss_nq)
{
	int i; 
	struct service *s;

	controller_balance_get(&s, NULL);
	for (i = ih->ih_rss_nq; i < rss_nq; ++i) {
		WRITE_ONCE(ih->ih_rss_table[i], s->p_id);
		s->p_rss_nq++;
	}
	WRITE_ONCE(ih->ih_rss_nq, rss_nq);
}

void
controller_update_rss_table(struct log *log)
{
	int i, rss_nq;
	struct route_if *ifp;
	struct service *s;

	LOG_TRACE(log);
	rss_nq = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_flags & IFF_UP) {
			if (rss_nq < ifp->rif_rss_nq) {
				rss_nq = ifp->rif_rss_nq;
			}
		}
	}
	if (ih->ih_rss_nq > rss_nq) {
		controller_rss_table_reduce(log, rss_nq);
	} else if (ih->ih_rss_nq < rss_nq)  {
		controller_rss_table_expand(log, rss_nq);
	}
	if (controller->p_rss_nq) {
		controller->p_dirty_rss_table = 1;
	}
	for (i = 0; i < nservices; ++i) {
		s = services[i];
		if (s->p_rss_nq) {
			controller_service_update_rss_table(log, s);
		}
	}
}

static int
sysctl_controller_service_init(struct log *log, struct sysctl_conn *cp,
	void *udata, const char *new, struct strbuf *old)
{
	int i, fd, pid;
	struct service *s;

	if (new == NULL) {
		return 0;
	}
	if (cp == NULL || cp->sccn_peer_pid == 0) {
		return -EPERM;
	}
	pid = cp->sccn_peer_pid;
	s = controller_service_get(pid);
	if (s != NULL) {
		return -EEXIST;
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		s = ih->ih_services + i;
		if (s->p_pid == 0) {
			controller_service_add(log, s, pid);
			fd = sysctl_conn_fd(cp);
			s->p_fd[P_CONTROLLER] = fd;
			return 0;
		}
	}
	return -ENOENT;
}

static void
controller_service_conn_close(struct log *log, struct sysctl_conn *cp)
{
	int pid;
	struct service *s;

	pid = cp->sccn_peer_pid;
	if (pid == 0) {
		return;
	}
	LOG_TRACE(log);
	s = controller_service_get(pid);
	if (s != NULL) {
		controller_service_check_deadlock(log, s);
		controller_service_del(log, s);
		service_clean_rss_table(s);
		s->p_pid = 0;
	}
}

static int
controller_bind(struct log *log, int pid)
{
	int rc, fd;
	struct sockaddr_un a;

	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(log, &a, 1);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sysctl_conn_open(log, &controller_listen, fd);
	if (rc) {
		sys_close(log, fd);
		return rc;	
	}
	sys_unlink(log, SYSCTL_CONTROLLER_PATH);
	rc = sys_symlink(log, a.sun_path, SYSCTL_CONTROLLER_PATH);
	if (rc) {
		sysctl_conn_close(log, controller_listen);
	}
	controller_listen->sccn_accept_conn = 1;
	controller_listen->sccn_close_fn = controller_service_conn_close;
	return rc;
}

int
controller_init(int daemonize, const char *p_comm)
{
	int i, rc, pid;
	uint64_t hz;
	struct log *log;
	struct service *s;

	api_locked = 1;
	log = log_trace0();
	pid = getpid();
	controller_pid_file.pf_name = "controller.pid";
	rc = pid_file_open(log, &controller_pid_file);
	if (rc) {
		return rc;
	}
	rc = pid_file_acquire(log, &controller_pid_file, pid);
	if (rc != pid) {
		return rc;
	}	
	if (daemonize) {
		rc = sys_daemon(log, 0, 1);
		if (rc) {
			return rc;
		}
	}
	rc = controller_terminate(log);
	if (rc) {
		return rc;
	}
	rc = sysctl_root_init(log);
	if (rc) {
		goto err;
	}
	rc = shm_init(log, (void **)&ih, sizeof(*ih));
	if (rc) {
		goto err;
	}
	memset(ih, 0, sizeof(*ih));
	rc = mod_foreach_mod_init(log, ih);
	if (rc) {
		goto err;
	}
	hz = sleep_compute_hz();
	set_hz(hz);
	ih->ih_version = IH_VERSION;
	ih->ih_hz = hz;
	ih->ih_rss_nq = 0;
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		s = ih->ih_services + i;
		s->p_id = i;
		mod_foreach_mod_service_init(log, s);
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_rss_table); ++i) {
		ih->ih_rss_table[i] = -1;
	}
	current = controller;
	current->p_pid = pid;
	rc = mod_foreach_mod_attach(log, ih);
	if (rc) {
		goto err;
	}
	sysctl_read_file(log, p_comm);
	rc = controller_bind(log, pid);
	if (rc) {
		goto err;
	}
	sysctl_add(log, SYSCTL_CONTROLLER_SERVICE_INIT, SYSCTL_WR,
	           NULL, NULL, sysctl_controller_service_init);
	LOGF(log, LOG_NOTICE, 0, "ok; pid=%d", pid);
	return 0;
err:
	if (current != NULL) {
		current->p_pid = 0;
		current = NULL;
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		s = ih->ih_services + i;
		mod_foreach_mod_service_deinit(log, s);
	}
	mod_foreach_mod_detach(log);
	mod_foreach_mod_deinit(log, ih);
	shm_deinit(log);
	sysctl_root_deinit(log);
	pid_file_close(log, &controller_pid_file);
	return rc;
}

void
controller_loop()
{
	while (1) {
		wait_for_fd_events();
	}
}
