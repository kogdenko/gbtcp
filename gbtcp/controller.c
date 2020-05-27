#include "internals.h"

struct controller_mod {
	struct log_scope log_scope;
};

static struct controller_mod *curmod;
static struct service *services[GT_SERVICES_MAX];
static int nservices;
static struct sysctl_conn *controller_listen;
static int controller_pid_fd = -1;
static int controller_done;

struct init_hdr *ih;

int
controller_mod_init(void **pp)
{
	int rc;
	struct controller_mod *mod;

	rc = shm_malloc(pp, sizeof(*mod));
	if (rc == 0) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "controller");
		mod->log_scope.lgs_level = LOG_NOTICE;
	}
	return rc;
}

int
controller_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
controller_mod_deinit(void *raw_mod)
{
	struct controller_mod *mod;

	mod = raw_mod;
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
controller_mod_detach()
{
	curmod = NULL;
}

static int
controller_terminate()
{
	int i, n, rc, fd, pid, npids, again;
	uint64_t to;
	int pids[GT_SERVICES_MAX];
	struct sockaddr_un a;
	DIR *dir;
	struct dirent *entry;
	struct pid_wait pw;

	again = 0;
	pid_wait_init(&pw, PID_WAIT_NONBLOCK);
	rc = sys_opendir(&dir, PID_PATH);
	if (rc) {
		return rc;
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
	to = 3 * NANOSECONDS_SECOND;
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
	for (i = 0; i < npids; ++i) {
		sysctl_make_sockaddr_un(&a, pids[i]);
		sys_unlink(a.sun_path);
	}
	if (pid_wait_is_empty(&pw)) {
		INFO(0, "ok;");
		rc = 0;
	} else {
		ERR(ETIMEDOUT, "failed;");
		rc = -ETIMEDOUT;
	}
out:
	pid_wait_deinit(&pw);
	if (rc) {
		return rc;
	} else {
		return again;
	}
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
controller_service_lock_detached(struct service *s)
{
	int rc;

	rc = spinlock_trylock(&s->p_lock);
	if (rc == 0) {
		die(0, "deadlocked; pid=%d", s->p_pid);
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
		if (rc < 0 && rc != -EAGAIN) {
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

	if (nservices) {
		poor = rich = services[0];
	} else {
		poor = rich = current;
	}
	for (i = 1; i < nservices; ++i) {
		s = services[i];
		if (poor->p_rss_nq > s->p_rss_nq) {
			poor = s;
		} else if (poor->p_rss_nq == s->p_rss_nq) {
			if (poor->p_kpps < s->p_kpps) {
				poor = s;
			}
		}
		if (rich->p_rss_nq < s->p_rss_nq) {
			rich = s;
		} else if (rich->p_rss_nq == s->p_rss_nq) {
			if (rich->p_kpps > s->p_kpps) {
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
controller_rss_table_set(u_int rss_qid, int service_id)
{
	ASSERT(rss_qid < GT_RSS_NQ_MAX);
	ASSERT(service_id == -1 || service_id < GT_SERVICES_MAX);
	if (ih->ih_rss_table[rss_qid] != service_id) {
		NOTICE(0, "hit; rss_qid=%d, pid=%d",
		       rss_qid, ih->ih_services[service_id].p_pid);
	}
	WRITE_ONCE(ih->ih_rss_table[rss_qid], service_id);
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
	for (i = 0; ih->ih_rss_nq; ++i) {
		if (ih->ih_rss_table[i] == rich->p_id) {
			controller_rss_table_set(i, poor->p_id);
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
		for (i = 0; i < nservices; ++i) {
			if (services[i] == s) {
				break;
			}
		}
		ASSERT(i < nservices);
		services[i] = services[--nservices];
		if (!nservices) {
			controller_done = 1;
		}
	}
	if (s->p_rss_nq) {
		controller_balance_get(&new, NULL);
		for (i = 0; i < ih->ih_rss_nq; ++i) {
			if (ih->ih_rss_table[i] == s->p_id) {
				controller_rss_table_set(i, new->p_id);
				ASSERT(s->p_rss_nq > 0);
				s->p_rss_nq--;
				new->p_rss_nq++;
			}
		}
		ASSERT(s->p_rss_nq == 0);
		controller_service_update(s);
		controller_service_update(new);
	}
}

static void
controller_service_add(struct service *s, int pid, struct sysctl_conn *cp)
{
	int fd;

	ASSERT(s != current);
	ASSERT(nservices < ARRAY_SIZE(services));
	fd = sysctl_conn_fd(cp);
	NOTICE(0, "hit; pid=%d, fd=%d", pid, fd);
	services[nservices++] = s;
	s->p_pid = pid;
	s->p_dirty = 0;
	s->p_rss_nq = 0;
	s->p_fd = fd;
	if (current->p_rss_nq) {
		ASSERT(nservices == 1);
		controller_service_del(current);
	}
}

static void
controller_rss_table_reduce(int rss_nq)
{
	int i, n;
	u_char id;
	struct service *s;

	n = ih->ih_rss_nq;
	WRITE_ONCE(ih->ih_rss_nq, rss_nq);
	for (i = rss_nq; i < n; ++i) {
		id = ih->ih_rss_table[i];
		controller_rss_table_set(i, -1);
		ASSERT(id < GT_SERVICES_MAX);
		s = ih->ih_services + id;
		ASSERT(s->p_rss_nq > 0);
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
	for (i = ih->ih_rss_nq; i < rss_nq; ++i) {
		controller_rss_table_set(i, s->p_id);
		s->p_rss_nq++;
	}
	WRITE_ONCE(ih->ih_rss_nq, rss_nq);
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
	if (ih->ih_rss_nq > rss_nq) {
		controller_rss_table_reduce(rss_nq);
	} else if (ih->ih_rss_nq < rss_nq)  {
		controller_rss_table_expand(rss_nq);
	}
	if (current->p_rss_nq) {
		controller_service_update(current);
	}
	for (i = 0; i < nservices; ++i) {
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
		i = 1;
	} else {
		i = strtoul(ident, NULL, 10) + 1;
		if (i < 1) {
			i = 1;
		}
	}
	for (; i < ARRAY_SIZE(ih->ih_services); ++i) {
		if (ih->ih_services[i].p_pid) {
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
	struct service *s;

	if (ident == NULL) {
		i = 1;
	} else {
		i = strtoul(ident, NULL, 10);
	}
	if (i < 1 || i >= ARRAY_SIZE(ih->ih_services)) {
		return -ENOENT;
	}
	s = ih->ih_services + i;
	if (!s->p_pid) {
		return -ENOENT;
	} else {
		strbuf_addf(out, "%d,%d,%u", s->p_pid, s->p_rss_nq, s->p_kpps);
		return 0;
	}
}

static void
controller_service_clean(struct service *s)
{
	int i;
	struct dev *dev;
	struct route_if *ifp;

	NOTICE(0, "hit; pid=%d", s->p_pid);
	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
			dev = &(ifp->rif_dev[s->p_id][i]);
			dev_clean(dev);
		}
	}
	s->p_pid = 0;
}

static void
controller_service_conn_close(struct sysctl_conn *cp)
{
	int pid;
	struct service *s;

	pid = cp->sccn_peer_pid;
	if (pid == 0) {
		return;
	}
	s = controller_service_get(pid);
	if (s != NULL) {
		controller_service_check_deadlock(s);
		controller_service_del(s);
		controller_service_clean(s);
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
	}
	controller_listen->sccn_accept_conn = 1;
	controller_listen->sccn_close_fn = controller_service_conn_close;
	return rc;
}

int
controller_init(int daemonize, const char *service_comm)
{
	int i, rc, pid;
	uint64_t hz;
	struct service *s;

	gt_preload_passthru = 1;
	ih = NULL;
	if (daemonize) {
		rc = sys_daemon(0, 1);
		if (rc) {
			goto err;
		}
	}
	do {
		rc = controller_terminate();
	} while (rc == 1);
	if (rc) {
		goto err;
	}
	pid = getpid();
	rc = pid_file_open("0.pid");
	if (rc < 0) {
		return rc;
	}
	controller_pid_fd = rc;
	rc = pid_file_acquire(controller_pid_fd, pid);
	if (rc != pid) {
		goto err;
	}	

	rc = sysctl_root_init();
	if (rc) {
		goto err;
	}
	rc = shm_init((void **)&ih, sizeof(*ih));
	if (rc) {
		goto err;
	}
	memset(ih, 0, sizeof(*ih));
	rc = mod_foreach_mod_init(ih);
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
		mod_foreach_mod_service_init(s);
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_rss_table); ++i) {
		ih->ih_rss_table[i] = -1;
	}
	current = ih->ih_services + 0;
	current->p_pid = pid;
	rc = mod_foreach_mod_attach(ih);
	if (rc) {
		goto err;
	}
	rc = service_init("controller");
	if (rc) {
		goto err;
	}
	sysctl_read_file(service_comm);
	rc = controller_bind(pid);
	if (rc) {
		goto err;
	}
	sysctl_add(SYSCTL_CONTROLLER_SERVICE_ATTACH, SYSCTL_WR, NULL, NULL,
	           sysctl_controller_service_attach);
	sysctl_add_list(GT_SYSCTL_CONTROLLER_SERVICE_LIST, SYSCTL_RD, NULL,
	                sysctl_controller_service_list_next,
	                sysctl_controller_service_list);
	NOTICE(0, "ok; pid=%d", pid);
	return 0;
err:
	if (current != NULL) {
		current->p_pid = 0;
		current = NULL;
	}
	if (ih != NULL) {
		for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
			s = ih->ih_services + i;
			mod_foreach_mod_service_deinit(s);
		}
	}
	service_deinit(0);
	mod_foreach_mod_detach();
	mod_foreach_mod_deinit(ih);
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
}
