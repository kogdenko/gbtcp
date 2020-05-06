// GPL2 license
#include "internals.h"

struct init_mod {
	struct log_scope log_scope;
};

#define MOD_FOREACH(x, a0, a1) \
	x(sysctl, a0, a1) \
	x(log, a0, a1) \
	x(proc, a0, a1) \
	x(subr, a0, a1) \
	x(pid, a0, a1) \
	x(poll, a0, a1) \
	x(epoll, a0, a1) \
	x(sys, a0, a1) \
	x(mbuf, a0, a1) \
	x(htable, a0, a1) \
	x(timer, a0, a1) \
	x(fd_event, a0, a1) \
	x(signal, a0, a1) \
	x(dev, a0, a1) \
	x(api, a0, a1) \
	x(lptree, a0, a1) \
	x(route, a0, a1) \
	x(arp, a0, a1) \
	x(file, a0, a1) \
	x(inet, a0, a1) \
	x(sockbuf, a0, a1) \
	x(tcp, a0, a1)

#define MOD_ENUM(name, a0, a1) MOD_##name,

#define MOD_INIT(name, log, a1) \
	if (rc == 0) { \
		rc = name##_mod_init(log, &(ih)->ih_mods[MOD_##name]); \
	}

#define MOD_ATTACH(name, log, a1) \
	if (rc == 0) { \
		rc = name##_mod_attach(log, (ih)->ih_mods[MOD_##name]); \
	}

#define PROC_INIT(name, log, p) \
	if (rc == 0) { \
		rc = name##_proc_init(log, p); \
	}

#define MOD_DEINIT(name, log, a1) \
	name##_mod_deinit(log, (ih)->ih_mods[MOD_##name]);

#define MOD_DETACH(name, log, a1) \
	name##_mod_detach(log);

enum {
	MOD_FOREACH(MOD_ENUM, 0, 0)
	MOD_COUNT_MAX
};

struct proc *current;

static struct spinlock service_init_lock;
static int service_fd = -1;
static struct sysctl_conn *controller_cp;
static struct init_hdr *ih;
static struct init_mod *curmod;

#define IH_VERSION 2

struct init_hdr {
	int ih_version;
	int ih_rss_nq;
	uint64_t ih_HZ;
	void *ih_mods[MOD_COUNT_MAX];
	union {
		struct proc ih_procs[GT_SERVICE_COUNT_MAX + 1];
		struct {
			struct proc ih_controller;
			struct proc ih_services[GT_SERVICE_COUNT_MAX];
		};
	};
	int ih_rss[GT_RSS_NQ_MAX];
};

int
proc_mod_init(struct log *log, void **pp)
{
	int rc;
	struct init_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "init");
	}
	return rc;
}
int
proc_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

int
proc_proc_init(struct log *log, struct proc *p)
{
	return 0;
}

void
proc_mod_deinit(struct log *log, void *raw_mod)
{
	struct init_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
proc_mod_detach(struct log *log)
{
	curmod = NULL;
}

static void
mod_foreach_mod_deinit(struct log *log)
{
	MOD_FOREACH(MOD_DEINIT, log, 0);
}

static int
mod_foreach_mod_init(struct log *log)
{
	int rc;

	rc = 0;
	MOD_FOREACH(MOD_INIT, log, 0);
	if (rc) {
		mod_foreach_mod_deinit(log);
	}
	return rc;
}

static void
mod_foreach_mod_detach(struct log *log)
{
	MOD_FOREACH(MOD_DETACH, log, 0);
}

static int
mod_foreach_mod_attach(struct log *log)
{
	int rc;

	ASSERT(current != NULL);
	rc = 0;
	MOD_FOREACH(MOD_ATTACH, log, 0);
	if (rc) {
		mod_foreach_mod_detach(log);
	}
	return rc;
}

static void
mod_foreach_proc_deinit(struct log *log, struct proc *proc)
{
}

static int
mod_foreach_proc_init(struct log *log, struct proc *proc)
{
	int rc;

	rc = 0;
	MOD_FOREACH(PROC_INIT, log, proc);
	if (rc) {
		mod_foreach_proc_deinit(log, proc);
	}
	return rc;
}

void
proc_init()
{
	dlsym_all();
	rdtsc_update_time();
	log_init_early();
}

static int
controller_lock(struct log *log)
{
	int rc, fd;
	const char *path;

	LOG_TRACE(log);
	path = GT_PREFIX"/controller.lock";
	rc = sys_open(log, path, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		die(log, -rc, "open('%s') failed;", path);
	}
	fd = rc;
	rc = sys_flock(log, fd, LOCK_EX);
	if (rc < 0) {
		die(log, -rc, "flock('%s') failed", path);
	}
	return fd;
}

static void
controller_unlock(struct log *log, int fd)
{
	sys_close(log, fd);
}

static int
sleep_compute_HZ()
{
	int rc;
	uint64_t t0, t1, HZ;
	struct timespec ts, rem;

	ts.tv_sec = 0;
	ts.tv_nsec = 10 * 1000 * 1000;
	t0 = rdtsc();
restart:
	rc = nanosleep(&ts, &rem);
	if (rc == -1) {
		if (errno == EINTR) {
			memcpy(&ts, &rem, sizeof(ts));
			goto restart;
		} else {
			return -errno;
		}
	}
	t1 = rdtsc();
	HZ = (t1 - t0) * 100;
	mHZ = HZ / 1000000;
	return 0;
}

static int
can_connect(struct log *log, int pid)
{
	int rc, fd;
	uint64_t to;
	struct sockaddr_un a;

	LOG_TRACE(log);
	rc = sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sysctl_make_sockaddr_un(&a, pid);
	to = 0;
	rc = connect_timed(log, fd, (struct sockaddr *)&a, sizeof(a), &to);
	sys_close(log, fd);
	if (rc == 0 || rc == -ETIMEDOUT) {
		return 1;
	} else {
		sys_unlink(log, a.sun_path);
		return 0;
	}
}

static int
controller_kill_all(struct log *log)
{
	int i, rc, pid, npids, enospc;
	uint64_t to;
	int pids[PIDWAIT_NENTRIES_MAX];
	struct sockaddr_un a;
	DIR *dir;
	struct dirent *entry;
	struct pidwait pw;

	LOG_TRACE(log);
restart:
	enospc = 0;
	pidwait_init(log, &pw, PIDWAIT_NONBLOCK);
	rc = sys_opendir(log, &dir, SYSCTL_PATH);
	if (rc) {
		return rc;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.sock", &pid);
		if (rc != 1) {
			continue;
		}
		rc = can_connect(log, pid);
		if (rc < 0) {
			closedir(dir);
			return rc;
		} else if (rc) {
			rc = pidwait_add(log, &pw, pid);
			if (rc == -ENOSPC) {
				enospc = 1;
				break;
			}
		}
	}
	closedir(dir);
	npids = 0;
	to = 3 * NANOSECONDS_SECOND;
	while (to && !pidwait_is_empty(&pw)) {
		rc = pidwait_kill(log, &pw, SIGKILL,
		                  pids, ARRAY_SIZE(pids) - npids);
		rc = pidwait_read(log, &pw, &to,
		                  pids + npids, ARRAY_SIZE(pids) - npids);
		if (rc > 0) {
			npids += rc;
		}
	}
	for (i = 0; i < npids; ++i) {
		sysctl_make_sockaddr_un(&a, pids[i]);
		sys_unlink(log, a.sun_path);
	}
	if (!pidwait_is_empty(&pw)) {
		LOGF(log, LOG_ERR, -ETIMEDOUT, "failed");
		return -ETIMEDOUT;
	}
	pidwait_deinit(log, &pw);
	if (enospc) {
		goto restart;
	}
	return 0;
}

static int
controller_service_lock(struct log *log, struct proc *s)
{
	spinlock_lock(&s->p_lock);
	return 0;
}

static void
controller_service_unlock(struct proc *s)
{
	spinlock_unlock(&s->p_lock);
}

int
get_rss_nq()
{
	return ih->ih_rss_nq;
}

int
controller_service_activate(struct log *log, struct proc *s)
{
	int i, rc;

	for (i = 0; i < ih->ih_rss_nq; ++i) {
		if (ih->ih_rss[i] == 0) {
			rc = controller_service_lock(log, s);
			if (rc == 0) {
				s->p_rss_qid = i;
				controller_service_unlock(s);
			}
			ih->ih_rss[i] = s->p_pid;
			return 1;
		}
	}
	return 0;
}

void
controller_set_rss_nq(struct log *log, int rss_nq)
{
	int i, rc, fd, rss_nq_old;
	struct proc *s;

	LOG_TRACE(log);
	fd = controller_lock(log);
	rss_nq_old = ih->ih_rss_nq;
	ASSERT(rss_nq_old != rss_nq);
	ih->ih_rss_nq = rss_nq;
	if (rss_nq == 0) {
		for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
			s = ih->ih_services + i;
			if (s->p_rss_qid >= 0) {
				ASSERT(s->p_rss_qid < rss_nq_old);
				ASSERT(ih->ih_rss[s->p_rss_qid] == s->p_pid);
				ih->ih_rss[s->p_rss_qid] = 0;
				rc = controller_service_lock(log, s);
				if (rc == 0) {
					s->p_rss_qid = -1;
					controller_service_unlock(s);
				}
			}
		}
		for (i = 0; i < rss_nq_old; ++i) {
			ASSERT(ih->ih_rss[i] == 0);
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
			s = ih->ih_services + i;
			if (s->p_pid != 0 && s->p_active) {
				rc = controller_service_activate(log, s);
				if (rc) {
					break;
				}
			}
		}	
	}
	controller_unlock(log, fd);
}

static void
controller_close_service(struct log *log, struct sysctl_conn *cp)
{
	int pid;

	pid = cp->sccn_peer_pid;
	if (pid) {
		dbg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!! %d", pid);
	}
}

static int
sysctl_proc_service_activate(struct log *log, void *udata,
	const char *new, struct strbuf *old)
{
	int i, rc, fd, pid;
	struct proc *s;

	if (new == NULL) {
		return 0;
	}
	rc = -ENOENT;
	fd = controller_lock(log);
	pid = strtoul(new, NULL, 10);
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		s = ih->ih_services + i;
		if (s->p_pid == pid) {
			rc = 0;
			controller_service_activate(log, s);
			break;	
		}
	}
	controller_unlock(log, fd);
	return rc;
}

static int
controller_bind(struct log *log, int pid)
{
	int rc, fd;
	struct sockaddr_un a;

	sysctl_add_int(log, SYSCTL_PROC_CONTROLLER_PID, SYSCTL_RD,
	               &ih->ih_controller.p_pid, 0, 0);
	sysctl_add(log, SYSCTL_PROC_SERVICE_ACTIVATE, SYSCTL_WR,
	           NULL, NULL, sysctl_proc_service_activate);
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(log, &a, 1);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sysctl_conn_open(log, &controller_cp, fd);
	if (rc) {
		sys_close(log, fd);
		return rc;	
	}
	sys_unlink(log, SYSCTL_CONTROLLER_PATH);
	rc = sys_symlink(log, a.sun_path, SYSCTL_CONTROLLER_PATH);
	if (rc) {
		sysctl_conn_close(log, controller_cp);
	}
	controller_cp->sccn_is_listen = 1;
	controller_cp->sccn_close_fn = controller_close_service;
	return rc;
}

int
controller_init(int daemonize, const char *proc_name)
{
	int i, rc, pid;
	struct log *log;
	struct proc *proc;

	log = log_trace0();
	if (daemonize) {
		rc = sys_daemon(log, 0, 1);
		if (rc) {
			return rc;
		}
	}
	rc = controller_kill_all(log);
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
	rc = mod_foreach_mod_init(log);
	if (rc) {
		goto err;
	}
	pid = getpid();
	ih->ih_version = IH_VERSION;
	ih->ih_HZ = sleep_compute_HZ();
	for (i = 0; i < ARRAY_SIZE(ih->ih_procs); ++i) {
		proc = ih->ih_procs + i;
		mod_foreach_proc_init(log, proc);
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		ih->ih_services[i].p_service_id = i;
	}
	current = &ih->ih_controller;
	current->p_pid = pid;
	rc = mod_foreach_mod_attach(log);
	if (rc) {
		goto err;
	}
	sysctl_read_file(log, proc_name);
	rc = controller_bind(log, pid);
	if (rc) {
		goto err;
	}
	return 0;
err:
	if (current != NULL) {
		current->p_pid = 0;
		current = NULL;
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_procs); ++i) {
		proc = ih->ih_procs + i;
		mod_foreach_proc_deinit(log, proc);
	}
	mod_foreach_mod_deinit(log);
	mod_foreach_mod_detach(log);
	shm_deinit(log);
	sysctl_root_deinit(log);
	return rc;
}

void
controller_loop()
{
	while (1) {
		gt_fd_event_mod_wait();
	}
}

static int
service_fork_controller(struct log *log, const char *proc_name)
{
	int rc, pipe_fd[2];
	uint64_t to;
	int msg;

	LOG_TRACE(log);
	rc = sys_pipe(log, pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork(log);
	if (rc < 0) {
		return rc;
	} else if (rc == 0) {
		api_locked = 100;
		log = log_trace0();
		sys_close(log, pipe_fd[0]);
		rc = controller_init(1, proc_name);
		send_full_buf(log, pipe_fd[1], &rc, sizeof(rc), MSG_NOSIGNAL);
		sys_close(log, pipe_fd[1]);
		if (rc == 0) {
			controller_loop();
		}
		return rc;
	}
	to = 4 * NANOSECONDS_SECOND;
	rc = read_timed(log, pipe_fd[0], &msg, sizeof(msg), &to);
	if (rc == 0) {
		LOGF(log, LOG_ERR, 0, "controller peer closed;");
		rc = -EPIPE;
	} else if (rc == 4) {
		if (msg == 0) {
			rc = 0;
			LOGF(log, LOG_ERR, 0, "controller ok;");
		} else if (msg > 0) {
			rc = -EINVAL;
			LOGF(log, LOG_ERR, 0,
			     "controller invalid reply; msg=%d", msg);
		} else {
			rc = msg;
			LOGF(log, LOG_ERR, -rc, "controller failed;");
		}
	} else if (rc > 0) {
		LOGF(log, LOG_ERR, 0,
		     "controller truncated reply; len=%d", rc);
		return -EINVAL;
	}
	sys_close(log, pipe_fd[0]);
	sys_close(log, pipe_fd[1]);
	return rc;
}

int
service_attach(struct log *log, const char *proc_name)
{
	int rc, pid;
	uint64_t to;
	struct sockaddr_un a;

	rc = shm_attach(log, (void **)&ih);
	dbg("ih=%p", ih);
	if (rc) {
		return rc;
	}
	if (ih->ih_version != IH_VERSION) {
		return -EINVAL;
	}
	pid = ih->ih_controller.p_pid;
	sysctl_make_sockaddr_un(&a, pid);
	to = 2 * NANOSECONDS_SECOND;
	rc = connect_timed(log, service_fd,
	                   (struct sockaddr *)&a, sizeof(a), &to);
	if (rc == 0) {
		LOGF(log, LOG_NOTICE, 0, "attached; pid=%d", pid);
	}
	return rc;
}

int
service_init_locked(struct log *log)
{
	int i, rc, pid;
	struct sockaddr_un a;
	char proc_name[PROC_NAME_SIZE_MAX];
	char buf[GT_SYSCTL_BUFSIZ];
	struct timeval tv;

	// Check again under the lock
	if (current != NULL) {
		return 0;
	}
	srand48(time(NULL));
	pid = getpid();
	rc = proc_get_name(log, proc_name, pid);
	if (rc) {
		return rc;
	}
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(log, &a, 0);
	if (rc < 0) {
		return rc;
	}
	service_fd = rc;
	for (i = 0; i < 3; ++i) {
		if (i == 0) {
			rc = 0;
		} else {
			rc = service_fork_controller(log, proc_name);
		}
		if (rc == 0) {
			rc = service_attach(log, proc_name);
			if (rc == 0) {
				break;
			}
		}
	}
	if (rc) {
		goto err;
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		current = ih->ih_services + i;
		if (current->p_pid == 0) {
			break;
		}
	}
	if (current->p_pid) {
		rc = -ENOENT;
		goto err;
	}
	rc = sysctl_req(log, service_fd, SYSCTL_PROC_CONTROLLER_PID, buf, "");
	if (rc < 0) {
		goto err;
	}
	current->p_pid = pid;
	current->p_rss_qid = -1;
	current->p_rss_qid_saved = -1;
	strzcpy(current->p_name, proc_name, sizeof(current->p_name));
	gettimeofday(&tv, NULL);
	rc = mod_foreach_mod_attach(log);
	if (rc) {
		goto err;
	}
	return 0;
err:
	if (service_fd >= 0) {
		sys_close(log, service_fd);
		service_fd = -1;
	}
	if (current != NULL) {
		current->p_pid = 0;
		current = NULL;
	}
	mod_foreach_mod_detach(log);
	shm_detach(log);
	return rc;
}

int
service_init()
{
	int rc, fd;
	struct log *log;

	assert(api_locked == 0);
	api_locked++;
	spinlock_lock(&service_init_lock);
	proc_init();
	ASSERT(current == NULL);
	log = log_trace0();
	LOGF(log, LOG_INFO, 0, "Hit;");
	fd = controller_lock(log);
	rc = service_init_locked(log);
	if (rc) {
		LOGF(log, LOG_ERR, -rc, "failed;");
	} else {
		LOGF(log, LOG_INFO, 0, "ok; current=%p", current);
	}
	controller_unlock(log, fd);
	spinlock_unlock(&service_init_lock);
	api_locked--;
	return rc;
}

int
service_activate(struct log *log)
{
	int rc;
	char buf[GT_SYSCTL_BUFSIZ];

	if (current->p_active) {
		return 0;
	}
	current->p_active = 1;
	if (current->p_rss_qid >= 0) {
		return 0;
	}
	LOG_TRACE(log);
	snprintf(buf, sizeof(buf), "%d", current->p_pid);
	SERVICE_UNLOCK;
	rc = sysctl_req(log, service_fd,
	                SYSCTL_PROC_SERVICE_ACTIVATE, buf, buf);
	SERVICE_LOCK;
	return rc;
}

void
service_deinit(struct log *log)
{
}

void
rdtsc_update_time()
{
	uint64_t t, ns;

	t = rdtsc();
	ns = 1000 * t / mHZ;
	// tsc can fall after suspend
	if (ns > nanoseconds) {
		nanoseconds = ns;
	}
}
