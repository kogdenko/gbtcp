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

#define MOD_INIT(name, log, ih) \
	if (rc == 0) { \
		rc = name##_mod_init(log, &(ih)->ih_mods[MOD_##name]); \
	}

#define MOD_ATTACH(name, log, ih) \
	if (rc == 0) { \
		rc = name##_mod_attach(log, (ih)->ih_mods[MOD_##name]); \
	}

#define PROC_INIT(name, log, p) \
	if (rc == 0) { \
		rc = name##_proc_init(log, p); \
	}

#define MOD_DEINIT(name, log, ih) \
	name##_mod_deinit(log, (ih)->ih_mods[MOD_##name]);

#define MOD_DETACH(name, log, ih) \
	name##_mod_detach(log);

enum {
	MOD_FOREACH(MOD_ENUM, 0, 0)
	MOD_COUNT_MAX
};

struct proc *current;

static struct spinlock init_lock;
static int service_fd = -1;
static struct sysctl_conn binded;
static struct init_mod *curmod;

#define IH_VERSION 2

struct init_hdr {
	int ih_version;
	uint64_t ih_HZ;
	void *ih_mods[MOD_COUNT_MAX];
	union {
		struct proc ih_procs[GT_SERVICE_COUNT_MAX + 1];
		struct {
			struct proc ih_controller;
			struct proc ih_services[GT_SERVICE_COUNT_MAX];
		};
	};
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
mod_foreach_mod_deinit(struct log *log, struct init_hdr *ih)
{
	MOD_FOREACH(MOD_DEINIT, log, ih);
}

static int
mod_foreach_mod_init(struct log *log, struct init_hdr *ih)
{
	int rc;

	rc = 0;
	MOD_FOREACH(MOD_INIT, log, ih);
	if (rc) {
		mod_foreach_mod_deinit(log, ih);
	}
	return rc;
}

static void
mod_foreach_mod_detach(struct log *log, struct init_hdr *ih)
{
	MOD_FOREACH(MOD_DETACH, log, ih);
}

static int
mod_foreach_mod_attach(struct log *log, struct init_hdr *ih)
{
	int rc;

	rc = 0;
	MOD_FOREACH(MOD_ATTACH, log, ih);
	if (rc) {
		mod_foreach_mod_detach(log, ih);
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
kill_all(struct log *log)
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
controller_sysctl_accept(struct log *log, struct sysctl_conn *lp)
{
	int rc, fd, pid;
	struct sysctl_conn *cp;

	rc = sysctl_conn_accept(log, lp, &pid);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sys_malloc(log, (void **)&cp, sizeof(*cp));
	if (rc) {
		sys_close(log, fd);
		return rc;
	}
	rc = sysctl_conn_open(log, cp, fd);
	if (rc) {
		dbg("!!");
		sys_close(log, fd);
		sys_free(cp);
		return rc;
	}
	dbg("fd %d, pid %d", fd, pid);
	return 0;
}

static int
controller_bind(struct log *log, int pid)
{
	int rc, fd;
	struct sockaddr_un a;

	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(log, &a);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sys_listen(log, fd, 5);
	if (rc < 0) {
		goto err;
	}
	sys_unlink(log, SYSCTL_CONTROLLER_PATH);
	rc = sys_symlink(log, a.sun_path, SYSCTL_CONTROLLER_PATH);
	if (rc) {
		goto err;
	}
	rc = sysctl_conn_open(log, &binded, fd);
	if (rc) {
		goto err;
	}
	binded.sccn_accept_fn = controller_sysctl_accept;
	return 0;
err:
	sys_close(log, fd);
	return rc;
}

int
proc_controller_init(struct log *log, int daemonize, const char *proc_name)
{
	int i, rc, pid;
	struct init_hdr *ih;
	struct proc *proc;

	dlsym_all();
	rdtsc_update_time();
	LOG_TRACE(log);
	if (daemonize) {
		rc = sys_daemon(log, 0, 1);
		if (rc) {
			return rc;
		}
	}
	rc = kill_all(log);
	if (rc) {
		return rc;
	}
	rc = shm_init(log, (void **)&ih, sizeof(*ih));
	if (rc) {
		return rc;
	}
	memset(ih, 0, sizeof(*ih));
	rc = mod_foreach_mod_init(log, ih);
	if (rc) {
		return rc;
	}
	rc = mod_foreach_mod_attach(log, ih);
	if (rc) {
		return rc;
	}
	pid = getpid();
	ih->ih_version = IH_VERSION;
	ih->ih_HZ = sleep_compute_HZ();
	for (i = 0; i < ARRAY_SIZE(ih->ih_procs); ++i) {
		proc = ih->ih_procs + i;
		mod_foreach_proc_init(log, proc);
	}
	current = &ih->ih_controller;
	current->p_pid = pid;
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
	mod_foreach_mod_deinit(log, ih);
	mod_foreach_mod_detach(log, ih);
	shm_deinit(log);
	return rc;
}

void
proc_controller_loop()
{
	while (1) {
		gt_fd_event_mod_wait();
	}
}

static int
fork_controller(struct log *log, const char *proc_name)
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
		api_locked += 100;
		log = log_trace0();
		sys_close(log, pipe_fd[0]);
		rc = proc_controller_init(log, 1, proc_name);
		write_all(log, pipe_fd[1], &rc, sizeof(rc));
		sys_close(log, pipe_fd[1]);
		if (rc == 0) {
			proc_controller_loop();
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
service_attach(struct log *log, const char *proc_name, struct init_hdr **pih)
{
	int rc, pid;
	uint64_t to;
	struct sockaddr_un a;

	rc = shm_attach(log, (void **)pih);
	if (rc) {
		return rc;
	}
	if ((*pih)->ih_version != IH_VERSION) {
		return -EINVAL;
	}
	pid = (*pih)->ih_controller.p_pid;
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
	struct init_hdr *ih;

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
	rc = sysctl_bind(log, &a);
	if (rc < 0) {
		return rc;
	}
	service_fd = rc;
	for (i = 0; i < 3; ++i) {
		if (i) {
			rc = fork_controller(log, proc_name);
		} else {
			rc = 0;
		}
		if (rc == 0) {
			rc = service_attach(log, proc_name, &ih);
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
	current->p_pid = pid;
	strzcpy(current->p_name, proc_name, sizeof(current->p_name));
	rc = mod_foreach_mod_attach(log, ih);
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
	spinlock_lock(&init_lock);
	dlsym_all();
	rdtsc_update_time();
	ASSERT(current == NULL);
	log = log_trace0();
	log_init_early();
	LOGF(log, LOG_INFO, 0, "Hit;");
	rc = sys_open(log, GT_PREFIX"/init.lock", O_CREAT|O_RDWR, 0666);
	fd = rc;
	if (rc < 0) {
		goto out;
	}
	rc = sys_flock(log, fd, LOCK_EX);
	if (rc < 0) {
		goto out;
	}
	rc = service_init_locked(log);
out:
	if (rc) {
		LOGF(log, LOG_ERR, -rc, "failed;");
	} else {
		LOGF(log, LOG_INFO, 0, "ok; current=%p", current);
	}
	if (fd >= 0) {
		sys_close(log, fd);	
	}
	spinlock_unlock(&init_lock);
	api_locked--;
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
