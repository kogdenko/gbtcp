/* GPL2 license */
#include "internals.h"

struct init_mod {
	struct log_scope log_scope;
};

struct mod {
	int (*m_init)(struct log *, void **);
	int (*m_attach)(struct log *, void *);
	void (*m_deinit)(struct log *, void *);
	void (*m_detach)(struct log *);
	int m_inited;
	int m_attached;
	void *m_data;
	const char *m_name;
};

#define MOD_FOREACH(x) \
	x(sysctl) \
	x(log) \
	x(init) \
	x(subr) \
	x(pid) \
	x(poll) \
	x(epoll) \
	x(sys) \
	x(mbuf) \
	x(htable) \
	x(timer) \
	x(fd_event) \
	x(signal) \
	x(dev) \
	x(api) \
	x(service) \
	x(lptree) \
	x(route) \
	x(arp) \
	x(file) \
	x(inet) \
	x(sockbuf) \
	x(tcp)

#define MOD_ENUM(name) MOD_##name,
#define MOD_INIT(name) \
	pmod = &ih->ih_mods[MOD_##name]; \
	if (0) \
		printf("Init { %s\n", #name); \
	name##_mod_init(NULL, pmod); \
	if (0) { \
		printf("Init %s - %p\n", #name, *pmod); \
		printf("Attach %s [%d]%p\n", #name, MOD_##name, *pmod); \
	} \
	name##_mod_attach(NULL, *pmod);

	
#define MOD_ATTACH(name) \
	pmod = &ih->ih_mods[MOD_##name]; \
	if (0) \
		printf("Attach %s [%d]%p\n", #name, MOD_##name, *pmod); \
	name##_mod_attach(NULL, *pmod);

enum {
	MOD_FOREACH(MOD_ENUM)
	MOD_COUNT_MAX
};

int gt_global_epoch;
struct proc *current;

static struct spinlock init_lock;
static struct sysctl_conn binded;
static struct init_mod *curmod;

#define IH_VERSION 2

struct init_hdr {
	int ih_version;
	uint64_t ih_HZ;
	void *ih_mods[MOD_COUNT_MAX];
	struct proc ih_controller;
	struct proc ih_services[GT_SERVICE_COUNT_MAX];
};

#define INIT_MOD(name) \
{ \
	.m_init = name##_mod_init, \
	.m_attach = name##_mod_attach, \
	.m_deinit = name##_mod_deinit, \
	.m_detach = name##_mod_detach, \
	.m_inited = 0, \
	.m_attached = 0, \
	.m_data = NULL, \
	.m_name = #name \
}

#if 0
#define INIT_MOD(name) \
{ \
	.m_inited = 0, \
	.m_name = #name \
}
#endif
void
gtd_host_rxtx(struct dev *dev, short revents)
{
	int i, n, len;
	u_char *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
//	struct route_if *ifp;

	//ifp = container_of(dev, struct route_if, rif_host_dev);
	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			data = (u_char *)NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			UNUSED(data);
			UNUSED(slot);
			UNUSED(len);
			//gtd_tx_to_net(ifp, data, len);
			
			DEV_RXR_NEXT(rxr);
		}
	}
}



int
init_mod_init(struct log *log, void **pp)
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
init_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
init_mod_deinit(struct log *log, void *raw_mod)
{
	struct init_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
init_mod_detach(struct log *log)
{
	curmod = NULL;
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

int
common_init(int is_service, struct init_hdr *ih)
{
	void **pmod;

	gt_global_epoch++;
	rdtsc_update_time();
	if (is_service == 0) {
		memset(ih, 0, sizeof(*ih));
		printf("init modules\n");
		MOD_FOREACH(MOD_INIT);
		printf("init dodules done\n");
	} else {
		MOD_FOREACH(MOD_ATTACH);
	}
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
		dbg("0");
		return rc;
	}
	fd = rc;
	rc = sys_malloc(log, (void **)&cp, sizeof(*cp));
	if (rc) {
		dbg("!");
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
	binded.c_accept_fn = controller_sysctl_accept;
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
	rc = shm_init((void **)&ih, sizeof(*ih));
	if (rc) {
		return rc;
	}
	rc = common_init(0, ih);
	assert(rc == 0);
	pid = getpid();
	ih->ih_version = IH_VERSION;
	ih->ih_HZ = sleep_compute_HZ();
	current = &ih->ih_controller;
	current->p_pid = pid;
	current->p_type = PROC_CONTROLLER;
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		proc = ih->ih_services + i;
		proc->p_pid = 0;
		proc->p_type = PROC_SERVICE;
	}
	sysctl_read_file(log, proc_name);
	rc = controller_bind(log, pid);
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
		api_disabled += 100;
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
service_attach(struct log *log, int fd, const char *proc_name,
	struct init_hdr **pih)
{
	int rc, pid;
	uint64_t to;
	struct sockaddr_un a;

	rc = shm_attach((void **)pih);
	if (rc) {
		return rc;
	}
	if ((*pih)->ih_version != IH_VERSION) {
		return -EINVAL;
	}
	pid = (*pih)->ih_controller.p_pid;
	sysctl_make_sockaddr_un(&a, pid);
	to = 2 * NANOSECONDS_SECOND;
	rc = connect_timed(log, fd, (struct sockaddr *)&a, sizeof(a), &to);
	if (rc == 0) {
		LOGF(log, LOG_NOTICE, 0, "attached; pid=%d", pid);
	}
	return rc;
}

int
service_init_locked(struct log *log, int fd)
{
	int i, rc, pid;
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
	for (i = 0; i < 3; ++i) {
		rc = service_attach(log, fd, proc_name, &ih);
		if (rc == 0) {
			break;
		}
		rc = fork_controller(log, proc_name);
	}
	if (rc) {
		return rc;
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		current = ih->ih_services + i;
		if (current->p_pid == 0) {
			break;
		}
	}
	if (current->p_pid) {
		return -ENOENT;
	}
	current->p_pid = pid;
	strzcpy(current->p_name, proc_name, sizeof(current->p_name));
	rc = common_init(1, ih);
	ASSERT(rc == 0);
	return 0;
}

static int
service_init_spinlocked(struct log *log)
{
	int rc, fd, pid, lock_fd;
	struct sockaddr_un a;

	pid = getpid();
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(log, &a);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sys_open(log, GT_PREFIX"/init.lock", O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		sys_close(log, fd);
		return rc;
	}
	lock_fd = rc;
	rc = sys_flock(log, lock_fd, LOCK_EX);
	if (rc) {
		goto err;
	}
	rc = service_init_locked(log, fd);
	if (rc) {
		goto err;
	}
	sys_close(log, lock_fd);
	return 0;
err:
	sys_close(log, lock_fd);
	sys_close(log, fd);
	return rc;
}

int
service_init()
{
	int rc;
	struct log *log;

	assert(api_disabled == 0);
	api_disabled++;
	spinlock_lock(&init_lock);
	dlsym_all();
	ASSERT(current == NULL);
	log = log_trace0();
	log_init_early();
	LOGF(log, LOG_INFO, 0, "Hit;");
	rc = service_init_spinlocked(log);
	if (rc) {
		current = NULL;
		LOGF(log, LOG_ERR, -rc, "failed;");
	} else {
		LOGF(log, LOG_INFO, 0, "ok; current=%p", current);
	}
	spinlock_unlock(&init_lock);
	api_disabled--;
	return rc;
}

void
service_deinit(struct log *log)
{
//	int i;
//	struct mod *mod;

//	LOG_TRACE(log);
/*	for (i = ARRAY_SIZE(modules) - 1; i >= 0; --i) {
		mod = modules + i;
		if (mod->m_inited) {
			mod->m_inited = 0;
			(*mod->m_deinit)(log, mod->m_data);
		}
	}*/
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
