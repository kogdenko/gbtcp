/* GPL2 license */
#include "internals.h"

#define CONTROLLER_PIDFILE "controller.pid"

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
	printf("Init { %s\n", #name); \
	name##_mod_init(NULL, pmod); \
	printf("Init %s - %p\n", #name, *pmod); \
	printf("Attach %s [%d]%p\n", #name, MOD_##name, *pmod); \
	name##_mod_attach(NULL, *pmod);

	
#define MOD_ATTACH(name) \
	pmod = &ih->ih_mods[MOD_##name]; \
	printf("Attach %s [%d]%p\n", #name, MOD_##name, *pmod); \
	name##_mod_attach(NULL, *pmod);

enum {
	MOD_FOREACH(MOD_ENUM)
	MOD_COUNT_MAX
};

int gt_global_epoch;
static int iam_controller;
struct proc *current;
struct spinlock gt_global_lock;
static struct init_mod *current_mod;

#define IH_VERSION 2

struct init_hdr {
	int ih_version;
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
	current_mod = raw_mod;
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
	current_mod = NULL;
}

static int
compute_HZ()
{
	int rc;
	uint64_t t0, t1, HZ;
	struct timespec ts, rem;

	rmb();
	ts.tv_sec = 0;
	ts.tv_nsec = 10 * 1000 * 1000;
	t0 = gt_rdtsc();
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
	t1 = gt_rdtsc();
	HZ = (t1 - t0) * 100;
	gt_mHZ = HZ / 1000000;
//	printf("HZ=%"PRIu64"(%"PRIu64")\n", HZ, gt_mHZ);
	return 0;
}

int
common_init(int is_service, struct init_hdr *ih)
{
	int rc;
	void **pmod;
	gt_global_epoch++;
	assert(sizeof(struct gt_sock_tuple) == 12);
	assert(AF_UNIX == AF_LOCAL);
	rc = compute_HZ();
	if (rc) {
		return rc;
	}
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

//void
//sigchild(int f)
//{
//	printf("CHILD\n");
//}

static int
killall(struct log *log)
{
	int i, rc;
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *entry;
	struct pidwait pw;

	LOG_TRACE(log);
	pidwait_init(log, &pw, PIDWAIT_NONBLOCK);
	snprintf(path, PATH_MAX, "%s/pid", GT_PREFIX);
	rc = sys_opendir(log, &dir, path);
	if (rc) {
		return rc;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = read_pidfile(log, entry->d_name);
		if (rc > 0) {
			pidwait_add(log, &pw, rc);
		} else {
			pidfile_path(path, entry->d_name);
			sys_unlink(log, path);
		}
	}
	closedir(dir);
	for (i = 0; i < 3; ++i) {
		pidwait_kill(log, &pw, SIGKILL);
		if (pw.pw_nentries) {
			pidwait_read(log, &pw, NULL, -1);
		}
		if (pw.pw_nentries == 0) {
			break;
		}
	}
	rc = pw.pw_nentries ? -ETIMEDOUT : 0;
	pidwait_deinit(log, &pw);
	return rc;
}
int
run_controller(int fd)
{
	int i, rc, pid ;
	struct init_hdr *ih;
	struct log *log;

	dlsym_all();
	log = log_trace0();
	rc = killall(log);
	if (rc) {
		return rc;
	}
	pid = getpid();
	rc = write_pidfile(log, CONTROLLER_PIDFILE, pid);
	if (rc) {
		return rc;
	}
	rc = shm_init((void **)&ih, sizeof(*ih));
	if (rc) {
		return rc;
	}
	rc = common_init(0, ih);
	ih->ih_version = IH_VERSION;
	current = &ih->ih_controller;
	current->p_pid = pid;
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		ih->ih_services[i].p_pid = 0;
	}
	sysctl_read_file(log, NULL);
	rc = sysctl_bind(log, 0);
	if (rc) {
		return 1;
	}
	write_all(NULL, fd, STRSZ("Ok"));
	while (1) {
		gt_fd_event_mod_wait();
	}
	return 0;
}

static int
fork_controller(struct log *log)
{
	int rc, pipe_fd[2];
	char msg[1];

	gt_dbg("Forkcontroller");
	LOG_TRACE(log);
	rc = sys_pipe(log, pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork(log);
	if (rc < 0) {
		return rc;
	}
	if (rc == 0) {
		iam_controller = 1;
		sys_close(log, pipe_fd[0]);
		rc = run_controller(pipe_fd[1]);
		return rc;
	}
	gt_dbg("x");
	rc = sys_read(log, pipe_fd[0], msg, sizeof(msg));
	gt_dbg("y");
	if (rc == 0) {
		rc = -ETIMEDOUT;
	} else if (rc > 0) {
		rc = 0;
	}
	sys_close(log, pipe_fd[0]);
	sys_close(log, pipe_fd[1]);
	return rc;
}
int
service_attach(struct log *log, struct init_hdr **pih)
{
	int rc;
	rc = shm_attach((void **)pih);
	if (rc == 0) {
		if ((*pih)->ih_version != IH_VERSION) {
			goto err;
		}
		rc = read_pidfile(log, CONTROLLER_PIDFILE);
		if (rc > 0 && rc == (*pih)->ih_controller.p_pid) {
			return 0;
		}
	}
err:
	rc = fork_controller(log);
	if (rc) {
		return rc;
	}
	rc = shm_attach((void **)pih);
	return rc;
}
int
service_init_locked(struct log *log)
{
	int i, rc;
	struct proc *service;
	struct init_hdr *ih;

	// Check again under lock
	if (current != NULL) {
		return 0;
	}
	rc = service_attach(log, &ih);
	if (rc) {
		gt_dbg("a");
		return rc;
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		service = ih->ih_services + i;
		if (service->p_pid == 0) {
			current = service;
		}
	}
	if (current == NULL) {
		return -ENOENT;
	}
	rc = common_init(1, ih);
	ASSERT(rc == 0);
	gt_dbg("current %p", current);
	return 0;
}
int
service_init()
{
	int rc, lock_fd;
	char lock_path[PATH_MAX];
	struct log *log;

	if (iam_controller) {
		return -ENOTSUP;
	}
	assert(current == NULL);
	dlsym_all();
	log = log_trace0();
	snprintf(lock_path, sizeof(lock_path), "%s/init.lock", GT_PREFIX);
	rc = sys_open(log, lock_path, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		return rc;
	}
	lock_fd = rc;
	rc = sys_flock(log, lock_fd, LOCK_EX);
	if (!rc) {
		rc = service_init_locked(log);
	}
	sys_close(NULL, lock_fd);
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
	t = gt_rdtsc();
	ns = 1000 * t / gt_mHZ;
	// tsc can be reseted after suspend
	if (ns > nanoseconds) {
		nanoseconds = ns;
	}
}
