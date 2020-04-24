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

int gt_global_epoch;
int service_inited;
struct spinlock gt_global_lock;
static struct init_mod *current_mod;

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

int
init_mod_init(struct log *log, void **pp)
{
	int rc;
	struct init_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "init");
	return 0;
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

#define MOD_FOREACH(x) \
	x(sysctl) \
	x(log) \
	x(init) \
	x(subr) \
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
	printf("Init { %s\n", #name); \
	name##_mod_init(NULL, mods + MOD_##name); \
	printf("Init %s - %p\n", #name, mods + MOD_##name); \
	printf("Attach %s [%d]%p\n", #name, MOD_##name,  mods[MOD_##name]); \
	name##_mod_attach(NULL, mods[MOD_##name]);

	
#define MOD_ATTACH(name) \
	printf("Attach %s [%d]%p\n", #name, MOD_##name,  mods[MOD_##name]); \
	name##_mod_attach(NULL, mods[MOD_##name]);

enum {
	MOD_FOREACH(MOD_ENUM)
	NMODULES
};

static int
compute_HZ()
{
	int rc;
	uint64_t t0, t1, HZ;
	struct timespec ts, rem;

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
common_init(int is_service, void **mods)
{
	int rc;
	gt_global_epoch++;
	assert(sizeof(struct gt_sock_tuple) == 12);
	assert(AF_UNIX == AF_LOCAL);
	rc = compute_HZ();
	if (rc) {
		return rc;
	}
	gt_global_set_time();
	if (is_service == 0) {
		printf("init modules\n");
		MOD_FOREACH(MOD_INIT);
		printf("init dodules done\n");
	} else {
		MOD_FOREACH(MOD_ATTACH);
	}
	return 0;
}

int controller_run(int[2]);

void
sigchild(int f)
{
	printf("CHILD\n");
}

int
service_init()
{
	int rc;
	void *mods;

	assert(service_inited == 0);
	service_inited = 1;

	printf("IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII\n");
//	int fd[2];
	dlsym_all();
//	pipe
	sys_signal(NULL, SIGCHLD, sigchild);
	//rc = controller_run(NULL);
	//assert(0);
	rc = sys_fork(NULL);
	if (rc == 0) {
		rc = controller_run(NULL);
	} else if (rc > 0) {
		sleep(1);
		rc = shm_attach(&mods);
		if (rc) {
			printf("MM attach failed\n");
			return rc;
		}
		printf("MM attach ok %p\n", mods);
		rc = common_init(1, mods);
	}
	return rc;
}

int
controller_init()
{
	int rc, pid;
	void *mods;
	dlsym_all();
	printf("controler init \n");
	pid = getpid();
	rc = flock_pidfile(NULL, pid, "controller.pid");
	printf("rc=%d\n", rc);
	if (rc >= 0) {
		rc = shm_init(&mods, NMODULES * sizeof(void *));
		if (rc) {
			printf("MM init failed\n");
			return rc;
		}
		printf("MM init ok %p\n", mods);
		rc = common_init(0, mods);
	}
	return rc;
}

void
service_deinit(struct log *log)
{
//	int i;
//	struct mod *mod;

	assert(service_inited);
	LOG_TRACE(log);
/*	for (i = ARRAY_SIZE(modules) - 1; i >= 0; --i) {
		mod = modules + i;
		if (mod->m_inited) {
			mod->m_inited = 0;
			(*mod->m_deinit)(log, mod->m_data);
		}
	}*/
	service_inited = 0;
}

gt_time_t
gt_global_get_time()
{
	uint64_t t, nsec;

	t = gt_rdtsc();
	nsec = 1000 * t / gt_mHZ;
	return nsec;
}

void
gt_global_set_time()
{
	uint64_t nsec;

	nsec = gt_global_get_time();
	// tsc can be reseted after suspend
	if (nsec > gt_nsec) {
		gt_nsec = nsec;
	}
}
