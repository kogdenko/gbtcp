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
struct gt_spinlock gt_global_lock;
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
	rc = mm_alloc(log, pp, sizeof(*mod));
	if (rc)
		return rc;
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
	mm_free(mod);
}

void
init_mod_detach(struct log *log)
{
	current_mod = NULL;
}

static struct mod gt_global_modules[] = {
	INIT_MOD(sysctl),
	INIT_MOD(log),
	INIT_MOD(init),
	INIT_MOD(subr),
	INIT_MOD(poll),
	INIT_MOD(epoll),
	INIT_MOD(sys),
	INIT_MOD(mbuf),
	INIT_MOD(htable),
	INIT_MOD(timer),
	INIT_MOD(fd_event),
	INIT_MOD(signal),
	INIT_MOD(dev),
	INIT_MOD(api),
	INIT_MOD(service),
	INIT_MOD(lptree),
	INIT_MOD(route),
	INIT_MOD(arp),
	INIT_MOD(file),
	INIT_MOD(inet),
	INIT_MOD(sockbuf),
	INIT_MOD(tcp),
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
service_init()
{
	int i, rc;
	struct mod *mod;

	assert(service_inited == 0);
	service_inited = 1;
	gt_global_epoch++;
	assert(sizeof(struct gt_sock_tuple) == 12);
	assert(AF_UNIX == AF_LOCAL);
	sys_mod_dlsym();
	rc = compute_HZ();
	if (rc) {
		return rc;
	}
	gt_global_set_time();
	for (i = 0; i < ARRAY_SIZE(gt_global_modules); ++i) {
		mod = gt_global_modules + i;
		rc = (*mod->m_init)(NULL, &mod->m_data);
		if (rc)
			return rc;		
		mod->m_inited = 1;
		rc = (*mod->m_attach)(NULL, mod->m_data);
		if (rc)
			return rc;
		mod->m_attached = 1;
	}
	return 0;
}

void
service_deinit(struct log *log)
{
	int i;
	struct mod *mod;

	assert(service_inited);
	LOG_TRACE(log);
	for (i = ARRAY_SIZE(gt_global_modules) - 1; i >= 0; --i) {
		mod = gt_global_modules + i;
		if (mod->m_inited) {
			mod->m_inited = 0;
			(*mod->m_deinit)(log, mod->m_data);
		}
	}
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
