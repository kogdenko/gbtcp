#include "global.h"
#include "subr.h"
#include "sys.h"
#include "log.h"
#include "timer.h"
#include "htable.h"
#include "lptree.h"
#include "route.h"
#include "strbuf.h"
#include "ctl.h"
#include "inet.h"
#include "fd_event.h"
#include "poll.h"
#include "epoll.h"
#include "mbuf.h"
#include "file.h"
#include "sockbuf.h"
#include "tcp.h"
#include "signal.h"
#include "service.h"
#include "api.h"

#define GT_GLOBAL_LOG_NODE_FOREACH(x) \
	x(deinit) \

struct gt_global_mod {
	int (*m_init)();
	void (*m_deinit)(struct gt_log *);
	int m_inited;
	const char *m_name;
};

int gt_global_epoch;
int gt_global_inited;
struct gt_spinlock gt_global_lock;

#define GT_GLOBAL_MOD(name) \
{ \
	.m_init = gt_##name##_mod_init, \
	.m_deinit = gt_##name##_mod_deinit, \
	.m_inited = 0, \
	.m_name = #name \
}

static struct gt_global_mod gt_global_modules[] = {
	GT_GLOBAL_MOD(ctl),
	GT_GLOBAL_MOD(log),
	GT_GLOBAL_MOD(global),
	GT_GLOBAL_MOD(subr),
	GT_GLOBAL_MOD(poll),
	GT_GLOBAL_MOD(epoll),
	GT_GLOBAL_MOD(sys),
	GT_GLOBAL_MOD(mbuf),
	GT_GLOBAL_MOD(htable),
	GT_GLOBAL_MOD(timer),
	GT_GLOBAL_MOD(fd_event),
	GT_GLOBAL_MOD(signal),
	GT_GLOBAL_MOD(dev),
	GT_GLOBAL_MOD(api),
	GT_GLOBAL_MOD(service),
	GT_GLOBAL_MOD(lptree),
	GT_GLOBAL_MOD(route),
	GT_GLOBAL_MOD(arp),
	GT_GLOBAL_MOD(file),
	GT_GLOBAL_MOD(inet),
	GT_GLOBAL_MOD(sockbuf),
	GT_GLOBAL_MOD(tcp),
};

static struct gt_log_scope this_log;
GT_GLOBAL_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static int gt_global_compute_HZ();

int
gt_global_mod_init()
{
	gt_log_scope_init(&this_log, "global");
	GT_GLOBAL_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	return 0;
}

void
gt_global_mod_deinit(struct gt_log *log)
{
	gt_log_scope_deinit(log, &this_log);
}

int
gt_global_init()
{
	int i, rc;
	struct gt_global_mod *mod;

	assert(gt_global_inited == 0);
	gt_global_inited = 1;
	gt_global_epoch++;
	assert(sizeof(struct gt_sock_tuple) == 12);
	assert(AF_UNIX == AF_LOCAL);
	gt_sys_mod_dlsym();
	rc = gt_global_compute_HZ();
	if (rc) {
		return rc;
	}
	gt_global_set_time();
	for (i = 0; i < GT_ARRAY_SIZE(gt_global_modules); ++i) {
		mod = gt_global_modules + i;
		rc = (*mod->m_init)();
		if (rc) {
			return rc;		
		} else {
			mod->m_inited = 1;
		}
	}
	return 0;
}

void
gt_global_deinit(struct gt_log *log)
{
	int i;
	struct gt_global_mod *mod;

	assert(gt_global_inited);
	log = GT_LOG_TRACE(log, deinit);
	for (i = GT_ARRAY_SIZE(gt_global_modules) - 1; i >= 0; --i) {
		mod = gt_global_modules + i;
		if (mod->m_inited) {
			mod->m_inited = 0;
			(*mod->m_deinit)(log);
		}
	}
	gt_global_inited = 0;
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

static int
gt_global_compute_HZ()
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
