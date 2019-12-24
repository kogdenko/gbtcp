#include "fd_event.h"
#include "subr.h"
#include "sys.h"
#include "log.h"
#include "timer.h"
#include "poll.h"
#include "tcp.h"
#include "signal.h"
#include "ctl.h"
#include "global.h"

#define GT_FD_EVENT_LOG_NODE_FOREACH(x) \
	x(mod_deinit) \
	x(mod_check) \
	x(mod_wait) \
	x(new) \
	x(free) \
	x(del) \

uint64_t gt_fd_event_epoch;

static gt_time_t gt_fd_event_time;
static int gt_fd_event_nr_used;
static int gt_fd_event_in_cb;
static struct gt_fd_event *gt_fd_event_used[GT_FD_EVENTS_MAX];
static struct gt_fd_event gt_fd_event_buf[GT_FD_EVENTS_MAX];
static struct gt_log_scope this_log;
GT_FD_EVENT_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static void gt_fd_event_ctl_init_stat_entry(struct gt_log * log,
	const char *event_name, uint64_t *val, const char *stat_name);

static void gt_fd_event_free(struct gt_fd_event *e);

static int gt_fd_event_unref(struct gt_fd_event *e);

static int gt_fd_event_call(struct gt_fd_event *e, short revents);

int
gt_fd_event_mod_init()
{
	int i;
	struct gt_fd_event *e;

	gt_log_scope_init(&this_log, "fd_event");
	GT_FD_EVENT_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	gt_fd_event_nr_used = 0;
	memset(gt_fd_event_buf, 0, sizeof(gt_fd_event_buf));
	for (i = 0; i < GT_ARRAY_SIZE(gt_fd_event_buf); ++i) {
		e = gt_fd_event_buf + i;
		e->fde_fd = -1;
	}
	return 0;
}

void
gt_fd_event_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_fd_event_nr_used = 0;
	gt_log_scope_deinit(log, &this_log);
}

void
gt_fd_event_mod_check()
{
	struct gt_log *log;
	struct gt_fd_event_set set;
	struct pollfd pfds[GT_FD_EVENTS_MAX];

	log = GT_LOG_TRACE1(mod_check);
	do {
		set.fdes_to = 0;
		gt_fd_event_set_init(&set, pfds);
		gt_sys_ppoll(log, pfds, set.fdes_nr_used, &set.fdes_ts, NULL);
		gt_fd_event_set_call(&set, pfds);
	} while (set.fdes_again);
}

void
gt_fd_event_mod_try_check()
{
	uint64_t dt;

	if (gt_fd_event_in_cb) {
		// Occured in dev_init -- nm_open called inside callback
		return;
	}
	dt = gt_nsec - gt_fd_event_time;
	if (dt >= GT_FD_EVENT_TIMEOUT) {
		gt_fd_event_mod_check();
	}
}

void
gt_fd_event_mod_trylock_check()
{
	uint64_t t, dt;
	struct timespec ts;

	t = gt_global_get_time();
	dt = t - gt_fd_event_time;
	if (dt < GT_FD_EVENT_TIMEOUT) {
		ts.tv_nsec = GT_FD_EVENT_TIMEOUT - dt;
	} else {
		if (gt_spinlock_trylock(&gt_global_lock)) {
			gt_fd_event_mod_check();
			GT_GLOBAL_UNLOCK;
		}
		ts.tv_nsec = GT_FD_EVENT_TIMEOUT;
	}
	ts.tv_sec = 0;
	nanosleep(&ts, NULL);
}

int
gt_fd_event_mod_wait()
{
	int rc, epoch;
	struct gt_log *log;
	struct gt_fd_event_set set;
	struct pollfd pfds[GT_FD_EVENTS_MAX];

	log = GT_LOG_TRACE1(mod_wait);
	set.fdes_to = GT_TIMER_TIMEOUT;
	gt_fd_event_set_init(&set, pfds);
	epoch = gt_global_epoch;
	GT_GLOBAL_UNLOCK;
	rc = gt_sys_ppoll(log, pfds, set.fdes_nr_used, &set.fdes_ts, NULL);
	GT_GLOBAL_LOCK;
	if (epoch == gt_global_epoch) {
		gt_fd_event_set_call(&set, pfds);
	}
	return rc < 0 ? rc : 0;
}

static void
gt_fd_event_ctl_init_stat_entry(struct gt_log * log, const char *event_name,
	uint64_t *val, const char *stat_name)
{
	char path[PATH_MAX];
	
	snprintf(path, sizeof(path), "fd_event.list.%s.stat.%s",
	         event_name, stat_name);
	gt_ctl_add_uint64(log, path, GT_CTL_RD, val, 0, 0);
}

#define GT_FD_EVENT_INIT_CTL_STAT_ENTRY(x) \
	gt_fd_event_ctl_init_stat_entry(log, e->fde_name, &e->fde_cnt_##x, #x)

void
gt_fd_event_ctl_init(struct gt_log *log, struct gt_fd_event *e)
{
	if (e->fde_has_cnt) {
		return;
	}
	GT_FD_EVENT_INIT_CTL_STAT_ENTRY(POLLIN);
	GT_FD_EVENT_INIT_CTL_STAT_ENTRY(POLLOUT);
	GT_FD_EVENT_INIT_CTL_STAT_ENTRY(POLLERR);
	GT_FD_EVENT_INIT_CTL_STAT_ENTRY(POLLHUP);
	GT_FD_EVENT_INIT_CTL_STAT_ENTRY(POLLNVAL);
	GT_FD_EVENT_INIT_CTL_STAT_ENTRY(UNKNOWN);
	GT_FD_EVENT_INIT_CTL_STAT_ENTRY(set_POLLIN);
	GT_FD_EVENT_INIT_CTL_STAT_ENTRY(set_POLLOUT);
	e->fde_has_cnt = 1;
}

int
gt_fd_event_new(struct gt_log *log, struct gt_fd_event **pe,
	int fd, const char *name, gt_fd_event_f fn, void *udata)
{
	int i, id;
	struct gt_fd_event *e;

	GT_ASSERT(fd != -1);
	GT_ASSERT(fn != NULL);
	log = GT_LOG_TRACE(log, new);
	if (gt_fd_event_nr_used == GT_ARRAY_SIZE(gt_fd_event_used)) {
		GT_LOGF(log, LOG_ERR, 0, "limit exceeded; limit=%zu",
		        GT_ARRAY_SIZE(gt_fd_event_used));
		return -ENOMEM;
	}
	id = -1;
	for (i = 0; i < GT_ARRAY_SIZE(gt_fd_event_buf); ++i) {
		e = gt_fd_event_buf + i;
		if (e->fde_fd != -1) {
			if (!strcmp(e->fde_name, name)) {
				GT_LOGF(log, LOG_ERR, 0,
				        "already exists; event='%s'",
				        name);
				return -EEXIST;
			}
		} else {
			if (e->fde_ref_cnt == 0) {
				if (id == -1) {
					id = i;
				}
			}
		}
	}
	GT_ASSERT(id != -1);
	e = gt_fd_event_buf + id;
	memset(e, 0, sizeof(*e));
	e->fde_fd = fd;
	e->fde_ref_cnt = 1;
	e->fde_events = 0;
	e->fde_fn = fn;
	gt_strzcpy(e->fde_name, name, sizeof(e->fde_name));
	e->fde_udata = udata;
	e->fde_id = gt_fd_event_nr_used;
	gt_fd_event_used[e->fde_id] = e;
	gt_fd_event_nr_used++;
	*pe = e;
	GT_DBG(new, 0, "ok; event='%s'", e->fde_name);
	return 0;
}

static void
gt_fd_event_free(struct gt_fd_event *e)
{
	char path[PATH_MAX];
	struct gt_log *log;
	struct gt_fd_event *last;

	GT_DBG(free, 0, "hit; event='%s'", e->fde_name);
	GT_ASSERT(e->fde_id < gt_fd_event_nr_used);
	if (e->fde_has_cnt) {
		log = GT_LOG_TRACE1(del);
		snprintf(path, sizeof(path), "event.list.%s", e->fde_name);
		gt_ctl_del(log, path);
	}
	if (e->fde_id != gt_fd_event_nr_used - 1) {
		last = gt_fd_event_used[gt_fd_event_nr_used - 1];
		gt_fd_event_used[e->fde_id] = last;
		gt_fd_event_used[e->fde_id]->fde_id = e->fde_id;
	}
	gt_fd_event_nr_used--;
}

static int
gt_fd_event_unref(struct gt_fd_event *e)
{
	int ref_cnt;

	GT_ASSERT(e->fde_ref_cnt > 0);
	e->fde_ref_cnt--;
	ref_cnt = e->fde_ref_cnt;
	if (ref_cnt == 0) {
		gt_fd_event_free(e);
	}
	return ref_cnt;
}

void
gt_fd_event_del(struct gt_fd_event *e)
{
	if (e != NULL) {
		GT_DBG(del, 0, "hit; event='%s'", e->fde_name);
		GT_ASSERT(gt_fd_event_nr_used);
		GT_ASSERT(e->fde_fd != -1);
		GT_ASSERT(e->fde_id < gt_fd_event_nr_used);
		GT_ASSERT(e == gt_fd_event_used[e->fde_id]);
		e->fde_fd = -1;
		gt_fd_event_unref(e);
	}
}

void
gt_fd_event_set(struct gt_fd_event *e, short events)
{	
	GT_ASSERT(events);
	GT_ASSERT((events & ~(POLLIN|POLLOUT)) == 0);
	GT_ASSERT(e != NULL);
	GT_ASSERT(e->fde_fd != -1);
	GT_ASSERT(e->fde_id < gt_fd_event_nr_used);
	GT_ASSERT(e == gt_fd_event_used[e->fde_id]);
	if (e->fde_events != events) {
		if (events & POLLIN) {
			e->fde_cnt_set_POLLIN++;
		}
		if (events & POLLOUT) {
			e->fde_cnt_set_POLLOUT++;
		}
		e->fde_events |= events;
	}
}

void
gt_fd_event_clear(struct gt_fd_event *e, short events)
{
	GT_ASSERT(events);
	GT_ASSERT(e != NULL);
	GT_ASSERT(e->fde_id < gt_fd_event_nr_used);
	GT_ASSERT(e == gt_fd_event_used[e->fde_id]);
	GT_ASSERT((events & ~(POLLIN|POLLOUT)) == 0);
	e->fde_events &= ~events;
}

int
gt_fd_event_is_set(struct gt_fd_event *e, short events)
{
	return e->fde_events & events;
}

void
gt_fd_event_set_init(struct gt_fd_event_set *set, struct pollfd *pfds)
{
	int i, idx;
	struct gt_fd_event *e;

	GT_ASSERT3(0, gt_fd_event_in_cb == 0, "recursive wait");
	gt_global_set_time();
	set->fdes_again = 0;
	set->fdes_time = gt_nsec;
	set->fdes_nr_used = 0;
	set->fdes_epoch = gt_global_epoch;
	gt_sock_tx_flush();
	for (i = 0; i < gt_fd_event_nr_used; ++i) {
		e = gt_fd_event_used[i];
		if (e->fde_fd == -1 || e->fde_events == 0) {
			continue;
		}
		e->fde_ref_cnt++;
		idx = set->fdes_nr_used;
		pfds[idx].fd = e->fde_fd;
		pfds[idx].events = e->fde_events;
		set->fdes_used[idx] = e;
		set->fdes_nr_used++;
	}
	set->fdes_ts.tv_sec = 0;
	if (set->fdes_to == 0) {
		set->fdes_ts.tv_nsec = 0;
	} else if (set->fdes_to >= GT_TIMER_TIMEOUT) {
		set->fdes_ts.tv_nsec = GT_TIMER_TIMEOUT;
	} else {
		set->fdes_ts.tv_nsec = set->fdes_to;
	}
}

static int
gt_fd_event_call(struct gt_fd_event *e, short revents)
{
	int rc;

	rc = (*e->fde_fn)(e->fde_udata, revents);
	if (e->fde_has_cnt) {
		if (revents & POLLIN) {	
			e->fde_cnt_POLLIN++;
		} else if (revents & POLLOUT) {
			e->fde_cnt_POLLOUT++;
		} else if (revents & POLLERR) {
			e->fde_cnt_POLLERR++;
		} else if (revents & POLLHUP) {
			e->fde_cnt_POLLHUP++;
		} else if (revents & POLLNVAL) {
			e->fde_cnt_POLLNVAL++;
		} else {
			e->fde_cnt_UNKNOWN++;
		}
	}
	return rc;
}

int
gt_fd_event_set_call(struct gt_fd_event_set *set, struct pollfd *pfds)
{
	int i, n, rc;
	uint64_t dt;
	struct gt_fd_event *e;

	if (set->fdes_epoch != gt_global_epoch) {
		return 0;
	}
	gt_fd_event_epoch++;
	gt_global_set_time();
	dt = gt_nsec - set->fdes_time;
	if (dt > set->fdes_to) {
		set->fdes_to = 0;
	} else {
		set->fdes_to -= dt;
	}
	gt_timer_mod_check();
	n = 0;
	gt_fd_event_in_cb = 1;
	for (i = 0; i < set->fdes_nr_used; ++i) {
		e = set->fdes_used[i];
		if (pfds[i].revents) {
			n++;
			if (e->fde_fd != -1) {
				GT_ASSERT(pfds[i].fd == e->fde_fd);
				rc = gt_fd_event_call(e, pfds[i].revents);
				if (rc) {
					GT_ASSERT(rc == -EAGAIN);
					set->fdes_again = 1;
				}
			}
		}
		gt_fd_event_unref(e);
	}
	gt_fd_event_in_cb = 0;
	if (set->fdes_again == 0) {
		gt_fd_event_time = gt_nsec;
	}
	return n;
}
