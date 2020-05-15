#include "internals.h"

struct fd_event_mod {
	struct log_scope log_scope;
};

uint64_t gt_fd_event_epoch;

static uint64_t gt_fd_event_time;
static int fdevent_nused;
static int gt_fd_event_in_cb;
static struct gt_fd_event *gt_fd_event_used[GT_FD_EVENTS_MAX];
static struct gt_fd_event gt_fd_event_buf[GT_FD_EVENTS_MAX];
static struct fd_event_mod *curmod;

static void gt_fd_event_ctl_init_stat_entry(struct log * log,
	const char *event_name, uint64_t *val, const char *stat_name);

static void gt_fd_event_free(struct gt_fd_event *e);

static int gt_fd_event_unref(struct gt_fd_event *e);

static int gt_fd_event_call(struct gt_fd_event *e, short revents);

int
fd_event_mod_init(struct log *log, void **pp)
{
	int rc;
	struct fd_event_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "fd_event");
	}
	return rc;
}

int
fd_event_mod_attach(struct log *log, void *raw_mod)
{
	int i;
	struct gt_fd_event *e;
	curmod = raw_mod;
	fdevent_nused = 0;
	memset(gt_fd_event_buf, 0, sizeof(gt_fd_event_buf));
	for (i = 0; i < ARRAY_SIZE(gt_fd_event_buf); ++i) {
		e = gt_fd_event_buf + i;
		e->fde_fd = -1;
	}
	return 0;
}

int
fd_event_proc_init(struct log *log, struct proc *p)
{
	return 0;
}

void
fd_event_mod_deinit(struct log *log, void *raw_mod)
{
	struct fd_event_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
fd_event_mod_detach(struct log *log)
{
	fdevent_nused = 0;
	curmod = NULL;
}

void
gt_fd_event_mod_check()
{
	struct log *log;
	struct gt_fd_event_set set;
	struct pollfd pfds[GT_FD_EVENTS_MAX];

	log = log_trace0();
	do {
		set.fdes_to = 0;
		gt_fd_event_set_init(&set, pfds);
		sys_ppoll(log, pfds, set.fdes_nr_used, &set.fdes_ts, NULL);
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
	dt = nanoseconds - gt_fd_event_time;
	if (dt >= GT_FD_EVENT_TIMEOUT) {
		gt_fd_event_mod_check();
	}
}

int
gt_fd_event_mod_wait()
{
	int rc;
	struct log *log;
	struct gt_fd_event_set set;
	struct pollfd pfds[GT_FD_EVENTS_MAX];

	log = log_trace0();
	set.fdes_to = TIMER_TIMO;
	gt_fd_event_set_init(&set, pfds);
	SERVICE_UNLOCK;
	rc = sys_ppoll(log, pfds, set.fdes_nr_used, &set.fdes_ts, NULL);
	SERVICE_LOCK;
	gt_fd_event_set_call(&set, pfds);
	return rc < 0 ? rc : 0;
}

static void
gt_fd_event_ctl_init_stat_entry(struct log * log, const char *event_name,
	uint64_t *val, const char *stat_name)
{
	char path[PATH_MAX];
	
	snprintf(path, sizeof(path), "fd_event.list.%s.stat.%s",
	         event_name, stat_name);
	sysctl_add_uint64(log, path, SYSCTL_RD, val, 0, 0);
}

#define GT_FD_EVENT_INIT_CTL_STAT_ENTRY(x) \
	gt_fd_event_ctl_init_stat_entry(log, e->fde_name, &e->fde_cnt_##x, #x)

void
gt_fd_event_ctl_init(struct log *log, struct gt_fd_event *e)
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
gt_fd_event_new(struct log *log, struct gt_fd_event **pe,
	int fd, const char *name, gt_fd_event_f fn, void *udata)
{
	int i, id;
	struct gt_fd_event *e;

	ASSERT(fd != -1);
	ASSERT(fn != NULL);
	LOG_TRACE(log);
	if (fdevent_nused == ARRAY_SIZE(gt_fd_event_used)) {
		LOGF(log, LOG_ERR, 0, "limit exceeded; limit=%zu",
		     ARRAY_SIZE(gt_fd_event_used));
		return -ENOMEM;
	}
	id = -1;
	for (i = 0; i < ARRAY_SIZE(gt_fd_event_buf); ++i) {
		e = gt_fd_event_buf + i;
		if (e->fde_fd != -1) {
			if (!strcmp(e->fde_name, name)) {
				LOGF(log, LOG_ERR, 0,
				     "already exists; event='%s'", name);
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
	ASSERT(id != -1);
	e = gt_fd_event_buf + id;
	memset(e, 0, sizeof(*e));
	e->fde_fd = fd;
	e->fde_ref_cnt = 1;
	e->fde_events = 0;
	e->fde_fn = fn;
	strzcpy(e->fde_name, name, sizeof(e->fde_name));
	e->fde_udata = udata;
	e->fde_id = fdevent_nused;
	gt_fd_event_used[e->fde_id] = e;
	fdevent_nused++;
	*pe = e;
	DBG(log, 0, "ok; event='%s'", e->fde_name);
	return 0;
}

static void
gt_fd_event_free(struct gt_fd_event *e)
{
	char path[PATH_MAX];
	struct log *log;
	struct gt_fd_event *last;

	log = log_trace0();
	DBG(log, 0, "hit; event='%s'", e->fde_name);
	ASSERT(e->fde_id < fdevent_nused);
	if (e->fde_has_cnt) {
		snprintf(path, sizeof(path), "event.list.%s", e->fde_name);
		sysctl_del(log, path);
	}
	if (e->fde_id != fdevent_nused - 1) {
		last = gt_fd_event_used[fdevent_nused - 1];
		gt_fd_event_used[e->fde_id] = last;
		gt_fd_event_used[e->fde_id]->fde_id = e->fde_id;
	}
	fdevent_nused--;
}

static int
gt_fd_event_unref(struct gt_fd_event *e)
{
	int ref_cnt;

	ASSERT(e->fde_ref_cnt > 0);
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
	struct log *log;

	if (e != NULL) {
		log = log_trace0();
		DBG(log, 0, "hit; event='%s'", e->fde_name);
		ASSERT(fdevent_nused);
		ASSERT(e->fde_fd != -1);
		ASSERT(e->fde_id < fdevent_nused);
		ASSERT(e == gt_fd_event_used[e->fde_id]);
		e->fde_fd = -1;
		gt_fd_event_unref(e);
	}
}

void
gt_fd_event_set(struct gt_fd_event *e, short events)
{	
	ASSERT(events);
	ASSERT((events & ~(POLLIN|POLLOUT)) == 0);
	ASSERT(e != NULL);
	ASSERT(e->fde_fd != -1);
	ASSERT(e->fde_id < fdevent_nused);
	ASSERT(e == gt_fd_event_used[e->fde_id]);
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
	ASSERT(events);
	ASSERT(e != NULL);
	ASSERT(e->fde_id < fdevent_nused);
	ASSERT(e == gt_fd_event_used[e->fde_id]);
	ASSERT((events & ~(POLLIN|POLLOUT)) == 0);
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

	ASSERT3(0, gt_fd_event_in_cb == 0, "recursive wait");
	set->fdes_again = 0;
	set->fdes_time = nanoseconds;
	set->fdes_nr_used = 0;
	gt_sock_tx_flush();
	for (i = 0; i < fdevent_nused; ++i) {
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
	} else if (set->fdes_to >= TIMER_TIMO) {
		set->fdes_ts.tv_nsec = TIMER_TIMO;
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

	gt_fd_event_epoch++;
	dt = nanoseconds - set->fdes_time;
	if (dt > set->fdes_to) {
		set->fdes_to = 0;
	} else {
		set->fdes_to -= dt;
	}
	timer_mod_check();
	n = 0;
	gt_fd_event_in_cb = 1;
	for (i = 0; i < set->fdes_nr_used; ++i) {
		e = set->fdes_used[i];
		if (pfds[i].revents) {
			n++;
			if (e->fde_fd != -1) {
				ASSERT(pfds[i].fd == e->fde_fd);
				rc = gt_fd_event_call(e, pfds[i].revents);
				if (rc) {
					ASSERT(rc == -EAGAIN);
					set->fdes_again = 1;
				}
			}
		}
		gt_fd_event_unref(e);
	}
	gt_fd_event_in_cb = 0;
	if (set->fdes_again == 0) {
		gt_fd_event_time = nanoseconds;
	}
	return n;
}
