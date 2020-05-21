#include "internals.h"

struct fd_event_mod {
	struct log_scope log_scope;
};

uint64_t gt_fd_event_epoch;

static uint64_t last_check_time;
static int fd_event_nused;
static int gt_fd_event_in_cb;
static struct fd_event *gt_fd_event_used[FD_EVENTS_MAX];
static struct fd_event gt_fd_event_buf[FD_EVENTS_MAX];
static struct fd_event_mod *curmod;

static void gt_fd_event_free(struct fd_event *e);

static int gt_fd_event_unref(struct fd_event *e);

static int gt_fd_event_call(struct fd_event *e, short revents);

int
fd_event_mod_init(struct log *log, void **pp)
{
	int rc;
	struct fd_event_mod *mod;
	LOG_TRACE(log);
	rc = shm_malloc(log, pp, sizeof(*mod));
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
	struct fd_event *e;

	curmod = raw_mod;
	fd_event_nused = 0;
	memset(gt_fd_event_buf, 0, sizeof(gt_fd_event_buf));
	for (i = 0; i < ARRAY_SIZE(gt_fd_event_buf); ++i) {
		e = gt_fd_event_buf + i;
		e->fde_fd = -1;
	}
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
	fd_event_nused = 0;
	curmod = NULL;
}

void
check_fd_events()
{
	struct log *log;
	struct gt_fd_event_set set;
	struct pollfd pfds[FD_EVENTS_MAX];

	log = log_trace0();
	do {
		set.fdes_to = 0;
		gt_fd_event_set_init(&set, pfds);
		sys_ppoll(log, pfds, set.fdes_nr_used, &set.fdes_ts, NULL);
		gt_fd_event_set_call(&set, pfds);
	} while (set.fdes_again);
}

void
wait_for_fd_events()
{
	struct log *log;
	struct gt_fd_event_set set;
	struct pollfd pfds[FD_EVENTS_MAX];

	log = log_trace0();
	set.fdes_to = TIMER_TIMO;
	gt_fd_event_set_init(&set, pfds);
	SERVICE_UNLOCK;
	sys_ppoll(log, pfds, set.fdes_nr_used, &set.fdes_ts, NULL);
	SERVICE_LOCK;
	gt_fd_event_set_call(&set, pfds);
}

int
gt_fd_event_new(struct log *log, struct fd_event **pe,
	int fd, const char *name, fd_event_f fn, void *udata)
{
	int i, id;
	struct fd_event *e;

	ASSERT(fd != -1);
	ASSERT(fn != NULL);
	LOG_TRACE(log);
	if (fd_event_nused == ARRAY_SIZE(gt_fd_event_used)) {
		LOGF(log, LOG_ERR, ENOMEM, "failed; event='%s', limit=%zu",
		     name, ARRAY_SIZE(gt_fd_event_used));
		return -ENOMEM;
	}
	id = -1;
	for (i = 0; i < ARRAY_SIZE(gt_fd_event_buf); ++i) {
		e = gt_fd_event_buf + i;
		if (e->fde_fd != -1) {
			if (!strcmp(e->fde_name, name)) {
				LOGF(log, LOG_ERR, EEXIST,
				     "failed; event='%s'", name);
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
	e->fde_id = fd_event_nused;
	gt_fd_event_used[e->fde_id] = e;
	fd_event_nused++;
	*pe = e;
	DBG(0, "ok; event='%s'", e->fde_name);
	return 0;
}

static void
gt_fd_event_free(struct fd_event *e)
{
	struct fd_event *last;

	DBG(0, "hit; event='%s'", e->fde_name);
	ASSERT(e->fde_id < fd_event_nused);
	if (e->fde_id != fd_event_nused - 1) {
		last = gt_fd_event_used[fd_event_nused - 1];
		gt_fd_event_used[e->fde_id] = last;
		gt_fd_event_used[e->fde_id]->fde_id = e->fde_id;
	}
	fd_event_nused--;
}

static int
gt_fd_event_unref(struct fd_event *e)
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
gt_fd_event_del(struct fd_event *e)
{
	if (e != NULL) {
		DBG(0, "hit; event='%s'", e->fde_name);
		ASSERT(fd_event_nused);
		ASSERT(e->fde_fd != -1);
		ASSERT(e->fde_id < fd_event_nused);
		ASSERT(e == gt_fd_event_used[e->fde_id]);
		e->fde_fd = -1;
		gt_fd_event_unref(e);
	}
}

void
gt_fd_event_set(struct fd_event *e, short events)
{	
	ASSERT(events);
	ASSERT((events & ~(POLLIN|POLLOUT)) == 0);
	ASSERT(e != NULL);
	ASSERT(e->fde_fd != -1);
	ASSERT(e->fde_id < fd_event_nused);
	ASSERT(e == gt_fd_event_used[e->fde_id]);
	e->fde_events |= events;
}

void
gt_fd_event_clear(struct fd_event *e, short events)
{
	ASSERT(events);
	ASSERT(e != NULL);
	ASSERT(e->fde_id < fd_event_nused);
	ASSERT(e == gt_fd_event_used[e->fde_id]);
	ASSERT((events & ~(POLLIN|POLLOUT)) == 0);
	e->fde_events &= ~events;
}

int
gt_fd_event_is_set(struct fd_event *e, short events)
{
	return e->fde_events & events;
}

void
gt_fd_event_set_init(struct gt_fd_event_set *set, struct pollfd *pfds)
{
	int i, idx;
	struct fd_event *e;

	ASSERT3(0, gt_fd_event_in_cb == 0, "recursive wait");
	set->fdes_again = 0;
	rd_nanoseconds(); // FIXME: !!!!
	set->fdes_time = nanoseconds;
	set->fdes_nr_used = 0;
	sock_tx_flush();
	for (i = 0; i < fd_event_nused; ++i) {
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
gt_fd_event_call(struct fd_event *e, short revents)
{
	int rc;

	rc = (*e->fde_fn)(e->fde_udata, revents);
	return rc;
}

int
gt_fd_event_set_call(struct gt_fd_event_set *set, struct pollfd *pfds)
{
	int i, n, rc;
	uint64_t dt;
	struct fd_event *e;

	gt_fd_event_epoch++;
	rd_nanoseconds();
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
		last_check_time = nanoseconds;
	}
	return n;
}
