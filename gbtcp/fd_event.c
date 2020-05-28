#include "internals.h"

// System should periodically RX netmap devices or packets would be lost
#define FD_EVENT_TIMEOUT_MIN (20 * NANOSECONDS_MICROSECOND)
#define FD_EVENT_TIMEOUT_MAX (60 * NANOSECONDS_MICROSECOND) 

struct fd_event_mod {
	struct log_scope log_scope;
};

uint64_t gt_fd_event_epoch;

static uint64_t fd_event_last_check_time;
static uint64_t fd_event_timeout = FD_EVENT_TIMEOUT_MIN;
static int fd_event_nused;
static int fd_event_in_cb;
static struct fd_event *gt_fd_event_used[FD_EVENTS_MAX];
static struct fd_event gt_fd_event_buf[FD_EVENTS_MAX];
static struct fd_event_mod *curmod;

int
fd_event_mod_init(void **pp)
{
	int rc;
	struct fd_event_mod *mod;

	rc = shm_malloc(pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "fd_event");
	}
	return rc;
}

int
fd_event_mod_attach(void *raw_mod)
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
fd_event_mod_deinit(void *raw_mod)
{
	struct fd_event_mod *mod;

	mod = raw_mod;
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
fd_event_mod_detach()
{
	fd_event_nused = 0;
	curmod = NULL;
}

void
check_fd_events()
{
	int throttled;
	uint64_t elapsed;
	struct fd_poll fd_poll;
	struct pollfd pfds[FD_EVENTS_MAX];

	elapsed = nanoseconds - fd_event_last_check_time;
	if (elapsed < fd_event_timeout) {
		return;
	}
	throttled = -1;
	fd_poll_init(&fd_poll);
	do {
		fd_poll_set(&fd_poll, pfds);
		sys_ppoll(pfds, fd_poll.fdes_nr_used, &fd_poll.fdes_ts, NULL);
		fd_poll_call(&fd_poll, pfds);
		throttled++;
	} while (fd_poll.fdes_again);
	if (throttled) {
		fd_event_timeout >>= 1;
		if (fd_event_timeout < FD_EVENT_TIMEOUT_MIN) {
			fd_event_timeout = FD_EVENT_TIMEOUT_MIN;
		}
	} else if (fd_event_timeout < FD_EVENT_TIMEOUT_MAX) {
		fd_event_timeout += NANOSECONDS_MICROSECOND;
	}
}

void
wait_for_fd_events()
{
	struct fd_poll fd_poll;
	struct pollfd pfds[FD_EVENTS_MAX];

	fd_poll_init(&fd_poll);
	fd_poll.fdes_to = TIMER_TIMO;
	fd_poll_set(&fd_poll, pfds);
	SERVICE_UNLOCK;
	sys_ppoll(pfds, fd_poll.fdes_nr_used, &fd_poll.fdes_ts, NULL);
	SERVICE_LOCK;
	fd_poll_call(&fd_poll, pfds);
}

int
fd_event_add(struct fd_event **pe, int fd, const char *name,
	void *udata, fd_event_f fn)
{
	int i, id;
	struct fd_event *e;

	ASSERT(fd != -1);
	ASSERT(fn != NULL);
	if (fd_event_nused == ARRAY_SIZE(gt_fd_event_used)) {
		ERR(ENOMEM, "failed; event='%s', limit=%zu",
		    name, ARRAY_SIZE(gt_fd_event_used));
		return -ENOMEM;
	}
	id = -1;
	for (i = 0; i < ARRAY_SIZE(gt_fd_event_buf); ++i) {
		e = gt_fd_event_buf + i;
		if (e->fde_fd != -1) {
			if (!strcmp(e->fde_name, name)) {
				ERR(EEXIST, "failed; event='%s'", name);
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
	INFO(0, "ok; event='%s', fd=%d", e->fde_name, e->fde_fd);
	return 0;
}

static int
fd_event_unref(struct fd_event *e)
{
	int ref_cnt;
	struct fd_event *last;

	ASSERT(e->fde_ref_cnt > 0);
	e->fde_ref_cnt--;
	ref_cnt = e->fde_ref_cnt;
	if (ref_cnt == 0) {
		INFO(0, "hit; event='%s'", e->fde_name);
		ASSERT(e->fde_id < fd_event_nused);
		if (e->fde_id != fd_event_nused - 1) {
			last = gt_fd_event_used[fd_event_nused - 1];
			gt_fd_event_used[e->fde_id] = last;
			gt_fd_event_used[e->fde_id]->fde_id = e->fde_id;
		}
		fd_event_nused--;
	}
	return ref_cnt;
}

void
fd_event_del(struct fd_event *e)
{
	if (e != NULL) {
		INFO(0, "hit; event='%s'", e->fde_name);
		ASSERT(fd_event_nused);
		ASSERT(e->fde_fd != -1);
		ASSERT(e->fde_id < fd_event_nused);
		ASSERT(e == gt_fd_event_used[e->fde_id]);
		e->fde_fd = -1;
		fd_event_unref(e);
	}
}

void
fd_event_set(struct fd_event *e, short events)
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
fd_event_clear(struct fd_event *e, short events)
{
	ASSERT(events);
	ASSERT(e != NULL);
	ASSERT(e->fde_id < fd_event_nused);
	ASSERT(e == gt_fd_event_used[e->fde_id]);
	ASSERT((events & ~(POLLIN|POLLOUT)) == 0);
	e->fde_events &= ~events;
}

int
fd_event_is_set(struct fd_event *e, short events)
{
	return e->fde_events & events;
}

void
fd_poll_init(struct fd_poll *p)
{
	p->fdes_to = 0;
	p->fdes_first = 1;
}

void
fd_poll_set(struct fd_poll *p, struct pollfd *pfds)
{
	int i, idx;
	struct fd_event *e;

	ASSERT3(0, fd_event_in_cb == 0, "recursive wait");
	p->fdes_again = 0;
	if (!p->fdes_first) {
		rd_nanoseconds();
	}
	p->fdes_first = 0;
	p->fdes_time = nanoseconds;
	p->fdes_nr_used = 0;
	sock_tx_flush();
	for (i = 0; i < fd_event_nused; ++i) {
		e = gt_fd_event_used[i];
		if (e->fde_fd == -1 || e->fde_events == 0) {
			continue;
		}
		e->fde_ref_cnt++;
		idx = p->fdes_nr_used;
		pfds[idx].fd = e->fde_fd;
		pfds[idx].events = e->fde_events;
		p->fdes_used[idx] = e;
		p->fdes_nr_used++;
	}
	p->fdes_ts.tv_sec = 0;
	if (p->fdes_to == 0) {
		p->fdes_ts.tv_nsec = 0;
	} else if (p->fdes_to >= TIMER_TIMO) {
		p->fdes_ts.tv_nsec = TIMER_TIMO;
	} else {
		p->fdes_ts.tv_nsec = p->fdes_to;
	}
}

static int
fd_event_call(struct fd_event *e, short revents)
{
	int rc;

	rc = (*e->fde_fn)(e->fde_udata, revents);
	return rc;
}

int
fd_poll_call(struct fd_poll *p, struct pollfd *pfds)
{
	int i, n, rc;
	uint64_t dt;
	struct fd_event *e;

	gt_fd_event_epoch++;
	rd_nanoseconds();
	dt = nanoseconds - p->fdes_time;
	if (dt > p->fdes_to) {
		p->fdes_to = 0;
	} else {
		p->fdes_to -= dt;
	}
	check_timers();
	n = 0;
	fd_event_in_cb = 1;
	for (i = 0; i < p->fdes_nr_used; ++i) {
		e = p->fdes_used[i];
		if (pfds[i].revents) {
			n++;
			if (e->fde_fd != -1) {
				ASSERT(pfds[i].fd == e->fde_fd);
				rc = fd_event_call(e, pfds[i].revents);
				if (rc) {
					ASSERT(rc == -EAGAIN);
					p->fdes_again = 1;
				}
			}
		}
		fd_event_unref(e);
	}
	fd_event_in_cb = 0;
	if (p->fdes_again == 0) {
		fd_event_last_check_time = nanoseconds;
	}
	return n;
}
