#include "internals.h"

// System should periodically RX netmap devices or packets would be lost
#define FD_EVENT_TIMEOUT_MIN (20 * NANOSECONDS_MICROSECOND)
#define FD_EVENT_TIMEOUT_MAX (60 * NANOSECONDS_MICROSECOND) 

struct fd_event_mod {
	struct log_scope log_scope;
};

int fd_poll_epoch;

static uint64_t fd_event_last_check_time;
static uint64_t fd_event_timeout = FD_EVENT_TIMEOUT_MIN;
static int fd_event_nused;
static int fd_event_in_cb;
static struct fd_event *fd_event_used[FD_EVENTS_MAX];
static struct fd_event fd_event_buf[FD_EVENTS_MAX];
static struct fd_event_mod *curmod;

int
fd_event_mod_init(void **pp)
{
	int rc;

	rc = shm_malloc(pp, sizeof(*curmod));
	if (!rc) {
		curmod = *pp;
		log_scope_init(&curmod->log_scope, "fd_event");
	}
	return rc;
}

int
fd_event_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
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
	memset(fd_event_buf, 0, sizeof(fd_event_buf));
	curmod = NULL;
}

static void
wait_for_fd_events2(int force, uint64_t to)
{
	int throttled;
	uint64_t elapsed;
	struct fd_poll p;
	struct pollfd pfds[FD_EVENTS_MAX];

	if (!force) {
		elapsed = nanoseconds - fd_event_last_check_time;
		if (elapsed < fd_event_timeout) {
			return;
		}
	}
	throttled = 0;
	fd_poll_init(&p);
	p.fdp_to = to;
	while (1) {
		fd_poll_set(&p, pfds);
		SERVICE_UNLOCK;
		sys_ppoll(pfds, p.fdp_nused, &p.fdp_to_ts, NULL);
		SERVICE_LOCK;
		fd_poll_call(&p, pfds);
		if (p.fdp_throttled) {
			throttled = 1;
		} else {
			break;
		}
	}
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
check_fd_events()
{
	wait_for_fd_events2(0, 0);
}

void
wait_for_fd_events()
{
#if 1
	wait_for_fd_events2(1, TIMER_TIMO);
#else
	struct fd_poll fd_poll;
	struct pollfd pfds[FD_EVENTS_MAX];

	fd_poll_init(&fd_poll);
	fd_poll.fdes_to = TIMER_TIMO;
	fd_poll_set(&fd_poll, pfds);
	SERVICE_UNLOCK;
	sys_ppoll(pfds, fd_poll.fdes_nr_used, &fd_poll.fdes_ts, NULL);
	SERVICE_LOCK;
	fd_poll_call(&fd_poll, pfds);
#endif
}

int
fd_event_add(struct fd_event **pe, int fd, const char *name,
	void *udata, fd_event_f fn)
{
	int i, id;
	struct fd_event *e;

	ASSERT(fn != NULL);
	if (fd_event_nused == ARRAY_SIZE(fd_event_used)) {
		ERR(ENOMEM, "failed; fd=%d, event='%s', limit=%zu",
		    fd, name, ARRAY_SIZE(fd_event_used));
		return -ENOMEM;
	}
	id = -1;
	for (i = 0; i < ARRAY_SIZE(fd_event_buf); ++i) {
		e = fd_event_buf + i;
		if (e->fde_ref_cnt) {
			if (e->fde_fd == fd) {
				ERR(EEXIST, "failed; fd=%d, event='%s'",
			    	    fd, name);
				return -EEXIST;
			}
		} else {
			if (id == -1) {
				id = i;
			}
		}
	}
	ASSERT(id != -1);
	e = fd_event_buf + id;
	memset(e, 0, sizeof(*e));
	e->fde_fd = fd;
	e->fde_ref_cnt = 1;
	e->fde_events = 0;
	e->fde_fn = fn;
	e->fde_udata = udata;
	e->fde_id = fd_event_nused;
	fd_event_used[e->fde_id] = e;
	fd_event_nused++;
	*pe = e;
	INFO(0, "ok; fd=%d, event='%s'", e->fde_fd, name);
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
		INFO(0, "hit; fd=%d", e->fde_fd);
		ASSERT(e->fde_id < fd_event_nused);
		if (e->fde_id != fd_event_nused - 1) {
			last = fd_event_used[fd_event_nused - 1];
			fd_event_used[e->fde_id] = last;
			fd_event_used[e->fde_id]->fde_id = e->fde_id;
		}
		fd_event_nused--;
	}
	return ref_cnt;
}

void
fd_event_del(struct fd_event *e)
{
	if (e != NULL) {
		INFO(0, "hit; fd=%d", e->fde_fd);
		ASSERT(e->fde_fn != NULL);
		ASSERT(e->fde_id < fd_event_nused);
		ASSERT(e == fd_event_used[e->fde_id]);
		e->fde_fn = NULL;
		fd_event_unref(e);
	}
}

void
fd_event_set(struct fd_event *e, short events)
{	
	ASSERT(events);
	ASSERT((events & ~(POLLIN|POLLOUT)) == 0);
	ASSERT(e != NULL);
	ASSERT(e->fde_ref_cnt);
	ASSERT(e->fde_id < fd_event_nused);
	ASSERT(e == fd_event_used[e->fde_id]);
	e->fde_events |= events;
}

void
fd_event_clear(struct fd_event *e, short events)
{
	ASSERT(events);
	ASSERT(e != NULL);
	ASSERT(e->fde_id < fd_event_nused);
	ASSERT(e == fd_event_used[e->fde_id]);
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
	p->fdp_to = 0;
	p->fdp_first = 1;
}

void
fd_poll_set(struct fd_poll *p, struct pollfd *pfds)
{
	int i;
	struct fd_event *e;

	ASSERT3(0, fd_event_in_cb == 0, "recursive wait");
	p->fdp_throttled = 0;
//	if (!p->fdp_first) {
//		rd_nanoseconds();
//	}
//	p->fdp_first = 0;
	p->fdp_time = nanoseconds;
	p->fdp_nused = 0;
	sock_tx_flush();
	for (i = 0; i < fd_event_nused; ++i) {
		e = fd_event_used[i];
		if (e->fde_fn == NULL || e->fde_events == 0) {
			continue;
		}
		e->fde_ref_cnt++;
		pfds[p->fdp_nused].fd = e->fde_fd;
		pfds[p->fdp_nused].events = e->fde_events;
		p->fdp_used[p->fdp_nused++] = e;
	}
	p->fdp_to_ts.tv_sec = 0;
	if (p->fdp_to == 0) {
		p->fdp_to_ts.tv_nsec = 0;
	} else if (p->fdp_to >= TIMER_TIMO) {
		p->fdp_to_ts.tv_nsec = TIMER_TIMO;
	} else {
		p->fdp_to_ts.tv_nsec = p->fdp_to;
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
	uint64_t elapsed;
	struct fd_event *e;

	fd_poll_epoch++;
	rd_nanoseconds();
	elapsed = nanoseconds - p->fdp_time;
	if (elapsed > p->fdp_to) {
		p->fdp_to = 0;
	} else {
		p->fdp_to -= elapsed;
	}
	check_timers();
	n = 0;
	fd_event_in_cb = 1;
	for (i = 0; i < p->fdp_nused; ++i) {
		e = p->fdp_used[i];
		if (pfds[i].revents) {
			n++;
			if (e->fde_fn != NULL) {
				ASSERT(pfds[i].fd == e->fde_fd);
				rc = fd_event_call(e, pfds[i].revents);
				if (rc) {
					ASSERT(rc == -EAGAIN);
					p->fdp_throttled = 1;
				}
			}
		}
		fd_event_unref(e);
	}
	fd_event_in_cb = 0;
	if (p->fdp_throttled == 0) {
		fd_event_last_check_time = nanoseconds;
	}
	return n;
}
