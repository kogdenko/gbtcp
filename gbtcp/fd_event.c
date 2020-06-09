#include "internals.h"

#define CURMOD fd_event

// System should periodically RX netmap devices or packets would be lost
#define FD_EVENT_TIMEOUT_MIN (20 * NANOSECONDS_MICROSECOND)
#define FD_EVENT_TIMEOUT_MAX (60 * NANOSECONDS_MICROSECOND) 

int fd_poll_epoch;

static uint64_t fd_event_last_check_time;
static uint64_t fd_event_timeout = FD_EVENT_TIMEOUT_MIN;
static int fd_event_nused;
static int fd_event_in_cb;
static struct fd_event *fd_event_used[FD_EVENTS_MAX];
static struct fd_event fd_event_buf[FD_EVENTS_MAX];

void
clean_fd_events()
{
	fd_event_nused = 0;
	memset(fd_event_buf, 0, sizeof(fd_event_buf));
}

void
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

int
fd_event_add(struct fd_event **pe, int fd, const char *name,
	void *udata, fd_event_f fn)
{
	int i, id;
	struct fd_event *e;

	assert(fn != NULL);
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
	assert(id != -1);
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

	assert(e->fde_ref_cnt > 0);
	e->fde_ref_cnt--;
	ref_cnt = e->fde_ref_cnt;
	if (ref_cnt == 0) {
		INFO(0, "hit; fd=%d", e->fde_fd);
		assert(e->fde_id < fd_event_nused);
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
		assert(e->fde_fn != NULL);
		assert(e->fde_id < fd_event_nused);
		assert(e == fd_event_used[e->fde_id]);
		e->fde_fn = NULL;
		fd_event_unref(e);
	}
}

void
fd_event_set(struct fd_event *e, short events)
{	
	assert(events);
	assert((events & ~(POLLIN|POLLOUT)) == 0);
	assert(e != NULL);
	assert(e->fde_ref_cnt);
	assert(e->fde_id < fd_event_nused);
	assert(e == fd_event_used[e->fde_id]);
	e->fde_events |= events;
}

void
fd_event_clear(struct fd_event *e, short events)
{
	assert(events);
	assert(e != NULL);
	assert(e->fde_id < fd_event_nused);
	assert(e == fd_event_used[e->fde_id]);
	assert((events & ~(POLLIN|POLLOUT)) == 0);
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
	p->fdp_n_added = 0;
	p->fdp_n_events = 0;
}

void
fd_poll_add_fd_events(struct fd_poll *p)
{
	int i;
	struct fd_event *e;

	assert(fd_event_in_cb == 0 && "recursive wait");
	p->fdp_throttled = 0;
	p->fdp_time = nanoseconds;
	p->fdp_n_events = 0;
	sock_tx_flush();
	for (i = 0; i < fd_event_nused; ++i) {
		if (p->fdp_n_added + p->fdp_n_events == FD_SETSIZE) {
			break;
		}
		e = fd_event_used[i];
		if (e->fde_fn == NULL || e->fde_events == 0) {
			continue;
		}
		e->fde_ref_cnt++;
		pfds[p->fdp_n_events].fd = e->fde_fd;
		pfds[p->fdp_n_events].events = e->fde_events;
		p->fdp_events[p->fdp_n_events++] = e;
	}
	p->fdp_to_ts.tv_sec = 0;
	if (p->fdp_to == 0) {
		p->fdp_to_ts.tv_nsec = 0;
	} else if (p->fdp_to >= TIMER_TIMEOUT) {
		p->fdp_to_ts.tv_nsec = TIMER_TIMEOUT;
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
fd_poll_call(struct fd_poll *p)
{
	int i, n, rc;
	uint64_t elapsed;
	struct fd_event *e;

	fd_poll_epoch++;
	elapsed = nanoseconds - p->fdp_time;
	if (elapsed > p->fdp_to) {
		p->fdp_to = 0;
	} else {
		p->fdp_to -= elapsed;
	}
	check_timers();
	n = 0;
	fd_event_in_cb = 1;
	for (i = 0; i < p->fdp_n_events; ++i) {
		e = p->fdp_used[i];
		if (pfds[i].revents) {
			n++;
			if (e->fde_fn != NULL) {
				assert(pfds[i].fd == e->fde_fd);
				rc = fd_event_call(e, pfds[i].revents);
				if (rc) {
					assert(rc == -EAGAIN);
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
