// GPL v2
#include "internals.h"

#define CURMOD fd_event

// We should periodically RX devices to avoid packet loss 
#define FD_EVENT_TIMEOUT_MIN (20 * NSEC_USEC)
#define FD_EVENT_TIMEOUT_MAX (60 * NSEC_USEC) 


void
fd_thread_wait3(struct fd_thread *t, int force, uint64_t to)
{
	int throttled;
	uint64_t elapsed;
	struct fd_poll p;

	if (!force) {
		elapsed = nanoseconds - t->fdt_drain_time;
		if (elapsed < t->fdt_timeout) {
			return;
		}
	}
	throttled = 0;
	fd_poll_init(&p);
	p.fdp_to = to;
	while (1) {
		fd_poll_wait(&p, NULL);
		if (p.fdp_throttled) {
			throttled = 1;
		} else {
			break;
		}
	}
	if (throttled) {
		t->fdt_timeout >>= 1;
		if (t->fdt_timeout < FD_EVENT_TIMEOUT_MIN) {
			t->fdt_timeout = FD_EVENT_TIMEOUT_MIN;
		}
	} else if (t->fdt_timeout < FD_EVENT_TIMEOUT_MAX) {
		t->fdt_timeout += NSEC_USEC;
	}
}

struct fd_event *
fd_event_add(struct fd_thread *t, int fd, void *udata, fd_event_f fn)
{
	int i, id;
	struct fd_event *e;

	assert(fn != NULL);
	assert(t->fdt_n_used < ARRAY_SIZE(t->fdt_used));
	id = -1;
	for (i = 0; i < ARRAY_SIZE(t->fdt_buf); ++i) {
		e = t->fdt_buf + i;
		if (e->fde_ref_cnt) {
			if (e->fde_fn != NULL && e->fde_fd == fd) {
				die(0, "fd event already exists; fd=%d", fd);
			}
		} else {
			if (id == -1) {
				id = i;
			}
		}
	}
	assert(id != -1);
	e = t->fdt_buf + id;
	memset(e, 0, sizeof(*e));
	e->fde_fd = fd;
	e->fde_ref_cnt = 1;
	e->fde_events = 0;
	e->fde_fn = fn;
	e->fde_udata = udata;
	e->fde_id = t->fdt_n_used;
	e->fde_thread = t;
	t->fdt_used[e->fde_id] = e;
	t->fdt_n_used++;
	INFO(0, "add fd event; fd=%d, event='%s'", e->fde_fd);
	return e;
}

static int
fd_event_unref(struct fd_event *e)
{
	int ref_cnt;
	struct fd_thread *t;
	struct fd_event *last;

	assert(e->fde_ref_cnt > 0);
	t = e->fde_thread;
	e->fde_ref_cnt--;
	ref_cnt = e->fde_ref_cnt;
	if (ref_cnt == 0) {
		INFO(0, "free fd event; fd=%d", e->fde_fd);
		assert(e->fde_id < t->fdt_n_used);
		if (e->fde_id != t->fdt_n_used - 1) {
			last = t->fdt_used[t->fdt_n_used - 1];
			t->fdt_used[e->fde_id] = last;
			t->fdt_used[e->fde_id]->fde_id = e->fde_id;
		}
		t->fdt_n_used--;
	}
	return ref_cnt;
}

void
fd_event_del(struct fd_event *e)
{
	if (e != NULL) {
		INFO(0, "del fd event; fd=%d", e->fde_fd);
		assert(e->fde_fn != NULL);
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
	e->fde_events |= events;
}

void
fd_event_clear(struct fd_event *e, short events)
{
	assert(events);
	assert(e != NULL);
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

static int
fd_event_call(struct fd_event *e, short revents)
{
	int rc;

	rc = (*e->fde_fn)(e->fde_udata, revents);
	return rc;
}

int
fd_poll_add3(struct fd_poll *p, int fd, short events)
{
	int i;

	i = p->fdp_n_added;
	if (i == ARRAY_SIZE(p->fdp_pfds)) {
		return -ENFILE;
	} else {
		p->fdp_n_added++;
		p->fdp_pfds[i].fd = fd;
		p->fdp_pfds[i].events = events;
		p->fdp_pfds[i].revents = 0;
		return i;
	}
}

int
fd_poll_wait(struct fd_poll *p, const sigset_t *sigmask)
{
	int i, rc, n_triggered;
	uint64_t now, elapsed;
	struct timespec to;
	const sigset_t *fd_poll_sigmask;
	struct pollfd *pfd;
	struct fd_thread *t;
	struct fd_event *e;

	t = current_fd_thread;
	if (t->fdt_is_waiting) {
		return -EAGAIN;
	}
	p->fdp_throttled = 0;
	p->fdp_n_events = 0;
	sock_tx_flush();
	for (i = 0; i < t->fdt_n_used; ++i) {
		if (p->fdp_n_added + p->fdp_n_events == FD_SETSIZE) {
			break;
		}
		e = t->fdt_used[i];
		if (e->fde_fn == NULL || e->fde_events == 0) {
			continue;
		}
		e->fde_ref_cnt++;
		pfd = p->fdp_pfds + p->fdp_n_added + p->fdp_n_events;
		pfd->fd = e->fde_fd;
		pfd->events = e->fde_events;
		p->fdp_events[p->fdp_n_events++] = e;
	}
	to.tv_sec = 0;
	if (p->fdp_to == 0) {
		to.tv_nsec = 0;
	} else if (p->fdp_to >= TIMER_TIMEOUT) {
		to.tv_nsec = TIMER_TIMEOUT;
	} else {
		to.tv_nsec = p->fdp_to;
	}
	now = nanoseconds;
	fd_poll_sigmask = sigmask;
	if (fd_poll_sigmask == NULL) {
		fd_poll_sigmask = signal_sigprocmask_get();
	}
	SERVICE_UNLOCK;
	rc = sys_ppoll(p->fdp_pfds, p->fdp_n_added + p->fdp_n_events,
		&to, fd_poll_sigmask);
	SERVICE_LOCK;
	elapsed = nanoseconds - now;
	if (elapsed > p->fdp_to) {
		p->fdp_to = 0;
	} else {
		p->fdp_to -= elapsed;
	}
	run_timers();
	if (rc < 0) {
		return rc;
	}
	n_triggered = rc;
	t->fdt_is_waiting = 1;
	for (i = 0; i < p->fdp_n_events; ++i) {
		e = p->fdp_events[i];
		pfd = p->fdp_pfds + p->fdp_n_added + i;
		if (pfd->revents) {
			assert(n_triggered);
			n_triggered--;
			if (e->fde_fn != NULL) {
				assert(pfd->fd == e->fde_fd);
				rc = fd_event_call(e, pfd->revents);
				if (rc) {
					assert(rc == -EAGAIN);
					p->fdp_throttled = 1;
				}
			}
			pfd->revents = 0;
		}
		fd_event_unref(e);
	}
	t->fdt_is_waiting = 0;
	if (p->fdp_throttled == 0) {
		t->fdt_drain_time = nanoseconds;
	}
	return n_triggered;
}
