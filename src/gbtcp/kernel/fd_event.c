// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/node.h>
#include <gbtcp/kernel/subr.h>
#include <gbtcp/kernel/worker.h>

void
clean_fd_events(void)
{
	gt_current_thread.trd_fd_event_n_used = 0;
	memset(gt_current_thread.trd_fd_event_buf, 0,
	       sizeof(gt_current_thread.trd_fd_event_buf));
}

void
wait_for_fd_events2(int force, uint64_t to)
{
	int throttled;
	uint64_t elapsed;
	struct fd_poll p;

	if (!force) {
		elapsed =
			nanoseconds - gt_current_thread.trd_fd_event_drain_time;
		if (elapsed < gt_current_thread.trd_fd_event_timeout) {
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

	// Timeout adjustment (slow start algorithm)
	if (throttled) {
		gt_current_thread.trd_fd_event_timeout >>= 1;
		if (gt_current_thread.trd_fd_event_timeout <
		    FD_EVENT_TIMEOUT_MIN) {
			gt_current_thread.trd_fd_event_timeout =
				FD_EVENT_TIMEOUT_MIN;
		}
	} else if (gt_current_thread.trd_fd_event_timeout <
		   FD_EVENT_TIMEOUT_MAX) {
		gt_current_thread.trd_fd_event_timeout += GT_NSEC_PER_USEC;
	}
}

int
fd_event_add(struct fd_event **pe, int fd, void *udata, fd_event_f fn)
{
	int i, id;
	struct fd_event *e;

	assert(fd >= 0);
	assert(fn != NULL);
	assert(gt_current_thread.trd_fd_event_n_used <
	       GT_ARRAY_SIZE(gt_current_thread.trd_fd_event_used));
	id = -1;
	for (i = 0; i < GT_ARRAY_SIZE(gt_current_thread.trd_fd_event_buf);
	     ++i) {
		e = gt_current_thread.trd_fd_event_buf + i;
		if (e->fde_ref_cnt) {
			if (e->fde_fn != NULL && e->fde_fd == fd) {
				gt_die(0,
				       "Add duplicate fd to multiplexer; fd=%d",
				       fd);
			}
		} else {
			if (id == -1) {
				id = i;
			}
		}
	}
	assert(id != -1);
	e = gt_current_thread.trd_fd_event_buf + id;
	memset(e, 0, sizeof(*e));
	e->fde_fd = fd;
	e->fde_ref_cnt = 1;
	e->fde_events = 0;
	e->fde_fn = fn;
	e->fde_udata = udata;
	e->fde_id = gt_current_thread.trd_fd_event_n_used;
	gt_current_thread.trd_fd_event_used[e->fde_id] = e;
	gt_current_thread.trd_fd_event_n_used++;
	*pe = e;
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
		assert(e->fde_id < gt_current_thread.trd_fd_event_n_used);
		if (e->fde_id != gt_current_thread.trd_fd_event_n_used - 1) {
			last = gt_current_thread.trd_fd_event_used
				       [gt_current_thread.trd_fd_event_n_used -
					1];
			gt_current_thread.trd_fd_event_used[e->fde_id] = last;
			gt_current_thread.trd_fd_event_used[e->fde_id]->fde_id =
				e->fde_id;
		}
		gt_current_thread.trd_fd_event_n_used--;
	}
	return ref_cnt;
}

void
fd_event_del(struct fd_event *e)
{
	if (e != NULL) {
		assert(e->fde_fn != NULL);
		assert(e->fde_id < gt_current_thread.trd_fd_event_n_used);
		assert(e == gt_current_thread.trd_fd_event_used[e->fde_id]);
		e->fde_fn = NULL;
		fd_event_unref(e);
	}
}

void
fd_event_set(struct fd_event *e, short events)
{
	assert(events);
	assert((events & ~(POLLIN | POLLOUT)) == 0);
	assert(e != NULL);
	assert(e->fde_ref_cnt);
	assert(e->fde_id < gt_current_thread.trd_fd_event_n_used);
	assert(e == gt_current_thread.trd_fd_event_used[e->fde_id]);
	e->fde_events |= events;
}

void
fd_event_clear(struct fd_event *e, short events)
{
	assert(events);
	assert(e != NULL);
	assert(e->fde_id < gt_current_thread.trd_fd_event_n_used);
	assert(e == gt_current_thread.trd_fd_event_used[e->fde_id]);
	assert((events & ~(POLLIN | POLLOUT)) == 0);
	e->fde_events &= ~events;
}

int
fd_event_is_set(struct fd_event *e, short events)
{
	return e->fde_events & events;
}

void
gt_deferred_init(struct gt_deferred_entry *de)
{
	de->deferred_fn = NULL;
}

void
gt_deferred_add(struct gt_dlist *deferred_head, struct gt_deferred_entry *de,
		gt_deferred_f fn)
{
	if (de->deferred_fn == NULL) {
		de->deferred_fn = fn;
		GT_DLIST_INSERT_TAIL(deferred_head, de, deferred_link);
	}
}

void
gt_deferred_cancel(struct gt_deferred_entry *de)
{
	if (de->deferred_fn != NULL) {
		GT_DLIST_REMOVE(de, deferred_link);
		de->deferred_fn = NULL;
	}
}

static void
gt_deferred_call(struct gt_dlist *deferred_head)
{
	gt_deferred_f fn;
	struct gt_deferred_entry *de;

	while (!gt_dlist_is_empty(deferred_head)) {
		de = GT_DLIST_FIRST(deferred_head, struct gt_deferred_entry,
				    deferred_link);
		fn = de->deferred_fn;
		gt_deferred_cancel(de);
		(*fn)(de);
	}
}

void
fd_poll_init(struct fd_poll *p)
{
	p->fdp_to = 0;
	p->fdp_n_added = 0;
	p->fdp_n_events = 0;
}

static int
fd_event_call(struct fd_event *e, short revents, struct gt_dlist *deferred_head)
{
	int rc;

	rc = (*e->fde_fn)(e->fde_udata, revents, deferred_head);
	return rc;
}

int
fd_poll_add3(struct fd_poll *p, int fd, short events)
{
	int i;

	i = p->fdp_n_added;
	if (i == GT_ARRAY_SIZE(p->fdp_pfds)) {
		return -ENFILE;
	}

	p->fdp_n_added++;
	p->fdp_pfds[i].fd = fd;
	p->fdp_pfds[i].events = events;
	p->fdp_pfds[i].revents = 0;
	return i;
}

int
fd_poll_wait(struct fd_poll *p, const sigset_t *sigmask)
{
	int i, rc, n_triggered;
	uint64_t t, elapsed;
	struct timespec to;
	struct gt_dlist deferred_head;
	const sigset_t *fd_poll_sigmask;
	struct pollfd *pfd;
	struct fd_event *e;

	// ????
	if (gt_current_thread.trd_fd_poll_is_waiting) {
		return -EAGAIN;
	}
	p->fdp_throttled = 0;
	p->fdp_n_events = 0;
	if (current != NULL) {
		gt_worker_tx();
	}
	for (i = 0; i < gt_current_thread.trd_fd_event_n_used; ++i) {
		if (p->fdp_n_added + p->fdp_n_events == FD_SETSIZE) {
			break;
		}
		e = gt_current_thread.trd_fd_event_used[i];
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
	} else if (p->fdp_to >= GT_TIMER_EXPIRE_MIN) {
		to.tv_nsec = GT_TIMER_EXPIRE_MIN;
	} else {
		to.tv_nsec = p->fdp_to;
	}
	t = nanoseconds;
	fd_poll_sigmask = sigmask;
	if (fd_poll_sigmask == NULL) {
		fd_poll_sigmask = &gt_current_thread.trd_sigprocmask;
	}
	SERVICE_UNLOCK;
	rc = sys_ppoll(p->fdp_pfds, p->fdp_n_added + p->fdp_n_events, &to,
		       fd_poll_sigmask);
	rd_nanoseconds();
	elapsed = nanoseconds - t;
	if (elapsed > p->fdp_to) {
		p->fdp_to = 0;
	} else {
		p->fdp_to -= elapsed;
	}
	// FIXME: current?
	if (current != NULL) {
		gt_timer_wheel_run(&current->wrk_timer_wheel);
	}
	if (rc < 0) {
		return rc;
	}
	n_triggered = rc;
	gt_current_thread.trd_fd_poll_is_waiting = 1;
	gt_dlist_init(&deferred_head);
	for (i = 0; i < p->fdp_n_events; ++i) {
		e = p->fdp_events[i];
		pfd = p->fdp_pfds + p->fdp_n_added + i;
		if (pfd->revents) {
			assert(n_triggered);
			n_triggered--;
			if (e->fde_fn != NULL) {
				assert(pfd->fd == e->fde_fd);
				rc = fd_event_call(e, pfd->revents,
						   &deferred_head);
				if (rc) {
					assert(rc == -EAGAIN);
					p->fdp_throttled = 1;
				}
			}
			pfd->revents = 0;
		}
		fd_event_unref(e);
	}
	gt_current_thread.trd_fd_poll_is_waiting = 0;
	gt_deferred_call(&deferred_head);
	if (p->fdp_throttled == 0) {
		gt_current_thread.trd_fd_event_drain_time = nanoseconds;
	}
	return n_triggered;
}
