#include "sys.h"
#include "log.h"
#include "fd_event.h"
#include "file.h"
#include "tcp.h"
#include "service.h"
#include "global.h"

#define GT_POLL_LOG_NODE_FOREACH(x) \
	x(mod_deinit) 

struct gt_poll;

struct gt_poll_entry {
	struct gt_file_cb pe_cb;
	struct gt_poll *pe_poll;
	int pe_idx;
	short pe_revents;
	short pe_added;
};

struct gt_poll {
	struct pollfd p_pfds[2 * FD_SETSIZE];
	struct gt_poll_entry p_entries[FD_SETSIZE];
	int p_npfds;
	int p_n;
};

static struct gt_log_scope this_log;
GT_POLL_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static void gt_poll_cb(struct gt_file_cb *cb, int fd, short events);

static int gt_poll_load(struct gt_poll *poll, struct pollfd *pfds,
	int npfds, uint64_t to);

static int gt_poll_fill(struct gt_poll *poll, struct pollfd *pfds, int npfds);

int
gt_poll_mod_init()
{
	gt_log_scope_init(&this_log, "poll");
	GT_POLL_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	return 0;
}

void
gt_poll_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_log_scope_deinit(log, &this_log);
}

static void
gt_poll_cb(struct gt_file_cb *cb, int fd, short events)
{
	struct gt_poll_entry *e;

	e = (struct gt_poll_entry *)cb;
	e->pe_revents |= events;
	if (e->pe_added == 0) {
		e->pe_added = 1;
		e->pe_poll->p_n++;
	}
}

static int
gt_poll_load(struct gt_poll *poll, struct pollfd *pfds, int npfds, uint64_t to)
{
	int i, n, rc, fd;
	struct pollfd *pfd;
	struct gt_file *fp;
	struct gt_poll_entry *e;

	poll->p_n = 0;
	n = 0;
	for (i = 0; i < npfds; ++i) {
		e = poll->p_entries + i;
		pfd = pfds + i;
		fd = pfd->fd;
		e->pe_poll = poll;
		e->pe_revents = 0;
		e->pe_added = 0;
		pfd->revents = 0;
		gt_mbuf_init(&e->pe_cb.fcb_mbuf);
		gt_file_cb_init(&e->pe_cb);
		rc = gt_sock_get(fd, &fp);
		if (rc == 0) {
			e->pe_idx = -1;
			gt_file_cb_set(fp, &e->pe_cb, pfd->events, gt_poll_cb);
		} else {
			e->pe_idx = n;
			poll->p_pfds[n] = *pfd;
			n++;
		}
	}
	return n;
}

static int
gt_poll_fill(struct gt_poll *poll, struct pollfd *pfds, int npfds)
{
	int i, n;
	short revents;
	struct gt_poll_entry *e;

	n = 0;
	for (i = 0; i < npfds; ++i) {
		e = poll->p_entries + i;
		if (e->pe_idx == -1) {
			pfds[i].revents = e->pe_revents;
			gt_file_cb_cancel(&e->pe_cb);
		} else {
			revents = poll->p_pfds[e->pe_idx].revents;
			pfds[i].revents = revents;
			if (revents) {
				n++;
			}
		}
	}
	return n;
}

int
gt_poll(struct pollfd *pfds, int npfds, gt_time_t to, const sigset_t *sigmask)
{
	int n, m, a, b, sys, rc, epoch;
	struct gt_poll poll;
	struct gt_fd_event_set set;

	GT_UNUSED(b);
	GT_UNUSED(a);
	if (npfds > FD_SETSIZE) {
		return -EINVAL;
	}
	sys = gt_poll_load(&poll, pfds, npfds, to);
	set.fdes_to = to;
	do {
		gt_fd_event_set_init(&set, poll.p_pfds + sys);
		epoch = gt_global_epoch;
		GT_GLOBAL_UNLOCK;
		if (poll.p_n) {
			// If some events already occured - do not wait in poll
			set.fdes_ts.tv_nsec = 0;
		}
		rc = gt_sys_ppoll(NULL, poll.p_pfds,
		                  sys + set.fdes_nr_used,
		                  &set.fdes_ts, sigmask);
		GT_GLOBAL_LOCK;
		if (epoch != gt_global_epoch) {
			return -EFAULT;
		}
		m = gt_fd_event_set_call(&set, poll.p_pfds + sys);
		if (rc < 0) {
			return rc;
		}
		n = rc - m;
		a = n;
		n += poll.p_n;
	} while (n == 0 && set.fdes_to > 0);
	b = gt_poll_fill(&poll, pfds, npfds);
	GT_ASSERT3(0, a == b, "%d, %d", a, b);
	return n;
}
