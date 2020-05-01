#include "sys.h"
#include "log.h"
#include "fd_event.h"
#include "file.h"
#include "mm.h"
#include "tcp.h"
#include "service.h"
#include "global.h"

struct gt_poll;

struct poll_mod {
	struct log_scope log_scope;
};

struct poll_entry {
	struct file_aio pe_aio;
	struct gt_poll *pe_poll;
	int pe_idx;
	short pe_revents;
	short pe_added;
};

struct gt_poll {
	struct pollfd p_pfds[2 * FD_SETSIZE];
	struct poll_entry p_entries[FD_SETSIZE];
	int p_npfds;
	int p_n;
};

static struct poll_mod *curmod;

int
poll_mod_init(struct log *log, void **pp)
{
	int rc;
	struct poll_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "poll");
	return 0;
}

int
poll_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
poll_mod_deinit(struct log *log, void *raw_mod)
{
	struct poll_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
poll_mod_detach(struct log *log)
{
	curmod = NULL;
}

static void
poll_aio(struct file_aio *aio, int fd, short events)
{
	struct poll_entry *e;
	e = (struct poll_entry *)aio;
	e->pe_revents |= events;
	if (e->pe_added == 0) {
		e->pe_added = 1;
		e->pe_poll->p_n++;
	}
}

static int
poll_load(struct gt_poll *poll, struct pollfd *pfds, int npfds, uint64_t to)
{
	int i, n, rc, fd;
	struct pollfd *pfd;
	struct file *fp;
	struct poll_entry *e;
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
		mbuf_init(&e->pe_aio.faio_mbuf);
		file_aio_init(&e->pe_aio);
		rc = gt_sock_get(fd, &fp);
		if (rc == 0) {
			e->pe_idx = -1;
			file_aio_set(fp, &e->pe_aio, pfd->events, poll_aio);
		} else {
			e->pe_idx = n;
			poll->p_pfds[n] = *pfd;
			n++;
		}
	}
	return n;
}
static int
poll_fill(struct gt_poll *poll, struct pollfd *pfds, int npfds)
{
	int i, n;
	short revents;
	struct poll_entry *e;
	n = 0;
	for (i = 0; i < npfds; ++i) {
		e = poll->p_entries + i;
		if (e->pe_idx == -1) {
			pfds[i].revents = e->pe_revents;
			file_aio_cancel(&e->pe_aio);
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
gt_poll(struct pollfd *pfds, int npfds, uint64_t to, const sigset_t *sigmask)
{
	int n, m, a, b, sys, rc, epoch;
	struct gt_poll poll;
	struct gt_fd_event_set set;
	UNUSED(b);
	UNUSED(a);
	if (npfds > FD_SETSIZE) {
		return -EINVAL;
	}
	sys = poll_load(&poll, pfds, npfds, to);
	set.fdes_to = to;
	do {
		gt_fd_event_set_init(&set, poll.p_pfds + sys);
		epoch = gt_global_epoch;
		GT_GLOBAL_UNLOCK;
		if (poll.p_n) {
			// If some events already occured - do not wait in poll
			set.fdes_ts.tv_nsec = 0;
		}
		rc = sys_ppoll(NULL, poll.p_pfds,
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
	b = poll_fill(&poll, pfds, npfds);
	ASSERT3(0, a == b, "%d, %d", a, b);
	return n;
}
