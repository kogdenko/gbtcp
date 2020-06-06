#include "internals.h"

struct poll;

struct poll_entry {
	struct file_aio e_aio;
#define e_mbuf e_aio.faio_mbuf
	struct poll *e_poll;
	int e_id;
	short e_revents;
	short e_triggered;
};

struct poll {
	struct pollfd p_pfds[2 * FD_SETSIZE];
	struct poll_entry p_entries[FD_SETSIZE];
	int p_npfds;
	int p_ntriggered;
};

static void
poll_trigger(struct file_aio *aio, int fd, short revents)
{
	struct poll_entry *e;

	e = (struct poll_entry *)aio;
	e->e_revents |= revents;
	if (e->e_triggered == 0) {
		e->e_triggered = 1;
		e->e_poll->p_ntriggered++;
		if (revents & POLLNVAL) {
			file_aio_cancel(&e->e_aio);
		}
	}
}

static int
poll_init(struct poll *poll, struct pollfd *pfds, int npfds)
{
	int i, n, rc, fd;
	struct pollfd *pfd;
	struct sock *so;
	struct poll_entry *e;

	poll->p_ntriggered = 0;
	n = 0;
	for (i = 0; i < npfds; ++i) {
		e = poll->p_entries + i;
		pfd = pfds + i;
		fd = pfd->fd;
		e->e_poll = poll;
		e->e_revents = 0;
		e->e_triggered = 0;
		pfd->revents = 0;
		mbuf_init(&e->e_mbuf);
		file_aio_init(&e->e_aio);
		rc = so_get(fd, &so);
		if (rc == 0) {
			e->e_id = -fd;
			file_aio_set(&so->so_file, &e->e_aio,
			             pfd->events, poll_trigger);
		} else {
			e->e_id = n;
			poll->p_pfds[n++] = *pfd;
		}
	}
	return n;
}

static int
poll_read_events(struct poll *poll, struct pollfd *pfds, int npfds)
{
	int i, rc, ntriggered;
	short revents;
	struct sock *so;
	struct poll_entry *e;

	ntriggered = 0;
	for (i = 0; i < npfds; ++i) {
		e = poll->p_entries + i;
		if (e->e_id < 0) {
			pfds[i].revents = e->e_revents;
			rc = so_get(-e->e_id, &so);
			if (rc == 0) {
				file_aio_cancel(&e->e_aio);
			}
		} else {
			revents = poll->p_pfds[e->e_id].revents;
			pfds[i].revents = revents;
			if (revents) {
				ntriggered++;
			}
		}
	}
	return ntriggered;
}

int
u_poll(struct pollfd *pfds, int npfds, uint64_t to, const sigset_t *sigmask)
{
	int n, m, a, b, sys, rc;
	struct poll poll;
	struct fd_poll fd_poll;

	UNUSED(b);
	UNUSED(a);
	if (npfds > FD_SETSIZE) {
		return -EINVAL;
	}
	sys = poll_init(&poll, pfds, npfds);
	fd_poll_init(&fd_poll);
	fd_poll.fdp_to = to;
	do {
		fd_poll_set(&fd_poll, poll.p_pfds + sys);
		SERVICE_UNLOCK;
		if (poll.p_ntriggered) {
			fd_poll.fdp_to_ts.tv_nsec = 0;
		}
		rc = sys_ppoll(poll.p_pfds,
		               sys + fd_poll.fdp_nused,
		               &fd_poll.fdp_to_ts, sigmask);
		SERVICE_LOCK;
		m = fd_poll_call(&fd_poll, poll.p_pfds + sys);
		if (rc < 0) {
			return rc;
		}
		n = rc - m;
		a = n;
		n += poll.p_ntriggered;
	} while (n == 0 && fd_poll.fdp_to > 0);
	b = poll_read_events(&poll, pfds, npfds);
	assert(a == b);
	return n;
}
