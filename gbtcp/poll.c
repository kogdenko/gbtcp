#include "internals.h"

struct poll;

struct poll_mod {
	struct log_scope log_scope;
};

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

static struct poll_mod *curmod;

int
poll_mod_init(void **pp)
{
	int rc;
	struct poll_mod *mod;

	rc = shm_malloc(pp, sizeof(*mod));
	if (rc == 0) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "poll");
	}
	return rc;
}

int
poll_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
poll_mod_deinit(void *raw_mod)
{
	struct poll_mod *mod;

	mod = raw_mod;
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
poll_mod_detach()
{
	curmod = NULL;
}

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
poll_init(struct poll *poll, struct pollfd *pfds, int npfds, uint64_t to)
{
	int i, n, rc, fd;
	struct pollfd *pfd;
	struct gt_sock *so;
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
	struct gt_sock *so;
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
	struct gt_fd_event_set set;

	UNUSED(b);
	UNUSED(a);
	if (npfds > FD_SETSIZE) {
		return -EINVAL;
	}
	sys = poll_init(&poll, pfds, npfds, to);
	set.fdes_to = to;
	do {
		gt_fd_event_set_init(&set, poll.p_pfds + sys);
		SERVICE_UNLOCK;
		if (poll.p_ntriggered) {
			set.fdes_ts.tv_nsec = 0;
		}
		rc = sys_ppoll(poll.p_pfds,
		               sys + set.fdes_nr_used,
		               &set.fdes_ts, sigmask);
		SERVICE_LOCK;
		m = gt_fd_event_set_call(&set, poll.p_pfds + sys);
		if (rc < 0) {
			return rc;
		}
		n = rc - m;
		a = n;
		n += poll.p_ntriggered;
	} while (n == 0 && set.fdes_to > 0);
	b = poll_read_events(&poll, pfds, npfds);
	ASSERT3(0, a == b, "%d, %d", a, b);
	return n;
}
