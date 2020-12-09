// gpl2 license
#include "internals.h"

struct poll_entry {
	struct file_aio pe_aio;
#define pe_mbuf pe_aio.faio_mbuf
	int *pe_n_triggered;
	short pe_filter;
	short pe_revents;
};

static void
poll_handler(void *aio_ptr, int fd, short revents)
{
	short fr;
	struct poll_entry *e;

	e = container_of(aio_ptr, struct poll_entry, pe_aio);
	fr = revents & (e->pe_filter|POLLERR|POLLHUP|POLLNVAL);
	if (fr != 0) {
		if (e->pe_revents == 0) {
			(*e->pe_n_triggered)++;
		}
		e->pe_revents |= fr;
		if (fr & POLLNVAL) {
			file_aio_cancel(&e->pe_aio);
		}
	}
}

int
u_poll(struct pollfd *pfds, int npfds, uint64_t to, const sigset_t *sigmask)
{
	int i, fd, rc, n_triggered;
	struct pollfd *pfd;
	struct sock *so;
	struct fd_poll p;
	struct poll_entry *e, entries[FD_SETSIZE];

	if (npfds > FD_SETSIZE) {
		return -EINVAL;
	}
	fd_poll_init(&p);
	p.fdp_to = to;
	n_triggered = 0;
	for (i = 0; i < npfds; ++i) {
		e = entries + i;
		pfd = pfds + i;
		pfd->revents = 0;
		fd = pfd->fd;
		e->pe_revents = 0;
		e->pe_filter = pfd->events;
		e->pe_n_triggered = NULL;
		rc = so_get(pfd->fd, &so);
		if (rc == 0) {
			// gbtcp fd
			fd = -1;
			mbuf_init(&e->pe_mbuf);
			file_aio_init(&e->pe_aio);
			e->pe_n_triggered = &n_triggered;
			file_aio_add(&so->so_file, &e->pe_aio, poll_handler);
		}
		rc = fd_poll_add3(&p, fd, pfd->events);
		assert(rc == i);
	}
	do {
		if (n_triggered) {
			p.fdp_to = 0;
		}
		rc = fd_poll_wait(&p, sigmask);
		if (rc < 0) {
			return rc;
		}
		n_triggered += rc;
	} while (n_triggered == 0 && p.fdp_to > 0);
	for (i = 0; i < npfds; ++i) {
		pfd = p.fdp_pfds + i;
		e = entries + i;
		if (e->pe_n_triggered != NULL) {
			// gfbtcp fd
			pfds[i].revents = e->pe_revents;
			file_aio_cancel(&e->pe_aio);
		} else {
			pfds[i].revents = pfd->revents;
		}
	}
	return n_triggered;
}
