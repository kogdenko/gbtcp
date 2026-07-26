// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/socket/file.h>
#include <gbtcp/kernel/poll.h>
#include <gbtcp/socket/socket.h>

struct gt_poll_entry {
	struct file_aio pe_aio;
	int *pe_n_triggered;
	short pe_filter;
	short pe_revents;
};

static void
gt_poll_handler(void *aio, int fd, short revents)
{
	short fr;
	struct gt_poll_entry *e;

	e = container_of(aio, struct gt_poll_entry, pe_aio);
	fr = revents & (e->pe_filter | POLLERR | POLLHUP | POLLNVAL);
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
gt__poll(struct pollfd *pfds, int npfds, uint64_t to, const sigset_t *sigmask)
{
	int i, fd, rc, n_triggered;
	struct pollfd *pfd;
	struct gt_file *fp;
	struct fd_poll p;
	struct gt_poll_entry *e, entries[FD_SETSIZE];

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
		rc = gt_so_get(pfd->fd, &fp);
		if (rc == 0) {
			// gbtcp fd
			fd = -1;
			file_aio_init(&e->pe_aio);
			e->pe_n_triggered = &n_triggered;
			file_aio_add(fp, &e->pe_aio, gt_poll_handler);
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
