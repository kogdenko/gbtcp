// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/socket/epoll.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/socket/file.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/socket/socket.h>
#include <gbtcp/kernel/sys.h>
#include <gbtcp/kernel/worker.h>

#define EPOLL_FLAG_ENABLED (1 << 0)
#define EPOLL_FLAG_ONESHOT (1 << 1)
#define EPOLL_FLAG_ET (1 << 2)

struct epoll {
	struct gt_file ep_file;
	int ep_fd;
	struct gt_dlist epoll_entry_head;
	struct gt_dlist ep_triggered;
};

struct epoll_entry {
	struct file_aio epe_aio;
	struct gt_dlist epe_list;
	struct gt_dlist epe_head_list;
	struct epoll *epe_epoll;
	int epe_fd;
	short epe_filter;
	short epe_revents;
	short epe_flags;
	union {
		uint64_t epe_udata_u64;
		void *epe_udata_ptr;
	};
};

static void epoll_entry_handler(void *aio_ptr, int fd, short revents);

static struct epoll_entry *
epoll_entry_get(struct epoll *ep, struct gt_file *fp)
{
	struct file_aio *aio;
	struct epoll_entry *e;

	GT_DLIST_FOREACH(aio, &fp->fl_aio_head, faio_list) {
		if (aio->faio_fn == epoll_entry_handler) {
			e = container_of(aio, struct epoll_entry, epe_aio);
			if (e->epe_epoll == ep) {
				return e;
			}
		}
	}
	return NULL;
}

#define epoll_entry_is_triggered(e) ((e)->epe_list.dls_next != NULL)

static struct epoll_entry *
epoll_entry_alloc(struct epoll *ep, struct gt_file *fp)
{
	struct epoll_entry *e;

	e = gt_malloc(shm_cache(), sizeof(struct epoll_entry), GT_MF_ZERO);
	if (e == NULL) {
		return NULL;
	}
	e->epe_revents = 0;
	e->epe_filter = 0;
	e->epe_flags = EPOLL_FLAG_ENABLED;
	e->epe_epoll = ep;
	e->epe_list.dls_next = NULL;
	e->epe_fd = file_get_fd(fp);
	file_aio_init(&e->epe_aio);
	GT_DLIST_INSERT_TAIL(&ep->epoll_entry_head, e, epe_head_list);
	return e;
}

static void
epoll_entry_relax(struct epoll_entry *e)
{
	if (epoll_entry_is_triggered(e)) {
		GT_DLIST_REMOVE(e, epe_list);
		e->epe_list.dls_next = NULL;
	}
}

static void
epoll_entry_free(struct epoll_entry *e)
{
	epoll_entry_relax(e);
	GT_DLIST_REMOVE(e, epe_head_list);
	file_aio_cancel(&e->epe_aio);
	gt_free_internal(shm_cache(), e);
}

static void
epoll_entry_handler(void *aio_ptr, int fd, short revents)
{
	struct epoll_entry *e;
	struct epoll *ep;

	e = container_of(aio_ptr, struct epoll_entry, epe_aio);
	e->epe_revents |= revents & e->epe_filter;

	if (e->epe_revents & POLLNVAL) {
		epoll_entry_free(e);
		return;
	} else if (e->epe_revents && !epoll_entry_is_triggered(e)) {
		ep = e->epe_epoll;
		GT_DLIST_INSERT_HEAD(&ep->ep_triggered, e, epe_list);
	}

	//	struct sock *so;
	//	so_get(e->epe_fd, &so);
	//	if (so->so_rfin) {
	//		assert(epoll_entry_is_triggered(e));
	//	}
}

static void
epoll_entry_set(struct epoll_entry *e, struct gt_file *fp, short filter)
{
	e->epe_filter = filter | POLLERR | POLLHUP | POLLNVAL;
	e->epe_revents = 0;
	epoll_entry_relax(e);
	file_aio_cancel(&e->epe_aio);
	file_aio_add(fp, &e->epe_aio, epoll_entry_handler);
}

#ifdef __linux__
static void
epoll_get_event(struct epoll_entry *e, struct gt_file *fp, epoll_event_t *event)
{
	short x, y;

	x = e->epe_revents;
	assert(x);
	y = 0;
	if (x & POLLERR) {
		y |= EPOLLERR;
	}
	if (x & POLLRDHUP) {
		y |= EPOLLRDHUP;
	}
	if (x & POLLIN) {
		y |= EPOLLIN;
	}
	if (x & POLLOUT) {
		y |= EPOLLOUT;
	}
	assert(y);
	event->events = y;
	event->data.u64 = e->epe_udata_u64;
}
#else // __linux__
static void
epoll_get_event(struct epoll_entry *e, struct gt_file *fp, epoll_event_t *event)
{
	short x, filter;
	u_short flags;
	int data;

	x = e->epe_revents;
	filter = 0;
	flags = 0;
	data = 0;
	if (x & POLLIN) {
		filter = EVFILT_READ;
		file_ioctl(fp, FIONREAD, (uintptr_t)(&data));
	} else if (x & POLLOUT) {
		filter = EVFILT_WRITE;
		file_ioctl(fp, FIONSPACE, (uintptr_t)(&data));
	}
	if (x & POLLERR) {
		flags |= EV_ERROR;
		data = gt_so_get_err(fp);
	}
	assert(filter || flags);
	event->filter = filter;
	event->flags = flags;
	event->ident = e->epe_fd;
	event->fflags = 0;
	event->data = data;
	event->udata = e->epe_udata_ptr;
}
#endif // __linux__

static int
epoll_get(int fd, struct epoll **ep)
{
	int rc;
	struct gt_file *fp;

	rc = file_get(fd, &fp);
	if (rc < 0) {
		return rc;
	}
	if (fp->fl_type != FILE_EPOLL) {
		return -EINVAL;
	}
	*ep = (struct epoll *)fp;
	return 0;
}

static int
epoll_read_triggered(struct epoll *ep, epoll_event_t *buf, int cnt)
{
	int n;
	short revents;
	struct gt_file *fp;
	struct epoll_entry *e, *tmp;

	n = 0;
	GT_DLIST_FOREACH_SAFE(e, &ep->ep_triggered, epe_list, tmp) {
		if (n == cnt) {
			break;
		}
		if ((e->epe_flags & EPOLL_FLAG_ENABLED) == 0) {
			continue;
		}
		gt_so_get(e->epe_fd, &fp);
		if (e->epe_revents == 0) {
			revents = file_get_events(fp);
			e->epe_revents = revents & e->epe_filter;
			if (e->epe_revents == 0) {
				epoll_entry_relax(e);
				continue;
			}
		}
		epoll_get_event(e, fp, buf + n);
		n++;
		e->epe_revents = 0;
		if (e->epe_flags & EPOLL_FLAG_ET) {
			epoll_entry_relax(e);
		}
		if (e->epe_flags & EPOLL_FLAG_ONESHOT) {
			epoll_entry_free(e);
		}
	}
	return n;
}

#ifdef __linux__
static int
fd_read_triggered(int fd, epoll_event_t *events, int maxevents)
{
	int rc;

	rc = sys_epoll_pwait(fd, events, maxevents, 0, NULL);
	return rc;
}
#else // __linux__
static int
fd_read_triggered(int fd, epoll_event_t *events, int maxevents)
{
	int rc;
	struct timespec to;

	to.tv_sec = 0;
	to.tv_nsec = 0;
	rc = sys_kevent(fd, NULL, 0, events, maxevents, &to);
	return rc;
}

static int
kevent_mod(struct epoll *ep, struct gt_file *fp, struct kevent *event)
{
	short filter;
	struct epoll_entry *e;

	if (event->flags & EV_RECEIPT) {
		return -ENOTSUP;
	}
	if (event->fflags) {
		return -ENOTSUP;
	}
	switch (event->filter) {
	case EVFILT_READ:
		filter = POLLIN;
		break;
	case EVFILT_WRITE:
		filter = POLLOUT;
		break;
	default:
		return -EINVAL;
	}
	e = epoll_entry_get(ep, fp);
	if (event->flags & EV_DELETE) {
		if (e == NULL) {
			return -ENOENT;
		}
		epoll_entry_free(e);
		return 0;
	}
	if (e == NULL) {
		if ((event->flags & EV_ADD) == 0) {
			return -ENOENT;
		}
		e = epoll_entry_alloc(ep, fp);
		if (e == NULL) {
			return -ENOMEM;
		} else {
			epoll_entry_set(e, fp, filter);
		}
	}
	e->epe_udata_ptr = event->udata;
	if (event->flags & EV_ENABLE) {
		e->epe_flags |= EPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_DISABLE) {
		e->epe_flags &= ~EPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_ONESHOT) {
		e->epe_flags |= EPOLL_FLAG_ONESHOT;
	} else {
		e->epe_flags &= ~EPOLL_FLAG_ONESHOT;
	}
	if (event->flags & EV_CLEAR) {
		e->epe_flags &= ~EPOLL_FLAG_ET;
	} else {
		e->epe_flags |= EPOLL_FLAG_ET;
	}
	return 0;
}
#endif // __linux__

int
u_epoll_create(int ep_fd)
{
	int rc, fd;
	struct gt_file *fp;
	struct epoll *ep;

	rc = file_alloc(&fp, FILE_EPOLL);
	if (rc) {
		return rc;
	}
	fp->fl_referenced = 1;
	ep = (struct epoll *)fp;
	ep->ep_fd = ep_fd;
	if (rc) {
		file_free(fp);
		return rc;
	}
	gt_dlist_init(&ep->epoll_entry_head);
	gt_dlist_init(&ep->ep_triggered);
	fd = file_get_fd(fp);
	return fd;
}

int
u_epoll_close(struct gt_file *fp)
{
	int rc;
	struct epoll *ep;
	struct epoll_entry *e, *tmp;

	ep = (struct epoll *)fp;
	if (ep->ep_file.fl_worker_index == current->p_sid) {
		rc = sys_close(ep->ep_fd);
	} else {
		// u_epoll_close can be called in controller
		rc = 0;
	}
	GT_DLIST_FOREACH_SAFE(e, &ep->epoll_entry_head, epe_head_list, tmp) {
		epoll_entry_free(e);
	}
	file_free(fp);
	return rc;
}

int
u_epoll_pwait(int ep_fd, epoll_event_t *events, int m, uint64_t to,
	      const sigset_t *sigmask)
{
	int rc, n;
	struct epoll *ep;
	struct fd_poll p;

	if (m <= 0) {
		return -EINVAL;
	}
	rc = epoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	n = epoll_read_triggered(ep, events, m);
	if (n) {
		return n;
	}
	fd_poll_init(&p);
	fd_poll_add3(&p, ep->ep_fd, POLLIN);
	p.fdp_to = to;
	do {
		rc = fd_poll_wait(&p, sigmask);
		if (rc < 0) {
			return rc;
		}
		rc = epoll_get(ep_fd, &ep);
		if (rc) {
			return rc;
		}
		if (p.fdp_pfds[0].revents) {
			rc = fd_read_triggered(ep->ep_fd, events, m);
			if (rc < 0) {
				return rc;
			} else {
				n = rc;
			}
		}
		n += epoll_read_triggered(ep, events + n, m - n);
	} while (n == 0 && p.fdp_to > 0);
	return n;
}

#ifdef __linux__
int
u_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc, filter;
	struct gt_file *fp;
	struct epoll *ep;
	struct epoll_entry *e;

	if (ep_fd == fd) {
		return -EINVAL;
	}
	rc = epoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	rc = gt_so_get(fd, &fp);
	if (rc) {
		rc = sys_epoll_ctl(ep->ep_fd, op, fd, event);
		return rc;
	}
	filter = 0;
	if (event->events & EPOLLIN) {
		filter |= POLLIN;
	}
	if (event->events & EPOLLOUT) {
		filter |= POLLOUT;
	}
	if (event->events & EPOLLRDHUP) {
		filter |= POLLRDHUP;
	}
	e = epoll_entry_get(ep, fp);
	if (e == NULL) {
		switch (op) {
		case EPOLL_CTL_ADD:
			e = epoll_entry_alloc(ep, fp);
			if (e == NULL) {
				return -ENOMEM;
			} else {
				epoll_entry_set(e, fp, filter);
			}
			break;
		case EPOLL_CTL_MOD:
		case EPOLL_CTL_DEL:
			return -ENOENT;
		default:
			return -EINVAL;
		}
	} else {
		switch (op) {
		case EPOLL_CTL_ADD:
			return -EEXIST;
		case EPOLL_CTL_MOD:
			epoll_entry_set(e, fp, filter);
			break;
		case EPOLL_CTL_DEL:
			epoll_entry_free(e);
			return 0;
		default:
			return -EINVAL;
		}
	}
	e->epe_udata_u64 = event->data.u64;
	if (event->events & EPOLLET) {
		e->epe_flags |= EPOLL_FLAG_ET;
	} else {
		e->epe_flags &= ~EPOLL_FLAG_ET;
	}
	if (event->events & EPOLLONESHOT) {
		e->epe_flags |= EPOLL_FLAG_ONESHOT;
	} else {
		e->epe_flags &= ~EPOLL_FLAG_ONESHOT;
	}
	return 0;
}
#else // __linux__
int
u_kevent(int kq, const struct kevent *changelist, int nchanges,
	 struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int i, rc;
	uint64_t to;
	struct kevent *event;
	struct gt_file *fp;
	struct epoll *ep;

	rc = epoll_get(kq, &ep);
	if (rc) {
		return rc;
	}
	for (i = 0; i < nchanges; ++i) {
		event = (struct kevent *)changelist + i;
		rc = gt_so_get(event->ident, &fp);
		if (rc) {
			rc = sys_kevent(ep->ep_fd, event, 1, NULL, 0, NULL);
		} else {
			rc = kevent_mod(ep, fp, event);
		}
		if (rc < 0) {
			if (nevents) {
				memmove(eventlist, event, sizeof(*event));
				event = eventlist;
				event->flags = EV_ERROR;
				event->data = -rc;
				eventlist++;
				nevents--;
			} else {
				return rc;
			}
		}
	}
	if (nevents) {
		if (timeout == NULL) {
			to = UINT64_MAX;
		} else {
			to = GT_NSEC_PER_SEC * timeout->tv_sec +
			     timeout->tv_nsec;
		}
		rc = u_epoll_pwait(kq, eventlist, nevents, to, NULL);
	} else {
		rc = 0;
	}
	return rc;
}
#endif // __linux__
