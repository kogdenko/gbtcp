// GPL v2
#include "internals.h"

// TODO: duplicate epoll

#define CURMOD epoll

#define EPOLL_FLAG_ENABLED (1 << 0)
#define EPOLL_FLAG_ONESHOT (1 << 1)
#define EPOLL_FLAG_ET (1 << 2)
#define EPOLL_FLAG_TRIGGERED (1 << 3)

struct epoll {
	struct file ep_file;
	struct dlist ep_triggered;
	struct dlist ep_relaxed;
	int ep_fd;
	int ep_pid;
};

struct epoll_entry {
	struct file_aio epe_aio;
	struct dlist epe_list;
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

static void do_epoll_entry_io(void *, int, short);

static struct epoll_entry *
epoll_entry_get(struct epoll *ep, struct file *fp)
{
	struct file_aio *aio;
	struct epoll_entry *e;

	DLIST_FOREACH(aio, &fp->fl_aio_head, faio_list) {
		if (aio->faio_fn == do_epoll_entry_io) {
			e = container_of(aio, struct epoll_entry, epe_aio);
			if (e->epe_epoll == ep) {
				return e;
			}
		}
	}
	return NULL;
}

static struct epoll_entry *
epoll_entry_alloc(struct epoll *ep, struct file *fp)
{
	struct epoll_entry *e;

	e = mem_alloc(sizeof(*e));
	if (e == NULL) {
		return NULL;
	}
	e->epe_revents = 0;
	e->epe_filter = 0;
	e->epe_flags = EPOLL_FLAG_ENABLED;
	e->epe_epoll = ep;
	e->epe_fd = fp->fl_fd;
	DLIST_INSERT_HEAD(&ep->ep_relaxed, e, epe_list);
	file_aio_init(&e->epe_aio);
	
	return e;
}

static void
epoll_entry_relax(struct epoll_entry *e)
{
	if (e->epe_flags & EPOLL_FLAG_TRIGGERED) {
		e->epe_flags &= ~EPOLL_FLAG_TRIGGERED;
		DLIST_REMOVE(e, epe_list);
		DLIST_INSERT_HEAD(&e->epe_epoll->ep_relaxed, e, epe_list);
	}
}

static void
epoll_entry_trigger(struct epoll_entry *e)
{
	if ((e->epe_flags & EPOLL_FLAG_TRIGGERED) == 0) {
		e->epe_flags |= EPOLL_FLAG_TRIGGERED;
		DLIST_REMOVE(e, epe_list);
		DLIST_INSERT_HEAD(&e->epe_epoll->ep_triggered, e, epe_list);
	}
}

static void
epoll_entry_free(struct epoll_entry *e)
{
	DLIST_REMOVE(e, epe_list);
	file_aio_cancel(&e->epe_aio);
	mem_free(e);
}

static void
epoll_entry_free_list(struct dlist *head)
{
	struct epoll_entry *e;

	while (!dlist_is_empty(head)) {
		e = DLIST_FIRST(head, struct epoll_entry, epe_list);
		epoll_entry_free(e);
	}
}

static void
do_epoll_entry_io(void *aio_ptr, int fd, short revents)
{
	struct epoll_entry *e;

	e = container_of(aio_ptr, struct epoll_entry, epe_aio);
	e->epe_revents |= revents & e->epe_filter;
	if (e->epe_revents & POLLNVAL) {
		epoll_entry_free(e);
	} else if (e->epe_revents) {
		epoll_entry_trigger(e);
	}
}

static void
epoll_entry_set(struct epoll_entry *e, struct file *fp, short filter)
{
	e->epe_filter = filter|POLLERR|POLLHUP|POLLNVAL;
	e->epe_revents = 0;
	epoll_entry_relax(e);
	file_aio_cancel(&e->epe_aio);
	file_aio_add(fp, &e->epe_aio, do_epoll_entry_io);
}

#ifdef __linux__
static void
epoll_get_event(struct epoll_entry *e, struct sock *so, epoll_event_t *event)
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
epoll_get_event(struct epoll_entry *e, struct sock *so, epoll_event_t *event)
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
		file_ioctl(&so->so_file, FIONREAD, (uintptr_t)(&data));
	} else if (x & POLLOUT) {
		filter = EVFILT_WRITE;
		file_ioctl(&so->so_file, FIONSPACE, (uintptr_t)(&data));
	}
	if (x & POLLERR) {
		flags |= EV_ERROR;
		data = so_get_errnum(so);
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
	struct file *fp;
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
	struct sock *so;
	struct epoll_entry *e, *tmp;

	n = 0;
	DLIST_FOREACH_SAFE(e, &ep->ep_triggered, epe_list, tmp) {
		if (n == cnt) {
			break;
		}
		if ((e->epe_flags & EPOLL_FLAG_ENABLED) == 0) {
			continue;
		}
		so_get(e->epe_fd, &so);
		if (e->epe_revents == 0) {
			revents = file_get_events(&so->so_file);
			e->epe_revents = revents & e->epe_filter;
			if (e->epe_revents == 0) {
				epoll_entry_relax(e);
				continue;
			}
		}
		epoll_get_event(e, so, buf + n);
		n++;
		DBG(0, "epoll: rd; fd=%d, ev=%s",
			e->epe_fd, log_add_poll_events(e->epe_revents));
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
epoll_fd_read_triggered(int fd, epoll_event_t *events, int maxevents)
{
	int rc;

	rc = sys_epoll_pwait(fd, events, maxevents, 0, NULL);
	return rc;
}
#else // __linux__
static int
epoll_fd_read_triggered(int fd, epoll_event_t *events, int maxevents)
{
	int rc;
	struct timespec to;

	to.tv_sec = 0;
	to.tv_nsec = 0;
	rc = sys_kevent(fd, NULL, 0, events, maxevents, &to);
	return rc;
}

static int
kevent_mod(struct epoll *ep, struct sock *so, struct kevent *event)
{
	short filter;
	struct file *fp;
	struct epoll_entry *e;

	fp = &so->so_file;
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
		e->epe_flags |=  EPOLL_FLAG_ONESHOT;
	} else {
		e->epe_flags &= ~EPOLL_FLAG_ONESHOT;
	}
	if (event->flags & EV_CLEAR) {
		e->epe_flags &= ~EPOLL_FLAG_ET;
	} else {
		e->epe_flags |=  EPOLL_FLAG_ET;
	}
	return 0;
}
#endif // __linux__

int
u_epoll_create(int ep_fd)
{
	struct file *fp;
	struct epoll *ep;

	fp = file_alloc(FILE_EPOLL, sizeof(*ep));
	if (fp == NULL) {
		return -ENOMEM;
	}
	fp->fl_referenced = 1;
	ep = (struct epoll *)fp;
	ep->ep_fd = ep_fd;
	ep->ep_pid = getpid();
	dlist_init(&ep->ep_triggered);
	dlist_init(&ep->ep_relaxed);
	return fp->fl_fd;
}

int
u_epoll_close(struct file *fp)
{
	int rc/*, tmp*/;
//	struct mbuf *m;
	struct epoll *ep;
//	struct epoll_entry *e;

	ep = (struct epoll *)fp;
	if (ep->ep_pid == getpid()) {
		rc = sys_close(&ep->ep_fd);
	} else {
		// u_epoll_close can be called in controller
		rc = 0;
	}
	epoll_entry_free_list(&ep->ep_relaxed);
	epoll_entry_free_list(&ep->ep_triggered);
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
			rc = epoll_fd_read_triggered(ep->ep_fd, events, m);
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
	struct sock *so;
	struct file *fp;
	struct epoll *ep;
	struct epoll_entry *e;

	if (ep_fd == fd) {
		return -EINVAL;
	}
	rc = epoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	rc = so_get(fd, &so);
	if (rc) {
		rc = sys_epoll_ctl(ep->ep_fd, op, fd, event);
		return rc;
	}
	fp = &so->so_file;
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
	struct sock *so;
	struct epoll *ep;

	rc = epoll_get(kq, &ep);
	if (rc) {
		return rc;
	}
	for (i = 0; i < nchanges; ++i) {
		event = (struct kevent *)changelist + i;
		rc = so_get(event->ident, &so);
		if (rc) {
			rc = sys_kevent(ep->ep_fd, event, 1,
				NULL, 0, NULL);
		} else {
			rc = kevent_mod(ep, so, event);
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
			to = NSEC_INFINITY;
		} else {
			to = NSEC_SEC * timeout->tv_sec + timeout->tv_nsec;
		}
		rc = u_epoll_pwait(kq, eventlist, nevents, to, NULL);
	} else {
		rc = 0;
	}
	return rc;
}
#endif // __linux__
