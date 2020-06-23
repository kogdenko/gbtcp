#include "internals.h"

#define CURMOD epoll

#define EPOLL_FLAG_ENABLED (1 << 0)
#define EPOLL_FLAG_ONESHOT (1 << 1)
#define EPOLL_FLAG_ET (1 << 2)

struct epoll {
	struct file ep_file;
	int ep_fd;
	struct mbuf_pool *ep_pool;
	struct dlist ep_triggered;
};

struct u_epoll_event {
	struct file_aio epev_aio;
#define epev_mbuf epev_aio.faio_mbuf
#define epev_filter epev_aio.faio_filter
	struct dlist epev_list;
	struct epoll *epev_epoll;
	int epev_fd;
	short epev_revents;
	short epev_flags;
	union {
		uint64_t epev_udata_u64;
		void *epev_udata_ptr;
	};
};

static void epoll_event_set(struct u_epoll_event *, struct file *, short);

static struct u_epoll_event *
epoll_event_get(struct epoll *ep, struct file *fp)
{
	struct mbuf *m;
	struct u_epoll_event *e;

	DLIST_FOREACH(m, &fp->fl_aioq, mb_list) {
		if (mbuf_get_pool(m) == ep->ep_pool) {
			e = (struct u_epoll_event *)m;
			return e;
		}
	}
	return NULL;
}

static int
epoll_event_is_triggered(struct u_epoll_event *e)
{
	return e->epev_list.dls_next != NULL;
}

static struct u_epoll_event *
epoll_event_alloc(struct epoll *ep, struct file *fp, short filter)
{
	int rc;
	struct u_epoll_event *e;

	rc = mbuf_alloc(ep->ep_pool, (struct mbuf **)&e);
	if (rc) {
		return NULL;
	}
	e->epev_revents = 0;
	e->epev_flags = EPOLL_FLAG_ENABLED;
	e->epev_epoll = ep;
	e->epev_list.dls_next = NULL;
	e->epev_fd = file_get_fd(fp);
	file_aio_init(&e->epev_aio);
	epoll_event_set(e, fp, filter);
	return e;
}

static void
epoll_event_untrigger(struct u_epoll_event *e)
{
	assert(epoll_event_is_triggered(e));
	DLIST_REMOVE(e, epev_list);
	e->epev_list.dls_next = NULL;
}

static void
epoll_event_free(struct u_epoll_event *e)
{
	if (epoll_event_is_triggered(e)) {
		epoll_event_untrigger(e);
	}
	file_aio_cancel(&e->epev_aio);
	mbuf_free(&e->epev_mbuf);
}

static void
epoll_event_handler(struct file_aio *aio, int fd, short revents)
{
	struct u_epoll_event *e;
	struct epoll *ep;

	e = (struct u_epoll_event *)aio;
	if (revents & POLLNVAL) {
		epoll_event_free(e);
	} else {
		assert(revents);
		if (!epoll_event_is_triggered(e)) {
			ep = e->epev_epoll;
			DLIST_INSERT_HEAD(&ep->ep_triggered, e, epev_list);
		}
		e->epev_revents |= revents;
	}
}

static void
epoll_event_set(struct u_epoll_event *e, struct file *fp, short filter)
{
	if (e->epev_filter != filter) {
		if (epoll_event_is_triggered(e)) {
			epoll_event_untrigger(e);
		}
		e->epev_revents = 0;
		file_aio_set(fp, &e->epev_aio, filter, epoll_event_handler);
	}
}

#ifdef __linux__
static void
epoll_get_event(struct u_epoll_event *e, struct sock *so, epoll_event_t *event)
{
	short x, y;

	x = e->epev_revents;
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
	event->data.u64 = e->epev_udata_u64;
}
#else /* __linux__ */
static void
epoll_get_event(struct u_epoll_event *e, struct sock *so, epoll_event_t *event)
{
	short x, filter;
	u_short flags;
	int data;

	x = e->epev_revents;
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
		data = sock_get_eno((struct sock *)fp);
	}
	assert(filter || flags);
	event->filter = filter;
	event->flags = flags;
	event->ident = e->epev_fd;
	event->fflags = 0;
	event->data = data;
	event->udata = e->epev_udata_ptr;
}
#endif /* __linux__ */
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
	int n, rc;
	short revents;
	struct sock *so;
	struct u_epoll_event *e, *tmp;

	n = 0;
	DLIST_FOREACH_SAFE(e, &ep->ep_triggered, epev_list, tmp) {
		if (n == cnt) {
			break;
		}
		if ((e->epev_flags & EPOLL_FLAG_ENABLED) == 0) {
			continue;
		}
		rc = so_get(e->epev_fd, &so);
		UNUSED(rc);
		assert(rc == 0); // aio removed on file close, see POLLNVAL
		if (e->epev_revents == 0) {
			revents = file_get_events(&so->so_file, &e->epev_aio);
			if (revents == 0) {
				epoll_event_untrigger(e);
				continue;
			}
			e->epev_revents = revents;
		}
		epoll_get_event(e, so, buf + n);
		DBG(0, "hit; fd=%d, events=%s",
		    e->epev_fd, log_add_poll_events(e->epev_revents));
		e->epev_revents = 0;
		if (e->epev_flags & EPOLL_FLAG_ET) {
			epoll_event_untrigger(e);
		}
		if (e->epev_flags & EPOLL_FLAG_ONESHOT) {
			epoll_event_free(e);
		}
		n++;
	}
	return n;
}

#ifdef __linux__
static int
epoll_pwait0(int fd, epoll_event_t *events, int maxevents)
{
	int rc;

	rc = sys_epoll_pwait(fd, events, maxevents, 0, NULL);
	return rc;
}
#else /* __linux__ */
static int
epoll_pwait0(int fd, epoll_event_t *events, int maxevents)
{
	int rc;
	struct timespec to;

	to.tv_sec = 0;
	to.tv_nsec = 0;
	rc = sys_kevent(fd, NULL, 0, events, maxevents, &to);
	return rc;
}

static int
kevent_mod(struct epoll *ep, struct file *fp, struct kevent *event)
{
	short filter;
	struct u_epoll_event *e;

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
	e = epoll_event_get(ep, fp);
	if (event->flags & EV_DELETE) {
		if (e == NULL) {
			return -ENOENT;
		}
		epoll_event_free(e);
		return 0;
	}
	if (e == NULL) {
		if ((event->flags & EV_ADD) == 0) {
			return -ENOENT;
		}
		e = epoll_event_alloc(ep, fp, filter);
		if (e == NULL) {
			return -ENOMEM;
		}
	}
	e->epev_udata_ptr = event->udata;
	if (event->flags & EV_ENABLE) {
		e->epev_flags |= EPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_DISABLE) {
		e->epev_flags &= ~EPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_ONESHOT) {
		e->epev_flags |=  EPOLL_FLAG_ONESHOT;
	} else {
		e->epev_flags &= ~EPOLL_FLAG_ONESHOT;
	}
	if (event->flags & EV_CLEAR) {
		e->epev_flags &= ~EPOLL_FLAG_ET;
	} else {
		e->epev_flags |=  EPOLL_FLAG_ET;
	}
	return 0;
}
#endif /* __linux__ */

int
u_epoll_create(int ep_fd)
{
	int rc, fd;
	struct file *fp;
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
	rc = mbuf_pool_alloc(&ep->ep_pool, current->p_sid,
	                     sizeof(struct u_epoll_event), 0);
	if (rc) {
		file_free(fp);
		return rc;
	}
	dlist_init(&ep->ep_triggered);
	fd = file_get_fd(fp);
	return fd;
}

int
u_epoll_close(struct file *fp)
{
	int rc, tmp;
	struct mbuf *m;
	struct epoll *ep;
	struct u_epoll_event *e;

	ep = (struct epoll *)fp;
	if (ep->ep_pool->mbp_sid == current->p_sid) {
		rc = sys_close(ep->ep_fd);	
	} else {
		// u_epoll_close can be called in controller
		rc = 0;
	}
	MBUF_FOREACH_SAFE(m, ep->ep_pool, tmp) {
		e = (struct u_epoll_event *)m;
		epoll_event_free(e);
	}
	mbuf_pool_free(ep->ep_pool);
	ep->ep_pool = NULL;
	file_free(fp);
	return rc;
}

int
u_epoll_pwait(int ep_fd, epoll_event_t *events, int maxevents,
	uint64_t to, const sigset_t *sigmask)
{
	int rc, n_triggered;
	struct epoll *ep;
	struct fd_poll p;

	if (maxevents <= 0) {
		return -EINVAL;
	}
	rc = epoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	n_triggered = epoll_read_triggered(ep, events, maxevents);
	fd_poll_init(&p);
	fd_poll_add3(&p, ep->ep_fd, POLLIN);
	p.fdp_to = to;
	do {
		if (n_triggered) {
			p.fdp_to = 0;
		}
		rc = fd_poll_wait(&p, sigmask);
		if (rc < 0) {
			return rc;
		}
		rc = epoll_get(ep_fd, &ep);
		if (rc) {
			return rc;
		}
		if (p.fdp_pfds[0].revents) {
			rc = epoll_pwait0(ep->ep_fd, events + n_triggered,
			                  maxevents - n_triggered);
			if (rc < 0) {
				if (n_triggered == 0) {
					return rc;
				}
			} else {
				n_triggered += rc;
			}
		}
		n_triggered += epoll_read_triggered(ep, events + n_triggered,
		                                    maxevents - n_triggered);
	} while (n_triggered == 0 && p.fdp_to > 0);
	return n_triggered;
}

#ifdef __linux__
int
u_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc, filter;
	struct sock *so;
	struct file *fp;
	struct epoll *ep;
	struct u_epoll_event *e;

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
	e = epoll_event_get(ep, fp);
	if (e == NULL) {
		switch (op) {
		case EPOLL_CTL_ADD:
			e = epoll_event_alloc(ep, fp, filter);
			if (e == NULL) {
				return -ENOMEM;
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
			epoll_event_set(e, fp, filter);
			break;
		case EPOLL_CTL_DEL:
			epoll_event_free(e);
			return 0;
		default:
			return -EINVAL;
		}
	}
	e->epev_udata_u64 = event->data.u64;
	if (event->events & EPOLLET) {
		e->epev_flags |= EPOLL_FLAG_ET;
	} else {
		e->epev_flags &= ~EPOLL_FLAG_ET;
	}
	if (event->events & EPOLLONESHOT) {
		e->epev_flags |= EPOLL_FLAG_ONESHOT;
	} else {
		e->epev_flags &= ~EPOLL_FLAG_ONESHOT;
	}
	return 0;
}
#else /* __linux__ */
int
u_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int i, rc;
	uint64_t to;
	struct kevent *event;
	struct file *fp;
	struct epoll *ep;

	rc = epoll_get(kq, &ep);
	if (rc) {
		return rc;
	}
	for (i = 0; i < nchanges; ++i) {
		event = (struct kevent *)changelist + i;
		rc = sock_get(event->ident, &fp);
		if (rc) {
			rc = (*sys_kevent_fn)(ep->ep_fd, event, 1,
			                      NULL, 0, NULL);
			if (rc == -1) {
				rc = -errno;
				assert(rc);
			}
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
			to = GT_NSEC_MAX;
		} else {
			to = GT_SEC * timeout->tv_sec + timeout->tv_nsec;
		}
		rc = u_epoll_pwait(kq, eventlist, nevents, to, NULL);
	} else {
		rc = 0;
	}
	return rc;
}
#endif /* __linux__ */


