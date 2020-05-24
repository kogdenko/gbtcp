#include "internals.h"

#define EPOLL_FLAG_ENABLED (1 << 0)
#define EPOLL_FLAG_ONESHOT (1 << 1)
#define EPOLL_FLAG_ET (1 << 2)

struct epoll_mod {
	struct log_scope log_scope;
};

struct epoll {
	struct file ep_file;
	int ep_fd;
	struct mbuf_pool *ep_pool;
	struct dlist ep_triggered;
};

struct epoll_entry {
	struct file_aio e_aio;
#define e_mbuf e_aio.faio_mbuf
#define e_filter e_aio.faio_filter
	struct dlist e_list;
	struct epoll *e_ep;
	int e_fd;
	short e_revents;
	short e_flags;
	union {
		uint64_t e_udata_u64;
		void *e_udata_ptr;
	};
};

static struct epoll_mod *curmod;

static void epoll_entry_set(struct epoll_entry *, struct gt_sock *, short);

int
epoll_mod_init(void **pp)
{
	int rc;
	struct epoll_mod *mod;

	ASSERT(sizeof(struct epoll) <= sizeof(struct gt_sock));
	rc = shm_malloc(pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "epoll");
	}
	return rc;
}

int
epoll_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
epoll_mod_deinit(void *raw_mod)
{
	struct epoll_mod *mod;

	mod = raw_mod;
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
epoll_mod_detach()
{
	curmod = NULL;
}

static struct epoll_entry *
epoll_entry_get(struct epoll *ep, struct file *fp)
{
	struct mbuf *m;
	struct epoll_entry *e;

	DLIST_FOREACH(m, &fp->fl_aioq, mb_list) {
		if (mbuf_get_pool(m) == ep->ep_pool) {
			e = (struct epoll_entry *)m;
			return e;
		}
	}
	return NULL;
}

static int
epoll_entry_is_triggered(struct epoll_entry *e)
{
	return e->e_list.dls_next != NULL;
}

static struct epoll_entry *
epoll_entry_alloc(struct epoll *ep, struct gt_sock *so, short filter)
{
	int rc;
        struct epoll_entry *e;

	rc = mbuf_alloc(ep->ep_pool, (struct mbuf **)&e);
	if (rc) {
		return NULL;
	}
	e->e_revents = 0;
	e->e_flags = EPOLL_FLAG_ENABLED;
	e->e_ep = ep;
	e->e_list.dls_next = NULL;
	e->e_fd = so_get_fd(so);
	file_aio_init(&e->e_aio);
	epoll_entry_set(e, so, filter);
	return e;
}

static void
epoll_entry_untrigger(struct epoll_entry *e)
{
	ASSERT(epoll_entry_is_triggered(e));
	DLIST_REMOVE(e, e_list);
	e->e_list.dls_next = NULL;
}

static void
epoll_entry_free(struct epoll_entry *e)
{
	if (epoll_entry_is_triggered(e)) {
		epoll_entry_untrigger(e);
	}
	file_aio_cancel(&e->e_aio);
	mbuf_free(&e->e_mbuf);
}

static void
epoll_handler(struct file_aio *aio, int fd, short revents)
{
	struct epoll_entry *e;
	struct epoll *ep;

	e = (struct epoll_entry *)aio;
	if (revents & POLLNVAL) {
		epoll_entry_free(e);
	} else {
		ASSERT(revents);
		if (!epoll_entry_is_triggered(e)) {
			ep = e->e_ep;
			DLIST_INSERT_HEAD(&ep->ep_triggered, e, e_list);
		}
		e->e_revents |= revents;
	}
}

static void
epoll_entry_set(struct epoll_entry *e, struct gt_sock *so, short filter)
{
	if (e->e_filter != filter) {
		if (epoll_entry_is_triggered(e)) {
			epoll_entry_untrigger(e);
		}
		e->e_revents = 0;
		file_aio_set(&so->so_file, &e->e_aio, filter, epoll_handler);
	}
}

#ifdef __linux__
static void
epoll_entry_get_event(struct epoll_entry *e, struct gt_sock *so,
	epoll_event_t *event)
{
	short x, y;

	x = e->e_revents;
	ASSERT(x);
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
	ASSERT(y);
	event->events = y;
	event->data.u64 = e->e_udata_u64;
}
#else /* __linux__ */
static void
epoll_entry_get_event(struct epoll_entry *e, struct gt_sock *so,
	epoll_event_t *event)
{
	short x, filter;
	u_short flags;
	int data;

	x = e->e_revents;
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
		data = gt_sock_get_eno((struct gt_sock *)fp);
	}
	GT_ASSERT(filter || flags);
	event->filter = filter;
	event->flags = flags;
	event->ident = e->e_fd;
	event->fflags = 0;
	event->data = data;
	event->udata = e->e_udata_ptr;
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
	struct gt_sock *so;
	struct epoll_entry *e, *tmp;

	n = 0;
	DLIST_FOREACH_SAFE(e, &ep->ep_triggered, e_list, tmp) {
		if (n == cnt) {
			break;
		}
		if ((e->e_flags & EPOLL_FLAG_ENABLED) == 0) {
			continue;
		}
		rc = so_get(e->e_fd, &so);
		UNUSED(rc);
		ASSERT(rc == 0); // aio removed on file close, see POLLNVAL
		if (e->e_revents == 0) {
			revents = file_get_events(&so->so_file, &e->e_aio);
			if (revents == 0) {
				epoll_entry_untrigger(e);
				continue;
			}
			e->e_revents = revents;
		}
		epoll_entry_get_event(e, so, buf + n);
		DBG(0, "hit; fd=%d, events=%s",
		    e->e_fd, log_add_poll_events(e->e_revents));
		e->e_revents = 0;
		if (e->e_flags & EPOLL_FLAG_ET) {
			epoll_entry_untrigger(e);
		}
		if (e->e_flags & EPOLL_FLAG_ONESHOT) {
			epoll_entry_free(e);
		}
		n++;
	}
	return n;
}
#ifdef __linux__
static int
check_epoll_fd(int fd, epoll_event_t *buf, int cnt)
{
	int rc;

	rc = sys_epoll_pwait(fd, buf, cnt, 0, NULL);
	return rc;
}
#else /* __linux__ */
static int
check_epoll_fd(int fd, epoll_event_t *buf, int cnt)
{
	int rc;
	struct timespec to;

	to.tv_sec = 0;
	to.tv_nsec = 0;
	rc = sys_kevent(fd, NULL, 0, buf, cnt, &to);
	return rc;
}

static int
kevent_mod(struct epoll *ep, struct file *fp, struct kevent *event)
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
		e = epoll_entry_alloc(ep, fp, filter);
		if (e == NULL) {
			return -ENOMEM;
		}
	}
	e->e_udata_ptr = event->udata;
	if (event->flags & EV_ENABLE) {
		e->e_flags |= EPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_DISABLE) {
		e->e_flags &= ~EPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_ONESHOT) {
		e->e_flags |=  EPOLL_FLAG_ONESHOT;
	} else {
		e->e_flags &= ~EPOLL_FLAG_ONESHOT;
	}
	if (event->flags & EV_CLEAR) {
		e->e_flags &= ~EPOLL_FLAG_ET;
	} else {
		e->e_flags |=  EPOLL_FLAG_ET;
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
	fp->fl_opened = 1;
	ep = (struct epoll *)fp;
	ep->ep_fd = ep_fd;
	rc = shm_malloc((void **)&ep->ep_pool, sizeof(*ep->ep_pool));
	if (rc) {
		file_free(fp);
		return rc;
	}
	mbuf_pool_init(ep->ep_pool, current->p_id, sizeof(struct epoll_entry));
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
	struct epoll_entry *e;

	ep = (struct epoll *)fp;
	rc = sys_close(ep->ep_fd);
	MBUF_FOREACH_SAFE(m, ep->ep_pool, tmp) {
		e = (struct epoll_entry *)m;
		epoll_entry_free(e);
	}
	ASSERT(mbuf_pool_is_empty(ep->ep_pool));
	mbuf_pool_deinit(ep->ep_pool);
	shm_free(ep->ep_pool);
	file_free(fp);
	return rc;
}

int
u_epoll_pwait(int ep_fd, epoll_event_t *buf, int cnt,
	uint64_t to, const sigset_t *sigmask)
{
	int rc, n;
	struct pollfd pfds[1 + FD_EVENTS_MAX];
	struct epoll *ep;
	struct gt_fd_event_set set;

	if (cnt <= 0) {
		return -EINVAL;
	}
	rc = epoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	n = epoll_read_triggered(ep, buf, cnt);
	pfds[0].fd = ep->ep_fd;
	pfds[0].events = POLLIN;
	set.fdes_to = to;
	do {
		gt_fd_event_set_init(&set, pfds + 1);
		SERVICE_UNLOCK;
		if (n) {
			set.fdes_ts.tv_nsec = 0;
		}
		rc = sys_ppoll(pfds, set.fdes_nr_used + 1,
		               &set.fdes_ts, sigmask);
		SERVICE_LOCK;
		gt_fd_event_set_call(&set, pfds + 1);
		if (rc < 0) {
			return rc;
		}
		rc = epoll_get(ep_fd, &ep);
		if (rc) {
			return rc;
		}
		if (pfds[0].revents) {
			rc = check_epoll_fd(ep->ep_fd, buf + n, cnt - n);
			if (rc < 0) {
				if (n == 0) {
					return rc;
				}
			} else {
				n += rc;
			}
		}
		n += epoll_read_triggered(ep, buf + n, cnt - n);
	} while (n == 0 && set.fdes_to > 0);
	return n;
}

#ifdef __linux__
int
u_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc, filter;
	struct gt_sock *so;
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
	e = epoll_entry_get(ep, &so->so_file);
	if (e == NULL) {
		switch (op) {
		case EPOLL_CTL_ADD:
			e = epoll_entry_alloc(ep, so, filter);
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
			epoll_entry_set(e, so, filter);
			break;
		case EPOLL_CTL_DEL:
			epoll_entry_free(e);
			return 0;
		default:
			return -EINVAL;
		}
	}
	e->e_udata_u64 = event->data.u64;
	if (event->events & EPOLLET) {
		e->e_flags |= EPOLL_FLAG_ET;
	} else {
		e->e_flags &= ~EPOLL_FLAG_ET;
	}
	if (event->events & EPOLLONESHOT) {
		e->e_flags |= EPOLL_FLAG_ONESHOT;
	} else {
		e->e_flags &= ~EPOLL_FLAG_ONESHOT;
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
		rc = gt_sock_get(event->ident, &fp);
		if (rc) {
			rc = (*sys_kevent_fn)(ep->ep_fd, event, 1,
			                      NULL, 0, NULL);
			if (rc == -1) {
				rc = -errno;
				GT_ASSERT(rc);
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


