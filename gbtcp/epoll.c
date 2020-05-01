#include "internals.h"

#define UEPOLL_FLAG_ENABLED (1 << 0)
#define UEPOLL_FLAG_ONESHOT (1 << 1)
#define UEPOLL_FLAG_ET (1 << 2)
#define UEPOLL_FLAG_ADDED (1 << 3)

struct epoll_mod {
	struct log_scope log_scope;
};

struct uepoll {
	struct file ep_file;
	int ep_fd;
	struct mbuf_pool *ep_pool;
	struct dlist ep_head;
};

struct uepoll_entry {
	struct file_aio epe_aio;
	struct dlist epe_list;
	struct uepoll *epe_ep;
	int epe_fd;
	short epe_revents;
	short epe_flags;
	union {
		uint64_t epe_udata_u64;
		void *epe_udata_ptr;
	};
};

static struct epoll_mod *current_mod;

// entry
//static struct uepoll_entry *uepoll_entry_alloc(struct gt_epoll *,
//	struct file *fp, short filter);

//static struct gt_epoll_entry *gt_epoll_entry_get(struct gt_epoll *ep,
//	struct file *fp);

//static void gt_epoll_entry_remove(struct gt_epoll_entry *e);

//static void gt_epoll_entry_free(struct gt_epoll_entry *e);

//static void gt_epoll_entry_get_event(struct gt_epoll_entry *e,
//	gt_epoll_event_t *event, struct file *fp);

//static void gt_epoll_entry_cb(struct file_aio *, int fd, short revents);

//static void gt_epoll_entry_set(struct gt_epoll_entry *e,
//	struct file *fp, short filter);

// epoll
//static int gt_epoll_get(int fd, struct gt_epoll **ep);

//static int gt_epoll_get_events(struct gt_epoll *ep,
//	gt_epoll_event_t *buf, int cnt);

//static int gt_epoll_wait_fd(int fd, gt_epoll_event_t *buf, int cnt);

static void uepoll_entry_set(struct uepoll_entry *, struct file *, short);


#ifndef __linux__
//static int gt_epoll_kevent_mod(struct gt_epoll *ep, struct file *fp,
//	struct kevent *event);
#endif /* __linux__ */

int
epoll_mod_init(struct log *log, void **pp)
{
	int rc;
	struct epoll_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "epoll");
	}
	return rc;
}
int
epoll_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
	return 0;
}
void
epoll_mod_deinit(struct log *log, void *raw_mod)
{
	struct epoll_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}
void
epoll_mod_detach(struct log *log)
{
	current_mod = NULL;
}
static struct uepoll_entry *
uepoll_entry_get(struct uepoll *ep, struct file *fp)
{
	struct mbuf *mbuf;
	struct uepoll_entry *e;
	DLIST_FOREACH(mbuf, &fp->fl_aioq, mb_list) {
		if (mbuf->mb_pool_id == ep->ep_pool->mbp_id) {
			e = (struct uepoll_entry *)mbuf;
			return e;
		}
	}
	return NULL;
}
static struct uepoll_entry *
uepoll_entry_alloc(struct uepoll *ep, struct file *fp, short filter)
{
	int rc;
        struct uepoll_entry *e;
	rc = mbuf_alloc(NULL, ep->ep_pool, (struct mbuf **)&e);
	if (rc) {
		return NULL;
	}
	e->epe_revents = 0;
	e->epe_flags = UEPOLL_FLAG_ENABLED;
	e->epe_ep = ep;
	e->epe_fd = file_get_fd(fp);
	file_aio_init(&e->epe_aio);
	uepoll_entry_set(e, fp, filter);
	return e;
}
static void
uepoll_entry_remove(struct uepoll_entry *e)
{
	ASSERT(e->epe_revents);
	DLIST_REMOVE(e, epe_list);
	e->epe_revents = 0;
}
static void
uepoll_entry_free(struct uepoll_entry *e)
{
	if (e->epe_revents) {
		uepoll_entry_remove(e);
	}
	file_aio_cancel(&e->epe_aio);
	mbuf_free(&e->epe_aio.faio_mbuf);
}
static void
uepoll_entry_cb(struct file_aio *aio, int fd, short revents)
{
	struct uepoll_entry *e;
	e = (struct uepoll_entry *)aio;
	if (revents & POLLNVAL) {
		uepoll_entry_free(e);
	} else {
		ASSERT(revents);
		if (e->epe_revents == 0) {
			e->epe_flags |= UEPOLL_FLAG_ADDED;
			DLIST_INSERT_HEAD(&e->epe_ep->ep_head, e, epe_list);
		}
		e->epe_revents |= revents;
	}
}
static void
uepoll_entry_set(struct uepoll_entry *e, struct file *fp, short filter)
{
	if (e->epe_aio.faio_filter != filter) {
		if (e->epe_revents) {
			DLIST_REMOVE(e, epe_list);
			e->epe_revents = 0;
		}	
		file_aio_set(fp, &e->epe_aio, filter, uepoll_entry_cb);
	}
}
#ifdef __linux__
static void
uepoll_entry_get_event(struct uepoll_entry *e, epoll_event_t *event,
	struct file *fp)
{
	short x, y;
	x = e->epe_revents;
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
	event->events = y;
	event->data.u64 = e->epe_udata_u64;
}
#else /* __linux__ */
static void
uepoll_entry_get_event(struct uepoll_entry *e,
	epoll_event_t *event, struct file *fp)
{
	short x, filter;
	u_short flags;
	int data;

	x = e->epe_revents;
	filter = 0;
	flags = 0;
	data = 0;
	if (x & POLLIN) {
		GT_ASSERT((x & POLLOUT) == 0);
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
	event->ident = e->epe_fd;
	event->fflags = 0;
	event->data = data;
	event->udata = e->epe_udata_ptr;
}
#endif /* __linux__ */
static int
uepoll_get(int fd, struct uepoll **ep)
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
	*ep = (struct uepoll *)fp;
	return 0;
}
static int
uepoll_get_events(struct uepoll *ep, epoll_event_t *buf, int cnt)
{
	int n, rc;
	short revents;
	struct log *log;
	struct file *fp;
	struct uepoll_entry *e, *tmp;
	if (cnt <= 0) {
		return 0;
	}
	n = 0;
	DLIST_FOREACH_SAFE(e, &ep->ep_head, epe_list, tmp) {
		ASSERT(e->epe_revents);
		if ((e->epe_flags & UEPOLL_FLAG_ENABLED) == 0) {
			continue;
		}
		rc = gt_sock_get(e->epe_fd, &fp);
		UNUSED(rc);
		ASSERT(rc == 0);
		ASSERT(fp->fl_type == FILE_SOCK);
		if ((e->epe_flags & UEPOLL_FLAG_ADDED) == 0) {
			revents = file_get_events(fp, &e->epe_aio);
			if (revents == 0) {
				uepoll_entry_remove(e);
				continue;
			}
			e->epe_revents = revents;
		}
		e->epe_flags &= ~UEPOLL_FLAG_ADDED;
		uepoll_entry_get_event(e, buf + n, fp);
		log = log_trace0();
		DBG(log, 0, "hit; fd=%d, events=%s",
		    e->epe_fd, log_add_poll_events(e->epe_revents));
		if (e->epe_flags & UEPOLL_FLAG_ET) {
			uepoll_entry_remove(e);
		}
		if (e->epe_flags & UEPOLL_FLAG_ONESHOT) {
			uepoll_entry_free(e);
		}
		n++;
		if (n == cnt) {
			break;
		}
	}
	return n;
}
#ifdef __linux__
static int
uepoll_wait_fd(int fd, epoll_event_t *buf, int cnt)
{
	int rc;
	rc = sys_epoll_pwait(NULL, fd, buf, cnt, 0, NULL);
	return rc;
}
#else /* __linux__ */
static int
uepoll_wait_fd(int fd, epoll_event_t *buf, int cnt)
{
	int rc;
	struct timespec to;
	to.tv_sec = 0;
	to.tv_nsec = 0;
	rc = sys_kevent(NULL, fd, NULL, 0, buf, cnt, &to);
	return rc;
}
static int
uepoll_kevent_mod(struct uepoll *ep, struct file *fp, struct kevent *event)
{
	short filter;
	struct uepoll_entry *e;
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
	e = uepoll_entry_get(ep, fp);
	if (event->flags & EV_DELETE) {
		if (e == NULL) {
			return -ENOENT;
		}
		uepoll_entry_free(e);
		return 0;
	}
	if (e == NULL) {
		if ((event->flags & EV_ADD) == 0) {
			return -ENOENT;
		}
		e = uepoll_entry_alloc(ep, fp, filter);
		if (e == NULL) {
			return -ENOMEM;
		}
	}
	e->epe_udata_ptr = event->udata;
	if (event->flags & EV_ENABLE) {
		e->epe_flags |= UEPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_DISABLE) {
		e->epe_flags &= ~UEPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_ONESHOT) {
		e->epe_flags |=  UEPOLL_FLAG_ONESHOT;
	} else {
		e->epe_flags &= ~UEPOLL_FLAG_ONESHOT;
	}
	if (event->flags & EV_CLEAR) {
		e->epe_flags &= ~UEPOLL_FLAG_ET;
	} else {
		e->epe_flags |=  UEPOLL_FLAG_ET;
	}
	return 0;
}
#endif /* __linux__ */
int
uepoll_create(int ep_fd)
{
	int rc, fd;
	struct log *log;
	struct file *fp;
	struct uepoll *ep;
	log = log_trace0();
	rc = file_alloc(log, &fp, FILE_EPOLL);
	if (rc) {
		return rc;
	}
	fp->fl_opened = 1;
	ep = (struct uepoll *)fp;
	ep->ep_fd = ep_fd;
	rc = mbuf_pool_alloc(log, &ep->ep_pool, sizeof(struct uepoll_entry));
	if (rc) {
		file_free(fp);
		return rc;
	}
	dlist_init(&ep->ep_head);
	fd = file_get_fd(fp);
	return fd;
}
int
uepoll_close(struct file *fp)
{
	int rc, tmp;
	struct mbuf *m;
	struct uepoll *ep;
	struct uepoll_entry *e;

	ep = (struct uepoll *)fp;
	rc = (*sys_close_fn)(ep->ep_fd);
	if (rc == -1) {
		rc = errno;
	}
	MBUF_FOREACH_SAFE(m, ep->ep_pool, tmp) {
		e = (struct uepoll_entry *)m;
		uepoll_entry_free(e);
	}
	ASSERT(mbuf_pool_is_empty(ep->ep_pool));
	mbuf_pool_free(ep->ep_pool);
	file_free(fp);
	return rc;
}

int
uepoll_pwait(int ep_fd, epoll_event_t *buf, int cnt,
	uint64_t to, const sigset_t *sigmask)
{
	int rc, n, epoch;
	struct pollfd pfds[1 + GT_FD_EVENTS_MAX];
	struct uepoll *ep;
	struct gt_fd_event_set set;

	if (cnt <= 0) {
		return -EINVAL;
	}
	rc = uepoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	n = uepoll_get_events(ep, buf, cnt);
	if (n) {
		return n;
	}
	pfds[0].fd = ep->ep_fd;
	pfds[0].events = POLLIN;
	set.fdes_to = to;
	do {
		gt_fd_event_set_init(&set, pfds + 1);
		epoch = gt_global_epoch;
		GT_GLOBAL_UNLOCK;
		if (n) {
			set.fdes_ts.tv_nsec = 0;
		}
		rc = sys_ppoll(NULL, pfds, set.fdes_nr_used + 1,
		               &set.fdes_ts, sigmask);
		GT_GLOBAL_LOCK;
		if (epoch != gt_global_epoch) {
			return -EFAULT;
		}	
		gt_fd_event_set_call(&set, pfds + 1);
		if (rc < 0) {
			return rc;
		}
		rc = uepoll_get(ep_fd, &ep);
		if (rc) {
			return rc;
		}
		if (pfds[0].revents) {
			rc = uepoll_wait_fd(ep->ep_fd, buf + n, cnt - n);
			if (rc < 0) {
				if (n == 0) {
					return rc;
				}
			} else {
				n += rc;
			}
		}
		n += uepoll_get_events(ep, buf + n, cnt - n);
	} while (n == 0 && set.fdes_to > 0);
	return n;
}

#ifdef __linux__
int
uepoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc, filter;
	struct file *fp;
	struct uepoll *ep;
	struct uepoll_entry *e;

	if (ep_fd == fd) {
		return -EINVAL;
	}
	rc = uepoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	rc = gt_sock_get(fd, &fp);
	if (rc) {
		rc = (*sys_epoll_ctl_fn)(ep->ep_fd, op, fd, event);
		if (rc) {
			rc = -errno;
			ASSERT(rc);
		}
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
	e = uepoll_entry_get(ep, fp);
	if (e == NULL) {
		switch (op) {
		case EPOLL_CTL_ADD:
			e = uepoll_entry_alloc(ep, fp, filter);
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
			uepoll_entry_set(e, fp, filter);
			break;
		case EPOLL_CTL_DEL:
			uepoll_entry_free(e);
			return 0;
		default:
			return -EINVAL;
		}
	}
	e->epe_udata_u64 = event->data.u64;
	if (event->events & EPOLLET) {
		e->epe_flags |= UEPOLL_FLAG_ET;
	} else {
		e->epe_flags &= ~UEPOLL_FLAG_ET;
	}
	if (event->events & EPOLLONESHOT) {
		e->epe_flags |= UEPOLL_FLAG_ONESHOT;
	} else {
		e->epe_flags &= ~UEPOLL_FLAG_ONESHOT;
	}
	return 0;
}
#else /* __linux__ */
int
upoll_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int i, rc;
	uint64_t to;
	struct kevent *event;
	struct file *fp;
	struct uepoll *ep;

	rc = uepoll_get(kq, &ep);
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
			rc = uepoll_kevent_mod(ep, fp, event);
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
		rc = uepoll_pwait(kq, eventlist, nevents, to, NULL);
	} else {
		rc = 0;
	}
	return rc;
}
#endif /* __linux__ */


