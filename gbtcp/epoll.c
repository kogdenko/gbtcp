#include "log.h"
#include "sys.h"
#include "global.h"
#include "strbuf.h"
#include "mbuf.h"
#include "poll.h"
#include "file.h"
#include "fd_event.h"
#include "tcp.h"
#include "epoll.h"

#define GT_EPOLL_CNT_MAX 8

#define GT_EPOLL_FLAG_ENABLED (1 << 0)
#define GT_EPOLL_FLAG_ONESHOT (1 << 1)
#define GT_EPOLL_FLAG_ET (1 << 2)
#define GT_EPOLL_FLAG_ADDED (1 << 3)

#define GT_EPOLL_LOG_NODE_FOREACH(x) \
	x(mod_deinit) \
	x(open) \
	x(get_events) \

struct gt_epoll {
	struct gt_file ep_file;
	int ep_fd;
	struct gt_mbuf_pool *ep_pool;
	struct dllist ep_head;
};

struct gt_epoll_entry {
	struct gt_file_cb epe_cb;
	struct dllist epe_list;
	struct gt_epoll *epe_ep;
	int epe_fd;
	short epe_revents;
	short epe_flags;
	union {
		uint64_t epe_udata_u64;
		void *epe_udata_ptr;
	};
};

static int gt_epoll_cnt;
static struct gt_log_scope this_log;
GT_EPOLL_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

// entry
static struct gt_epoll_entry *gt_epoll_entry_alloc(struct gt_epoll *ep,
	struct gt_file *fp, short filter);

static struct gt_epoll_entry *gt_epoll_entry_get(struct gt_epoll *ep,
	struct gt_file *fp);

static void gt_epoll_entry_remove(struct gt_epoll_entry *e);

static void gt_epoll_entry_free(struct gt_epoll_entry *e);

static void gt_epoll_entry_get_event(struct gt_epoll_entry *e,
	gt_epoll_event_t *event, struct gt_file *fp);

static void gt_epoll_entry_cb(struct gt_file_cb *cb, int fd, short revents);

static void gt_epoll_entry_set(struct gt_epoll_entry *e,
	struct gt_file *fp, short filter);

// epoll
static int gt_epoll_get(int fd, struct gt_epoll **ep);

static int gt_epoll_get_events(struct gt_epoll *ep,
	gt_epoll_event_t *buf, int cnt);

static int gt_epoll_wait_fd(int fd, gt_epoll_event_t *buf, int cnt);

#ifndef __linux__
static int gt_epoll_kevent_mod(struct gt_epoll *ep, struct gt_file *fp,
	struct kevent *event);
#endif /* __linux__ */


int
gt_epoll_mod_init()
{
	gt_log_scope_init(&this_log, "epoll");
	GT_EPOLL_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	gt_epoll_cnt = 0;
	return 0;
}

void
gt_epoll_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_log_scope_deinit(log, &this_log);
}

int
gt_epoll_create(int ep_fd)
{
	int rc, fd;
	struct gt_log *log;
	struct gt_file *fp;
	struct gt_epoll *ep;

	log = GT_LOG_TRACE1(open);
	if (gt_epoll_cnt == GT_EPOLL_CNT_MAX) {
		GT_LOGF(log, LOG_ERR, 0, "too many epoll objects");
		return -ENFILE;
	}
	rc = gt_file_alloc(log, &fp, GT_FILE_EPOLL);
	if (rc) {
		return rc;
	}
	fp->fl_opened = 1;
	ep = (struct gt_epoll *)fp;
	ep->ep_fd = ep_fd;
	rc = gt_mbuf_pool_new(log, &ep->ep_pool,
	                      sizeof(struct gt_epoll_entry));
	if (rc) {
		gt_file_free(fp);
		return rc;
	}
	dllist_init(&ep->ep_head);
	fd = gt_file_get_fd(fp);
	gt_epoll_cnt++;
	return fd;
}

int
gt_epoll_close(struct gt_file *fp)
{
	int rc, tmp;
	struct gt_mbuf *m;
	struct gt_epoll *ep;
	struct gt_epoll_entry *e;

	ep = (struct gt_epoll *)fp;
	rc = (*gt_sys_close_fn)(ep->ep_fd);
	if (rc == -1) {
		rc = errno;
	}
	GT_MBUF_FOREACH_SAFE(m, ep->ep_pool, tmp) {
		e = (struct gt_epoll_entry *)m;
		gt_epoll_entry_free(e);
	}
	GT_ASSERT(gt_mbuf_pool_is_empty(ep->ep_pool));
	gt_mbuf_pool_del(ep->ep_pool);
	gt_file_free(fp);
	gt_epoll_cnt--;
	return rc;
}

int
gt_epoll_pwait(int ep_fd, gt_epoll_event_t *buf, int cnt,
	uint64_t to, const sigset_t *sigmask)
{
	int rc, n, epoch;
	struct pollfd pfds[1 + GT_FD_EVENTS_MAX];
	struct gt_epoll *ep;
	struct gt_fd_event_set set;

	if (cnt <= 0) {
		return -EINVAL;
	}
	rc = gt_epoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	n = gt_epoll_get_events(ep, buf, cnt);
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
		rc = gt_sys_ppoll(NULL, pfds, set.fdes_nr_used + 1,
		                  &set.fdes_ts, sigmask);
		GT_GLOBAL_LOCK;
		if (epoch != gt_global_epoch) {
			return -EFAULT;
		}	
		gt_fd_event_set_call(&set, pfds + 1);
		if (rc < 0) {
			return rc;
		}
		rc = gt_epoll_get(ep_fd, &ep);
		if (rc) {
			return rc;
		}
		if (pfds[0].revents) {
			rc = gt_epoll_wait_fd(ep->ep_fd, buf + n, cnt - n);
			if (rc < 0) {
				if (n == 0) {
					return rc;
				}
			} else {
				n += rc;
			}
		}
		n += gt_epoll_get_events(ep, buf + n, cnt - n);
	} while (n == 0 && set.fdes_to > 0);
	return n;
}

#ifdef __linux__
int
gt_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc, filter;
	struct gt_file *fp;
	struct gt_epoll *ep;
	struct gt_epoll_entry *e;

	if (ep_fd == fd) {
		return -EINVAL;
	}
	rc = gt_epoll_get(ep_fd, &ep);
	if (rc) {
		return rc;
	}
	rc = gt_sock_get(fd, &fp);
	if (rc) {
		rc = (*gt_sys_epoll_ctl_fn)(ep->ep_fd, op, fd, event);
		if (rc) {
			rc = -errno;
			GT_ASSERT(rc);
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
	e = gt_epoll_entry_get(ep, fp);
	if (e == NULL) {
		switch (op) {
		case EPOLL_CTL_ADD:
			e = gt_epoll_entry_alloc(ep, fp, filter);
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
			gt_epoll_entry_set(e, fp, filter);
			break;
		case EPOLL_CTL_DEL:
			gt_epoll_entry_free(e);
			return 0;
		default:
			return -EINVAL;
		}
	}
	e->epe_udata_u64 = event->data.u64;
	if (event->events & EPOLLET) {
		e->epe_flags |= GT_EPOLL_FLAG_ET;
	} else {
		e->epe_flags &= ~GT_EPOLL_FLAG_ET;
	}
	if (event->events & EPOLLONESHOT) {
		e->epe_flags |= GT_EPOLL_FLAG_ONESHOT;
	} else {
		e->epe_flags &= ~GT_EPOLL_FLAG_ONESHOT;
	}
	return 0;
}
#else /* __linux__ */
int
gt_epoll_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int i, rc;
	uint64_t to;
	struct kevent *event;
	struct gt_file *fp;
	struct gt_epoll *ep;

	rc = gt_epoll_get(kq, &ep);
	if (rc) {
		return rc;
	}
	for (i = 0; i < nchanges; ++i) {
		event = (struct kevent *)changelist + i;
		rc = gt_sock_get(event->ident, &fp);
		if (rc) {
			rc = (*gt_sys_kevent_fn)(ep->ep_fd, event, 1,
			                         NULL, 0, NULL);
			if (rc == -1) {
				rc = -errno;
				GT_ASSERT(rc);
			}
		} else {
			rc = gt_epoll_kevent_mod(ep, fp, event);
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
		rc = gt_epoll_pwait(kq, eventlist, nevents, to, NULL);
	} else {
		rc = 0;
	}
	return rc;
}
#endif /* __linux__ */

// static
static struct gt_epoll_entry *
gt_epoll_entry_alloc(struct gt_epoll *ep, struct gt_file *fp, short filter)
{
	int rc;
        struct gt_epoll_entry *e;

	rc = gt_mbuf_alloc(NULL, ep->ep_pool, (struct gt_mbuf **)&e);
	if (rc) {
		return NULL;
	}
	e->epe_revents = 0;
	e->epe_flags = GT_EPOLL_FLAG_ENABLED;
	e->epe_ep = ep;
	e->epe_fd = gt_file_get_fd(fp);
	gt_file_cb_init(&e->epe_cb);
	gt_epoll_entry_set(e, fp, filter);
	return e;
}

static struct gt_epoll_entry *
gt_epoll_entry_get(struct gt_epoll *ep, struct gt_file *fp)
{
	struct gt_mbuf *mbuf;
	struct gt_epoll_entry *e;

	DLLIST_FOREACH(mbuf, &fp->fl_cbq, mb_list) {
		if (mbuf->mb_pool_id == ep->ep_pool->mbp_id) {
			e = (struct gt_epoll_entry *)mbuf;
			return e;
		}
	}
	return NULL;
}

static void
gt_epoll_entry_remove(struct gt_epoll_entry *e)
{
	GT_ASSERT(e->epe_revents);
	DLLIST_REMOVE(e, epe_list);
	e->epe_revents = 0;
}

static void
gt_epoll_entry_free(struct gt_epoll_entry *e)
{
	if (e->epe_revents) {
		gt_epoll_entry_remove(e);
	}
	gt_file_cb_cancel(&e->epe_cb);
	gt_mbuf_free(&e->epe_cb.fcb_mbuf);
}

#ifdef __linux__
static void
gt_epoll_entry_get_event(struct gt_epoll_entry *e,
	gt_epoll_event_t *event, struct gt_file *fp)
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
gt_epoll_entry_get_event(struct gt_epoll_entry *e,
	gt_epoll_event_t *event, struct gt_file *fp)
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
		gt_file_ioctl(fp, FIONREAD, (uintptr_t)(&data));
	} else if (x & POLLOUT) {
		filter = EVFILT_WRITE;
		gt_file_ioctl(fp, FIONSPACE, (uintptr_t)(&data));
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

static void
gt_epoll_entry_cb(struct gt_file_cb *cb, int fd, short revents)
{
	struct gt_epoll_entry *e;

	e = (struct gt_epoll_entry *)cb;
	if (revents & POLLNVAL) {
		gt_epoll_entry_free(e);
	} else {
		GT_ASSERT(revents);
		if (e->epe_revents == 0) {
			e->epe_flags |= GT_EPOLL_FLAG_ADDED;
			DLLIST_INSERT_HEAD(&e->epe_ep->ep_head, e, epe_list);
		}
		e->epe_revents |= revents;
	}
}

static void
gt_epoll_entry_set(struct gt_epoll_entry *e, struct gt_file *fp, short filter)
{
	if (e->epe_cb.fcb_filter != filter) {
		if (e->epe_revents) {
			DLLIST_REMOVE(e, epe_list);
			e->epe_revents = 0;
		}	
		gt_file_cb_set(fp, &e->epe_cb, filter, gt_epoll_entry_cb);
	}
}

static int
gt_epoll_get(int fd, struct gt_epoll **ep)
{
	int rc;
	struct gt_file *fp;

	rc = gt_file_get(fd, &fp);
	if (rc < 0) {
		return rc;
	}
	if (fp->fl_type != GT_FILE_EPOLL) {
		return -EINVAL;
	}
	*ep = (struct gt_epoll *)fp;
	return 0;
}


static int
gt_epoll_get_events(struct gt_epoll *ep, gt_epoll_event_t *buf, int cnt)
{
	int n, rc;
	short revents;
	struct gt_file *fp;
	struct gt_epoll_entry *e, *tmp;

	if (cnt <= 0) {
		return 0;
	}
	n = 0;
	DLLIST_FOREACH_SAFE(e, &ep->ep_head, epe_list, tmp) {
		GT_ASSERT(e->epe_revents);
		if ((e->epe_flags & GT_EPOLL_FLAG_ENABLED) == 0) {
			continue;
		}
		rc = gt_sock_get(e->epe_fd, &fp);
		UNUSED(rc);
		GT_ASSERT(rc == 0);
		GT_ASSERT(fp->fl_type == GT_FILE_SOCK);
		if ((e->epe_flags & GT_EPOLL_FLAG_ADDED) == 0) {
			revents = gt_file_get_events(fp, &e->epe_cb);
			if (revents == 0) {
				gt_epoll_entry_remove(e);
				continue;
			}
			e->epe_revents = revents;
		}
		e->epe_flags &= ~GT_EPOLL_FLAG_ADDED;
		gt_epoll_entry_get_event(e, buf + n, fp);
		GT_DBG(get_events, 0, "hit; fd=%d, events=%s",
		       e->epe_fd, gt_log_add_poll_events(e->epe_revents));
		if (e->epe_flags & GT_EPOLL_FLAG_ET) {
			gt_epoll_entry_remove(e);
		}
		if (e->epe_flags & GT_EPOLL_FLAG_ONESHOT) {
			gt_epoll_entry_free(e);
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
gt_epoll_wait_fd(int fd, gt_epoll_event_t *buf, int cnt)
{
	int rc;

	rc = (*gt_sys_epoll_pwait_fn)(fd, buf, cnt, 0, NULL);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
	}
	return rc;
}
#else /* __linux__ */
static int
gt_epoll_wait_fd(int fd, gt_epoll_event_t *buf, int cnt)
{
	int rc;
	struct timespec to;

	to.tv_sec = 0;
	to.tv_nsec = 0;
	rc = (*gt_sys_kevent_fn)(fd, NULL, 0, buf, cnt, &to);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc); 
	}
	return rc;
}

static int
gt_epoll_kevent_mod(struct gt_epoll *ep, struct gt_file *fp,
	struct kevent *event)
{
	short filter;
	struct gt_epoll_entry *e;

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
	e = gt_epoll_entry_get(ep, fp);
	if (event->flags & EV_DELETE) {
		if (e == NULL) {
			return -ENOENT;
		}
		gt_epoll_entry_free(e);
		return 0;
	}
	if (e == NULL) {
		if ((event->flags & EV_ADD) == 0) {
			return -ENOENT;
		}
		e = gt_epoll_entry_alloc(ep, fp, filter);
		if (e == NULL) {
			return -ENOMEM;
		}
	}
	e->epe_udata_ptr = event->udata;
	if (event->flags & EV_ENABLE) {
		e->epe_flags |= GT_EPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_DISABLE) {
		e->epe_flags &= ~GT_EPOLL_FLAG_ENABLED;
	}
	if (event->flags & EV_ONESHOT) {
		e->epe_flags |=  GT_EPOLL_FLAG_ONESHOT;
	} else {
		e->epe_flags &= ~GT_EPOLL_FLAG_ONESHOT;
	}
	if (event->flags & EV_CLEAR) {
		e->epe_flags &= ~GT_EPOLL_FLAG_ET;
	} else {
		e->epe_flags |=  GT_EPOLL_FLAG_ET;
	}
	return 0;
}
#endif /* __linux__ */
