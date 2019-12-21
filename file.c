#include "file.h"
#include "log.h"
#include "tcp.h"
#include "epoll.h"
#include "strbuf.h"
#include "fd_event.h"
#include "ctl.h"

#define GT_FILE_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(mod_deinit) \
	x(cb_call) \
	x(alloc) \
	x(free) \
	x(wakeup) \
	x(get_events) \
	x(cb_set) \
	x(cb_cancel) \

static int gt_file_first_fd;
static struct gt_mbuf_pool *gt_file_pool;
static struct gt_log_scope this_log;
GT_FILE_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static void gt_file_init(struct gt_file *fp, int type);

static void gt_file_cb_call(struct gt_file_cb *cb, short revents);

static void gt_file_wait_cb(struct gt_file_cb *cb, int fd, short revents);

static void gt_file_cb_stub(struct gt_file_cb *cb, int fd, short events);

static void
gt_file_init(struct gt_file *fp, int type)
{
	fp->fl_flags = 0;
	fp->fl_type = type;
	fp->fl_blocked = 1;
	gt_list_init(&fp->fl_cbq);
}

static void
gt_file_cb_call(struct gt_file_cb *cb, short revents)
{
	int fd;
	gt_file_cb_f fn;

	fn = cb->fcb_fn;
	fd = cb->fcb_fd;
	GT_DBG(cb_call, 0, "hit; cb=%p, fd=%d, events=%s",
	       cb, fd, gt_log_add_poll_events(revents));
	(*fn)(cb, fd, revents);
}

int
gt_file_mod_init()
{
	int rc;
	struct gt_log *log;

	gt_log_scope_init(&this_log, "file");
	GT_FILE_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	gt_file_first_fd = FD_SETSIZE / 2;
	gt_ctl_add_int(log, GT_CTL_FILE_FIRST_FD, GT_CTL_LD,
	               &gt_file_first_fd, 3, 1024 * 1024);
	rc = gt_mbuf_pool_new(log, &gt_file_pool, sizeof(struct gt_sock));
	if (rc) {
		gt_ctl_del(log, "file.first_fd");
	}
	return rc;
}

void
gt_file_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_ctl_del(log, GT_CTL_FILE_FIRST_FD);
	gt_mbuf_pool_del(gt_file_pool);
	gt_log_scope_deinit(log, &this_log);
}

int
gt_file_get_fd(struct gt_file *fp)
{
	int m_id;

	m_id = gt_mbuf_get_id(gt_file_pool, &fp->fl_mbuf);
	return m_id + gt_file_first_fd;
}

struct gt_file *
gt_file_next(int fd)
{
	int m_id;
	struct gt_mbuf *m;
	struct gt_file *fp;

	if (fd < gt_file_first_fd) {
		m_id = 0;
	} else {
		m_id = fd - gt_file_first_fd;
	}
	m = gt_mbuf_next(gt_file_pool, m_id);
	fp = (struct gt_file *)m;
	return fp;
}

int
gt_file_alloc(struct gt_log *log, struct gt_file **fpp, int type)
{
	int rc;
	struct gt_file *fp;

	log = GT_LOG_TRACE(log, alloc);
	rc = gt_mbuf_alloc(log, gt_file_pool, (struct gt_mbuf **)fpp);
	if (rc == 0) {
		fp = *fpp;
		gt_file_init(fp, type);
		GT_DBG(alloc, 0, "ok; fp=%p, fd=%d", fp, gt_file_get_fd(fp));
	} else {
		GT_DBG(alloc, -rc, "failed");
	}
	return rc;
}

int
gt_file_alloc4(struct gt_log *log, struct gt_file **fpp, int type, int fd)
{
	int rc;
	uint32_t m_id;
	struct gt_file *fp;

	log = GT_LOG_TRACE(log, alloc);
	if (fd < gt_file_first_fd) {
		rc = -EBADF;
	} else {
		m_id = fd - gt_file_first_fd;
		rc = gt_mbuf_alloc4(log, gt_file_pool, m_id,
		                    (struct gt_mbuf **)fpp);
	}
	if (rc == 0) {
		fp = *fpp;
		gt_file_init(fp, type);
		GT_DBG(alloc, 0, "ok; fp=%p, fd=%d", fp, gt_file_get_fd(fp));
	} else {
		GT_DBG(alloc, -rc, "failed");
	}
	return rc;
}

int
gt_file_get(int fd, struct gt_file **fpp)
{
	int m_id;
	struct gt_mbuf *m;
	struct gt_file *fp;

	*fpp = NULL;
	if (fd < gt_file_first_fd) {
		return -EBADF;
	}
	m_id = fd - gt_file_first_fd;
	m = gt_mbuf_get(gt_file_pool, m_id);
	fp = (struct gt_file *)m;
	if (fp == NULL) {
		return -EBADF;
	}
	if (fp->fl_opened == 0) {
		return -EBADF;
	}
	*fpp = fp;
	return 0;
}

void
gt_file_free(struct gt_file *fp)
{
	GT_DBG(free, 0, "hit; fp=%p, fd=%d", fp, gt_file_get_fd(fp));
	gt_mbuf_free(&fp->fl_mbuf);
}

void
gt_file_close(struct gt_file *fp, int how)
{
	fp->fl_opened = 0;
	gt_file_wakeup(fp, POLLNVAL);
	switch (fp->fl_type) {
	case GT_FILE_SOCK:
		gt_sock_close(fp, GT_SOCK_GRACEFULL);
		break;
	case GT_FILE_EPOLL:
		gt_epoll_close(fp);
		break;
	default:
		GT_BUG;
	}
}

int
gt_file_cntl(struct gt_file *fp, int cmd, uintptr_t arg)
{
	int flags, rc;

	switch (cmd) {
	case F_GETFD:
		return O_CLOEXEC;
	case F_SETFD:
		return 0;
	case F_GETFL:
		rc = O_RDWR;
		if (!fp->fl_blocked) {
			rc |= O_NONBLOCK;
		}
		return rc;
	case F_SETFL:
		flags = arg;
		if (flags & ~(O_RDWR|O_NONBLOCK)) {
			break;
		}
		if ((flags & O_NONBLOCK) == 0) {
			fp->fl_blocked = 1;
		} else {
			fp->fl_blocked = 0;
		}
		return 0;
	default:
		break;
	}
	return -ENOTSUP;
}

int
gt_file_ioctl(struct gt_file *fp, unsigned long request, uintptr_t arg)
{
	int rc;

	if (fp->fl_type != GT_FILE_SOCK) {
		return -ENOTSUP;
	}
	rc = 0;
	switch (request) {
	case FIONBIO:
		if (arg == 0) {
			fp->fl_blocked = 1;
		} else {
			fp->fl_blocked = 0;
		}
		break;
	case FIONREAD:
		rc = gt_sock_nread(fp);
		if (rc < 0) {
			break;
		}
		*((int *)arg) = rc;
		break;
	default:
		rc = gt_sock_ioctl(fp, request, arg);
		break;
	}
	return rc;
}

void
gt_file_wakeup(struct gt_file *fp, short events)
{
	short revents;
	struct gt_file_cb *cb, *tmp;

	GT_ASSERT(events);
	GT_DBG(wakeup, 0, "hit; fd=%d, events=%s",
	       gt_file_get_fd(fp), gt_log_add_poll_events(events));
	GT_LIST_FOREACH_SAFE(cb, &fp->fl_cbq, fcb_mbuf.mb_list, tmp) {
		GT_ASSERT(cb->fcb_filter);
		revents = (events & cb->fcb_filter);
		if (revents) {
			gt_file_cb_call(cb, revents);
		}
	}
}

struct gt_file_wait_data {
	struct gt_file_cb w_cb;
	short w_revents;
};

static void
gt_file_wait_cb(struct gt_file_cb *cb, int fd, short revents)
{
	struct gt_file_wait_data *data;

	data = gt_container_of(cb, struct gt_file_wait_data, w_cb);
	data->w_revents = revents;
}

int
gt_file_wait(struct gt_file *fp, short events)
{
	int rc;
	struct gt_file_wait_data data;

	gt_mbuf_init(&data.w_cb.fcb_mbuf);
	gt_file_cb_init(&data.w_cb);
	data.w_revents = 0;
	gt_file_cb_set(fp, &data.w_cb, events, gt_file_wait_cb);
	do {
		rc = gt_fd_event_mod_wait();
	} while (rc == 0 && data.w_revents == 0);
	gt_file_cb_cancel(&data.w_cb);
	return rc;
}

short
gt_file_get_events(struct gt_file *fp, struct gt_file_cb *cb)
{
	short revents;

	if (fp->fl_type == GT_FILE_SOCK) {
		revents = gt_sock_get_events(fp);
	} else {
		revents = 0;
	}
	revents &= cb->fcb_filter;
	GT_DBG(get_events, 0, "hit; cb=%p, fd=%d, events=%s",
	       cb, gt_file_get_fd(fp), gt_log_add_poll_events(revents));
	return revents;
}

void
gt_file_cb_init(struct gt_file_cb *cb)
{
	cb->fcb_filter = 0;
}

static void
gt_file_cb_stub(struct gt_file_cb *cb, int fd, short events)
{
}

void
gt_file_cb_set(struct gt_file *fp, struct gt_file_cb *cb,
	short events, gt_file_cb_f fn)
{
	int fd;
	const char *action;
	short filter, revents;

	GT_ASSERT(fp->fl_type == GT_FILE_SOCK);
	filter = events|POLLERR|POLLNVAL;
	if (cb->fcb_filter == filter) {
		return;
	}
	fd = gt_file_get_fd(fp);
	cb->fcb_fd = fd;
	cb->fcb_fn = fn;
	if (cb->fcb_fn == NULL) {
		cb->fcb_fn = gt_file_cb_stub;
	}
	if (cb->fcb_filter == 0) {
		GT_LIST_INSERT_HEAD(&fp->fl_cbq, cb, fcb_mbuf.mb_list);
		action = "add";
	} else {
		action = "mod";
	}
	GT_UNUSED(action);
	GT_DBG(cb_set, 0, "%s; cb=%p, fd=%d, filter=%s",
	       action, cb, fd, gt_log_add_poll_events(filter));
	cb->fcb_filter |= filter;
	revents = gt_file_get_events(fp, cb);
	if (revents) {
		gt_file_cb_call(cb, revents);
	}
}

void
gt_file_cb_cancel(struct gt_file_cb *cb)
{
	if (cb->fcb_filter) {
		GT_DBG(cb_cancel, 0,
		       "hit; cb=%p, fd=%d, filter=%s",
		       cb, cb->fcb_fd,
		       gt_log_add_poll_events(cb->fcb_filter));
		cb->fcb_filter = 0;
		GT_LIST_REMOVE(cb, fcb_mbuf.mb_list);
	}
}

int
gt_file_try_fd(int fd)
{
	if (fd < gt_file_first_fd) {
		return 0;
	} else {
		return -ENFILE;
	}
}
