#include "internals.h"

#define FILE_LOG_MSG_FOREACH(x) \
	x(aio_call) \
	x(alloc) \
	x(free) \
	x(wakeup) \
	x(get_events) \
	x(aio_set) \
	x(aio_cancel) \

struct file_mod {
	struct log_scope log_scope;
	FILE_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
	int file_first_fd;
};

static struct mbuf_pool *file_pool;
static struct file_mod *current_mod;

static void
file_init(struct file *fp, int type)
{
	fp->fl_flags = 0;
	fp->fl_type = type;
	fp->fl_blocked = 1;
	dlist_init(&fp->fl_aioq);
}
static void
file_aio_call(struct file_aio *aio, short revents)
{
	int fd;
	struct log *log;
	file_aio_f fn;
	fn = aio->faio_fn;
	fd = aio->faio_fd;
	log = log_trace0();
	DBG(log, LOG_MSG(aio_call), 0, "hit; aio=%p, fd=%d, events=%s",
	    aio, fd, log_add_poll_events(revents));
	(*fn)(aio, fd, revents);
}
int
file_mod_init(struct log *log, void **pp)
{
	int rc;
	struct file_mod *mod;
	LOG_TRACE(log);
	rc = mm_alloc(log, pp, sizeof(*mod));
	if (rc == 0) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "file");
		mod->file_first_fd = FD_SETSIZE / 2;
		sysctl_add_int(log, SYSCTL_FILE_FIRST_FD, SYSCTL_LD,
			       &mod->file_first_fd, 3, 1024 * 1024);
	}
	return rc;
}
int
file_mod_attach(struct log *log, void *raw_mod)
{
	int rc;
	current_mod = raw_mod;
	LOG_TRACE(log);
	rc = mbuf_pool_alloc(log, &file_pool, sizeof(struct gt_sock));
	return rc;
}
void
file_mod_deinit(struct log *log, void *raw_mod)
{
	struct file_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	sysctl_del(log, SYSCTL_FILE_FIRST_FD);
	log_scope_deinit(log, &mod->log_scope);
	mm_free(mod);
}
void
file_mod_detach(struct log *log)
{
	//ASSERT(mbuf_pool_is_empty(file_pool));
	mbuf_pool_free(file_pool);
	file_pool = NULL;
	current_mod = NULL;
}
int
file_get_fd(struct file *fp)
{
	int m_id;
	m_id = mbuf_get_id(file_pool, &fp->fl_mbuf);
	return m_id + current_mod->file_first_fd;
}
struct file *
file_next(int fd)
{
	int m_id;
	struct mbuf *m;
	struct file *fp;
	if (fd < current_mod->file_first_fd) {
		m_id = 0;
	} else {
		m_id = fd - current_mod->file_first_fd;
	}
	m = mbuf_next(file_pool, m_id);
	fp = (struct file *)m;
	return fp;
}
int
file_alloc(struct log *log, struct file **fpp, int type)
{
	int rc;
	struct file *fp;
	LOG_TRACE(log);
	rc = mbuf_alloc(log, file_pool, (struct mbuf **)fpp);
	if (rc == 0) {
		fp = *fpp;
		file_init(fp, type);
		DBG(log, LOG_MSG(alloc), 0, "ok; fp=%p, fd=%d",
		    fp, file_get_fd(fp));
	} else {
		DBG(log, LOG_MSG(alloc), -rc, "failed");
	}
	return rc;
}
int
file_alloc4(struct log *log, struct file **fpp, int type, int fd)
{
	int rc;
	uint32_t m_id;
	struct file *fp;
	LOG_TRACE(log);
	if (fd < current_mod->file_first_fd) {
		rc = -EBADF;
	} else {
		m_id = fd - current_mod->file_first_fd;
		rc = mbuf_alloc4(log, file_pool, m_id,
		                 (struct mbuf **)fpp);
	}
	if (rc == 0) {
		fp = *fpp;
		file_init(fp, type);
		DBG(log, LOG_MSG(alloc), 0, "ok; fp=%p, fd=%d",
		    fp, file_get_fd(fp));
	} else {
		DBG(log, LOG_MSG(alloc), -rc, "failed");
	}
	return rc;
}
int
file_get(int fd, struct file **fpp)
{
	int m_id;
	struct mbuf *m;
	struct file *fp;
	*fpp = NULL;
	if (fd < current_mod->file_first_fd) {
		return -EBADF;
	}
	m_id = fd - current_mod->file_first_fd;
	m = mbuf_get(file_pool, m_id);
	fp = (struct file *)m;
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
file_free(struct file *fp)
{
	struct log *log;
	log = log_trace0();
	DBG(log, LOG_MSG(free), 0, "hit; fp=%p, fd=%d",
	    fp, file_get_fd(fp));
	mbuf_free(&fp->fl_mbuf);
}
void
file_close(struct file *fp, int how)
{
	fp->fl_opened = 0;
	file_wakeup(fp, POLLNVAL);
	switch (fp->fl_type) {
	case FILE_SOCK:
		gt_sock_close(fp, GT_SOCK_GRACEFULL);
		break;
	case FILE_EPOLL:
		gt_epoll_close(fp);
		break;
	default:
		BUG;
	}
}
int
file_cntl(struct file *fp, int cmd, uintptr_t arg)
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
file_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
{
	int rc;
	if (fp->fl_type != FILE_SOCK) {
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
file_wakeup(struct file *fp, short events)
{
	short revents;
	struct log *log;
	struct file_aio *aio, *tmp;
	ASSERT(events);
	log = log_trace0();
	DBG(log, LOG_MSG(wakeup), 0, "hit; fd=%d, events=%s",
	    file_get_fd(fp), log_add_poll_events(events));
	DLIST_FOREACH_SAFE(aio, &fp->fl_aioq, faio_list, tmp) {
		ASSERT(aio->faio_filter);
		revents = (events &aio->faio_filter);
		if (revents) {
			file_aio_call(aio, revents);
		}
	}
}
struct file_wait_data {
	struct file_aio w_aio;
	short w_revents;
};
static void
file_wait_cb(struct file_aio *aio, int fd, short revents)
{
	struct file_wait_data *data;
	data = container_of(aio, struct file_wait_data, w_aio);
	data->w_revents = revents;
}
int
file_wait(struct file *fp, short events)
{
	int rc;
	struct file_wait_data data;
	mbuf_init(&data.w_aio.faio_mbuf);
	file_aio_init(&data.w_aio);
	data.w_revents = 0;
	file_aio_set(fp, &data.w_aio, events, file_wait_cb);
	do {
		rc = gt_fd_event_mod_wait();
	} while (rc == 0 && data.w_revents == 0);
	file_aio_cancel(&data.w_aio);
	return rc;
}
short
file_get_events(struct file *fp, struct file_aio *aio)
{
	short revents;
	struct log *log;
	if (fp->fl_type == FILE_SOCK) {
		revents = gt_sock_get_events(fp);
	} else {
		revents = 0;
	}
	revents &= aio->faio_filter;
	log = log_trace0();
	DBG(log, LOG_MSG(get_events), 0, "hit; aio=%p, fd=%d, events=%s",
	    aio, file_get_fd(fp), log_add_poll_events(revents));
	return revents;
}
void
file_aio_init(struct file_aio *aio)
{
	aio->faio_filter = 0;
}
static void
file_aio_stub(struct file_aio *aio, int fd, short events)
{
}
void
file_aio_set(struct file *fp, struct file_aio *aio, short events,
	file_aio_f fn)
{
	int fd;
	const char *action;
	short filter, revents;
	struct log *log;
	ASSERT(fp->fl_type == FILE_SOCK);
	filter = events|POLLERR|POLLNVAL;
	if (aio->faio_filter == filter) {
		return;
	}
	fd = file_get_fd(fp);
	aio->faio_fd = fd;
	aio->faio_fn = fn;
	if (aio->faio_fn == NULL) {
		aio->faio_fn = file_aio_stub;
	}
	if (aio->faio_filter == 0) {
		DLIST_INSERT_HEAD(&fp->fl_aioq, aio, faio_list);
		action = "add";
	} else {
		action = "mod";
	}
	UNUSED(action);
	log = log_trace0();
	DBG(log, LOG_MSG(aio_set), 0, "%s; aio=%p, fd=%d, filter=%s",
	    action, aio, fd, log_add_poll_events(filter));
	aio->faio_filter |= filter;
	revents = file_get_events(fp, aio);
	if (revents) {
		file_aio_call(aio, revents);
	}
}

void
file_aio_cancel(struct file_aio *aio)
{
	struct log *log;
	if (aio->faio_filter) {
		log = log_trace0();
		DBG(log, LOG_MSG(aio_cancel), 0,
		    "hit; aio=%p, fd=%d, filter=%s",
		    aio, aio->faio_fd,
		    log_add_poll_events(aio->faio_filter));
		aio->faio_filter = 0;
		DLIST_REMOVE(aio, faio_list);
	}
}
int
file_try_fd(int fd)
{
	if (fd < current_mod->file_first_fd) {
		return 0;
	} else {
		return -ENFILE;
	}
}
