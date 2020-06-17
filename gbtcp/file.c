#include "internals.h"

#define CURMOD file

struct file_mod {
	struct log_scope log_scope;
	int file_first_fd;
	int file_last_fd;
};

static void
file_init(struct file *fp, int type)
{
	fp->fl_flags = 0;
	fp->fl_type = type;
	fp->fl_blocked = 1;
	fp->fl_sid = current->p_sid;
	dlist_init(&fp->fl_aioq);
}

static void
file_aio_call(struct file_aio *aio, short revents)
{
	int fd;
	short revents_filtered;
	file_aio_f fn;

	revents_filtered = aio->faio_filter & revents;
	if (revents_filtered) {
		fn = aio->faio_fn;
		fd = aio->faio_fd;
		aio->faio_revents |= revents_filtered;
		DBG(0, "hit; aio=%p, fd=%d, events=%s",
		    aio, fd, log_add_poll_events(revents_filtered));
		if (fn != NULL) {
			(*fn)(aio, fd, revents_filtered);
		}
	}
}

static int
sysctl_file_nofile(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *out)
{
	int rc;
	u_long first_fd, last_fd;

	strbuf_addf(out, "%d,%d", curmod->file_first_fd, curmod->file_last_fd);
	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%lu,%lu", &first_fd, &last_fd);
	if (rc != -2 || last_fd <= first_fd) {
		return -EINVAL;
	} else if (last_fd > 100*1000000) {
		return -ERANGE;
	} else {
		curmod->file_first_fd = first_fd;
		curmod->file_last_fd = last_fd;
		return 0;
	}
}

int
file_mod_init()
{
	int rc;

	rc = curmod_init();
	if (rc == 0) {
		curmod->file_first_fd = FD_SETSIZE / 2;
		curmod->file_last_fd = 100000;
		sysctl_add(GT_SYSCTL_FILE_NOFILE, SYSCTL_WR, NULL,
		           NULL, sysctl_file_nofile); 
	}
	return rc;
}

void
file_mod_deinit()
{
	sysctl_del("file");
	curmod_deinit();
}

int
service_init_file(struct service *s)
{
	int rc, size, n;

	if (s->p_file_pool == NULL) {
		size = sizeof(struct sock) + sizeof(struct file_aio); // FIXME:!!!!!!
		n =  curmod->file_last_fd - curmod->file_first_fd + 1;
		assert(n > 0);
		rc = mbuf_pool_alloc(&s->p_file_pool, s->p_sid,
		                     "file.pool", size, n);
	} else {
		rc = 0;
	}
	return rc;
}

void
service_deinit_file(struct service *s)
{
	int tmp_fd;
	struct file *fp;

	if (s->p_file_pool != NULL) {
		FILE_FOREACH_SAFE3(s, fp, tmp_fd) {
			file_clean(fp);
		}
		mbuf_pool_free(s->p_file_pool);
		s->p_file_pool = NULL;
	}
}

int
file_get_fd(struct file *fp)
{
	int m_id;

	m_id = mbuf_get_id(&fp->fl_mbuf);
	return m_id + curmod->file_first_fd;
}

struct file *
file_next(struct service *s, int fd)
{
	int m_id;
	struct mbuf *m;
	struct file *fp;

	if (fd < curmod->file_first_fd) {
		m_id = 0;
	} else {
		m_id = fd - curmod->file_first_fd;
	}
	m = mbuf_next(s->p_file_pool, m_id);
	fp = (struct file *)m;
	return fp;
}

int
file_alloc3(struct file **fpp, int fd, int type)
{
	int rc, m_id;
	struct mbuf_pool *p;
	struct file *fp;

	p = current->p_file_pool;
	if (fd == 0) {
		rc = mbuf_alloc(p, (struct mbuf **)fpp);
	} else {
		assert(fd >= curmod->file_first_fd);
		m_id = fd - curmod->file_first_fd;
		rc = mbuf_alloc3(p, m_id, (struct mbuf **)fpp);
	}
	if (rc == 0) {
		fp = *fpp;
		file_init(fp, type);
		DBG(0, "ok; fp=%p, fd=%d", fp, file_get_fd(fp));
	} else {
		DBG(-rc, "failed;");
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
	if (fd < curmod->file_first_fd) {
		return -EBADF;
	}
	m_id = fd - curmod->file_first_fd;
	m = mbuf_get(current->p_file_pool, m_id);
	fp = (struct file *)m;
	if (fp == NULL) {
		return -EBADF;
	}
	if (fp->fl_referenced == 0) {
		return -EBADF;
	}
	*fpp = fp;
	return 0;
}

void
file_free(struct file *fp)
{
	DBG(0, "hit; fp=%p, fd=%d", fp, file_get_fd(fp));
	mbuf_free(&fp->fl_mbuf);
}

void
file_free_rcu(struct file *fp)
{
	DBG(0, "hit; fp=%p, fd=%d", fp, file_get_fd(fp));
	mbuf_free_rcu(&fp->fl_mbuf);
}

void
file_close(struct file *fp)
{
	file_wakeup(fp, POLLNVAL);
	fp->fl_referenced = 0;
	switch (fp->fl_type) {
	case FILE_SOCK:
		so_close((struct sock *)fp);
		break;
	case FILE_EPOLL:
		u_epoll_close(fp);
		break;
	default:
		assert(!"bad fl_type");
	}
}

void
file_clean(struct file *fp)
{
	fp->fl_referenced = 0; // dont call POLLNVAL
	file_close(fp);
}

int
file_fcntl(struct file *fp, int cmd, uintptr_t arg)
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
		rc = sock_nread(fp);
		if (rc < 0) {
			break;
		}
		*((int *)arg) = rc;
		break;
	default:
		rc = sock_ioctl(fp, request, arg);
		break;
	}
	return rc;
}

void
file_wakeup(struct file *fp, short revents)
{
	struct file_aio *aio, *tmp;

	assert(revents);
	DBG(0, "hit; fd=%d, revents=%s",
	    file_get_fd(fp), log_add_poll_events(revents));
	if (!fp->fl_referenced) {
		return;
	}
	DLIST_FOREACH_SAFE(aio, &fp->fl_aioq, faio_list, tmp) {
		assert(aio->faio_filter);
		file_aio_call(aio, revents);
	}
	assert((revents & POLLNVAL) == 0 || dlist_is_empty(&fp->fl_aioq));
}

void
file_wait(struct file *fp, short events)
{
	struct file_aio aio;

	mbuf_init(&aio.faio_mbuf, MBUF_AREA_NONE);
	file_aio_init(&aio);
	file_aio_set(fp, &aio, events, NULL);
	do {
		wait_for_fd_events();
	} while (aio.faio_revents == 0);
	file_aio_cancel(&aio);
}

short
file_get_events(struct file *fp, struct file_aio *aio)
{
	short revents;

	if (fp->fl_type == FILE_SOCK) {
		revents = so_get_events(fp);
	} else {
		revents = 0;
	}
	DBG(0, "hit; aio=%p, fd=%d, events=%s",
	    aio, file_get_fd(fp), log_add_poll_events(revents));
	return revents;
}

void
file_aio_init(struct file_aio *aio)
{
	aio->faio_filter = 0;
	aio->faio_revents = 0;
}

void
file_aio_set(struct file *fp, struct file_aio *aio, short events,
	file_aio_f fn)
{
	int fd;
	const char *action;
	short filter, revents;

	assert(fp->fl_type == FILE_SOCK);
	filter = events|POLLERR|POLLNVAL;
	if (aio->faio_filter == filter) {
		return;
	}
	fd = file_get_fd(fp);
	aio->faio_fd = fd;
	aio->faio_fn = fn;
	if (aio->faio_filter == 0) {
		DLIST_INSERT_HEAD(&fp->fl_aioq, aio, faio_list);
		action = "add";
	} else {
		action = "mod";
	}
	UNUSED(action);
	DBG(0, "%s; aio=%p, fd=%d, filter=%s",
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
	if (aio->faio_filter) {
		DBG(0, "hit; aio=%p, fd=%d, filter=%s",
		    aio, aio->faio_fd,
		    log_add_poll_events(aio->faio_filter));
		aio->faio_filter = 0;
		DLIST_REMOVE(aio, faio_list);
	}
	aio->faio_revents = 0;
}

int
file_first_fd()
{
	return curmod->file_first_fd;
}
