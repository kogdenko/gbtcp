// SPDX-License-Identifier: LGPL-2.1-only

#include "epoll.h"
#include "fd_event.h"
#include "file.h"
#include "global.h"
#include "log.h"
#include "service.h"
#include "socket.h"

struct gt_module_file {
	struct log_scope log_scope;
	int file_nofile;
};

static void
file_init(struct file *fp, int type)
{
	fp->fl_type = type;
	fp->fl_referenced = 0;
	fp->fl_blocked = 1;
	fp->fl_sid = current->p_sid;
	file_aio_init(&fp->fl_aio);
	dlist_init(&fp->fl_aio_head);
}

static void
file_aio_call(struct file_aio *aio, int fd, short revents)
{
	(*aio->faio_fn)(aio, fd, revents);
}

int
file_mod_init(void)
{
	int rc;
	struct gt_module_file *m;

	rc = gt_module_init(GT_MODULE_FILE, sizeof(*m));
	if (rc == 0) {
		m = gt_module_get(GT_MODULE_FILE);
		m->file_nofile = upper_pow2_32(GT_FIRST_FD + 100000);
		sysctl_add_int(GT_SYSCTL_FILE_NOFILE, SYSCTL_WR, &m->file_nofile,
				GT_FIRST_FD + 1, 1 << 26);
	}
	return rc;
}

/*void
file_mod_deinit()
{
	sysctl_del("file");
	curmod_deinit();
}*/

int
init_files(struct service *s)
{
	int rc, size, n;
	struct gt_module_file *m;

	m = gt_module_get(GT_MODULE_FILE);
	if (s->p_file_pool == NULL) {
		size = gt_vso_struct_size();
		n = m->file_nofile - GT_FIRST_FD;
		assert(n > 0);
		rc = mbuf_pool_alloc(&s->p_file_pool, s->p_sid,	2 * 1024 * 1024, size, n);
	} else {
		rc = 0;
	}
	return rc;
}

void
deinit_files(struct service *s)
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
	int id;

	id = mbuf_get_id(&fp->fl_mbuf);
	return GT_FIRST_FD + id;
}

struct file *
file_next(struct service *s, int fd)
{
	int id;
	struct mbuf *m;
	struct file *fp;

	if (fd < GT_FIRST_FD) {
		id = 0;
	} else {
		id = fd - GT_FIRST_FD;
	}
	m = mbuf_next(s->p_file_pool, id);
	fp = (struct file *)m;
	return fp;
}

int
file_alloc3(struct file **fpp, int fd, int type)
{
	int rc, id;
	struct mbuf_pool *p;
	struct file *fp;

	p = current->p_file_pool;
	if (fd == 0) {
		rc = mbuf_alloc(p, (struct mbuf **)fpp);
	} else {
		assert(fd >= GT_FIRST_FD);
		id = fd - GT_FIRST_FD;
		rc = mbuf_alloc3(p, id, (struct mbuf **)fpp);
	}
	if (rc == 0) {
		fp = *fpp;
		file_init(fp, type);
	}
	return rc;
}

int
file_get(int fd, struct file **fpp)
{
	int id;
	struct mbuf *m;
	struct file *fp;

	*fpp = NULL;
	if (fd < GT_FIRST_FD) {
		return -EBADF;
	}
	id = fd - GT_FIRST_FD;
	m = mbuf_get(current->p_file_pool, id);
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
	mbuf_free(&fp->fl_mbuf);
}

void
file_free_rcu(struct file *fp)
{
	mbuf_free_rcu(&fp->fl_mbuf);
}

void
file_close(struct file *fp)
{
	if (fp->fl_referenced) {
		file_wakeup(fp, POLLNVAL);
		fp->fl_referenced = 0;
		switch (fp->fl_type) {
		case FILE_SOCK:
			gt_vso_close(fp);
			break;
		case FILE_EPOLL:
			u_epoll_close(fp);
			break;
		default:
			assert(!"Bad file type");
		}
	}
}

void
file_clean(struct file *fp)
{
	dlist_init(&fp->fl_aio_head);
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
		rc = gt_vso_nread(fp);
		if (rc < 0) {
			break;
		}
		*((int *)arg) = rc;
		break;
	default:
		rc = gt_vso_ioctl(fp, request, arg);
		break;
	}
	return rc;
}

void
file_wakeup(struct file *fp, short revents)
{
	int fd;
	struct file_aio *aio, *tmp;

	assert(revents);
	fd = file_get_fd(fp);
	DLIST_FOREACH_SAFE(aio, &fp->fl_aio_head, faio_list, tmp) {
		file_aio_call(aio, fd, revents);
	}
}

static short file_wait_filter;

static void
file_wait_handler(void *aio_ptr, int fd, short event)
{
	struct file_aio *aio;

	if (event & file_wait_filter) {
		aio = aio_ptr;
		file_aio_cancel(aio);
	}
}

void
file_wait(struct file *fp, short events)
{
	struct file_aio aio;

	mbuf_init(&aio.faio_mbuf, MBUF_AREA_NONE);
	file_wait_filter = events;
	file_aio_init(&aio);
	file_aio_add(fp, &aio, file_wait_handler);
	do {
		wait_for_fd_events();
	} while (aio.faio_fn != 0);
}

short
file_get_events(struct file *fp)
{
	short revents;

	if (fp->fl_type == FILE_SOCK) {
		revents = gt_vso_get_events(fp);
	} else {
		revents = 0;
	}
	return revents;
}

void
file_aio_init(struct file_aio *aio)
{
	aio->faio_fn = NULL;
}

void
file_aio_add(struct file *fp, struct file_aio *aio, gt_aio_f fn)
{
	int fd;
	short revents;

	assert(fn != NULL);
	assert(fp->fl_type == FILE_SOCK);
	if (!file_aio_is_added(aio)) {
		fd = file_get_fd(fp);
		aio->faio_fn = fn;
		DLIST_INSERT_HEAD(&fp->fl_aio_head, aio, faio_list);
		revents = file_get_events(fp);
		if (revents) {
			file_aio_call(aio, fd, revents);
		}
	}
}

void
file_aio_cancel(struct file_aio *aio)
{
	if (file_aio_is_added(aio)) {
		aio->faio_fn = NULL;
		DLIST_REMOVE(aio, faio_list);
	}
}
