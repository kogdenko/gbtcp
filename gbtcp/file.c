// GPL v2
#include "internals.h"

#define CURMOD file

struct file_mod {
	struct log_scope log_scope;
	int file_nofile;
};

static void
file_init(struct file *fp, int fd, int type)
{
	fp->fl_fd = fd;
	fp->fl_type = type;
	fp->fl_referenced = 0;
	fp->fl_blocked = 1;
	fp->fl_pid = current->ps_pid;
	file_aio_init(&fp->fl_aio);
	dlist_init(&fp->fl_aio_head);
}

static void
file_aio_call(struct file_aio *aio, int fd, short revents)
{
	DBG(0, "call aio; aio=%p, fd=%d, events=%s",
		aio, fd, log_add_poll_events(revents));
	(*aio->faio_fn)(aio, fd, revents);
}

int
file_mod_init()
{
	int rc;

	rc = curmod_init();
	if (rc) {
		return rc;
	}
	curmod->file_nofile = upper_pow2_32(GT_FIRST_FD + 100000);
	sysctl_add_int(GT_SYSCTL_FILE_NOFILE, SYSCTL_WR,
		&curmod->file_nofile, GT_FIRST_FD + 1, 1 << 26);
	return 0;
}

void
file_mod_deinit()
{
	curmod_deinit();
}

int
init_files(struct service *s)
{
	itable_init(&s->p_file_fd_table, sizeof(struct file *));
	return 0;
}

void
deinit_files(struct service *s)
{
//	int tmp_fd;
//	struct file *fp;

	itable_deinit(&s->p_file_fd_table);
		// TODO:
		//FILE_FOREACH_SAFE3(s, fp, tmp_fd) {
		//	file_clean(fp);
		//}
}

struct file *
file_alloc3(int fd, int type, int size)
{
	int rc;
	struct file *fp;

	if (fd == 0) {
		fp = mem_alloc(size);
	} else {
		assert(0);
		fp = NULL;
//		assert(fd >= GT_FIRST_FD);
//		id = fd - GT_FIRST_FD;
//		rc = mbuf_alloc3(p, id, (struct mbuf **)fpp);
	}
	if (fp != NULL) {
		rc = itable_alloc(&current_cpu->p_file_fd_table, &fp);
		if (rc < 0) {
			mem_free(fp);
		} else {
			file_init(fp, GT_FIRST_FD + rc, type);
			rc = 0;
		}
	}
	if (rc < 0) {
		DBG(-rc, "file alloc failed;");
	} else {
		DBG(0, "file alloc; fp=%p, fd=%d", fp, fp->fl_fd);
	}
	return fp;
}

int
file_get(int fd, struct file **fpp)
{
	void *ptr;
	struct file *fp;

	*fpp = NULL;
	if (fd < GT_FIRST_FD) {
		return -EBADF;
	}
	ptr = itable_get(&current_cpu->p_file_fd_table, fd - GT_FIRST_FD);
	if (ptr == NULL) {
		return -EBADF;
	}
	fp = *(struct file **)ptr;
	if (fp->fl_referenced == 0) {
		return -EBADF;
	}
	*fpp = fp;
	return 0;
}

void
file_free(struct file *fp)
{
	DBG(0, "file free; fp=%p, fd=%d", fp, fp->fl_fd);
	itable_free(&current_cpu->p_file_fd_table, fp->fl_fd - GT_FIRST_FD);
	mem_free(fp);
}

void
file_close(struct file *fp)
{
	if (fp->fl_referenced) {
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
}

/*static void
file_clean(struct file *fp)
{
	dlist_init(&fp->fl_aio_head);
	file_close(fp);
}*/

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
	DBG(0, "file wakeup; fd=%d, revents=%s", fp->fl_fd,
		log_add_poll_events(revents));
	DLIST_FOREACH_SAFE(aio, &fp->fl_aio_head, faio_list, tmp) {
		file_aio_call(aio, fp->fl_fd, revents);
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

	file_wait_filter = events;
	file_aio_init(&aio);
	file_aio_add(fp, &aio, file_wait_handler);
	do {
		fd_thread_wait(current_fd_thread);
	} while (aio.faio_fn != 0);
}

short
file_get_events(struct file *fp)
{
	short revents;

	if (fp->fl_type == FILE_SOCK) {
		revents = so_get_events(fp);
	} else {
		revents = 0;
	}
	DBG(0, "get file events; events=%s", log_add_poll_events(revents));
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
	short revents;

	assert(fn != NULL);
	assert(fp->fl_type == FILE_SOCK);
	if (!file_aio_is_added(aio)) {
		aio->faio_fn = fn;
		DLIST_INSERT_HEAD(&fp->fl_aio_head, aio, faio_list);
		DBG(0, "add file aio; aio=%p, fd=%d", aio, fp->fl_fd);
		revents = file_get_events(fp);
		if (revents) {
			file_aio_call(aio, fp->fl_fd, revents);
		}
	}
}

void
file_aio_cancel(struct file_aio *aio)
{
	if (file_aio_is_added(aio)) {
		DBG(0, "cancel file aio; aio=%p", aio);
		aio->faio_fn = NULL;
		DLIST_REMOVE(aio, faio_list);
	}
}
