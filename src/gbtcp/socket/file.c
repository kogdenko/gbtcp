// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/socket/epoll.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/socket/file.h>
#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/socket/socket.h>
#include <gbtcp/kernel/worker.h>

static void
file_init(struct gt_file *fp, int type)
{
	fp->fl_type = type;
	fp->fl_referenced = 0;
	fp->fl_blocked = 1;
	fp->fl_worker_index = current->p_sid;
	file_aio_init(&fp->fl_aio);
	gt_dlist_init(&fp->fl_aio_head);
}

static void
file_aio_call(struct file_aio *aio, int fd, short revents)
{
	(*aio->faio_fn)(aio, fd, revents);
}

int
init_files(struct gt_socket_worker *w)
{
	int size;

	//n = m->file_nofile - GT_FIRST_FD;
	w->sow_file_max =
		gt_roundup_pow2_32(GT_FIRST_FD + 100000) - GT_FIRST_FD;
	assert(w->sow_file_max > 0);
	w->sow_file_cur = 0;

	gt_dlist_init(&w->sow_file_head);

	size = sizeof(struct gt_file *) * w->sow_file_max;
	w->sow_file_table = gt_malloc(shm_cache(), size, 0);
	if (w->sow_file_table == NULL) {
		return -ENOMEM;
	}
	memset(w->sow_file_table, 0, size);

	return 0;
}

void
deinit_files(struct service *s)
{
	int id;
	u8 worker_index;
	struct gt_file *fp;
	struct gt_socket_worker *wrk;

	worker_index = s->p_sid;
	wrk = gt_so_main->so_workers + worker_index;

	if (wrk->sow_file_table != NULL) {
		GT_FILE_FOREACH(worker_index, fp) {
			gt_dlist_init(&fp->fl_aio_head);
			file_close(fp);
		}

		// Free cached (closed) files...
		while (!gt_dlist_is_empty(&wrk->sow_file_head)) {
			fp = GT_DLIST_FIRST(&wrk->sow_file_head, struct gt_file,
					    fl_link);
			GT_DLIST_REMOVE(fp, fl_link);
			gt_free_internal(shm_cache(), fp);
		}

		// ...and any files still referenced by the table.
		for (id = 0; id < wrk->sow_file_max; ++id) {
			fp = wrk->sow_file_table[id];
			if (fp != NULL) {
				wrk->sow_file_table[id] = NULL;
				gt_free_internal(shm_cache(), fp);
			}
		}

		gt_free_internal(shm_cache(), wrk->sow_file_table);
		wrk->sow_file_table = NULL;
	}
}

int
file_get_fd(struct gt_file *fp)
{
	return fp->fl_fd;
}

struct gt_file *
file_next(u8 worker_index, int fd)
{
	int id;
	struct gt_file *fp;
	struct gt_socket_worker *w;

	if (fd < GT_FIRST_FD) {
		id = 0;
	} else {
		id = fd - GT_FIRST_FD;
	}

	w = gt_so_main->so_workers + worker_index;
	for (; id < w->sow_file_max; ++id) {
		fp = w->sow_file_table[id];
		if (fp != NULL) {
			return fp;
		}
	}

	return NULL;
}

int
file_alloc3(struct gt_file **fpp, int fd, int type)
{
	int id;
	struct gt_file *fp;
	struct gt_socket_worker *w;

	w = gt_so_main->so_workers + gt_get_worker_index();

	if (fd == 0) {
		if (gt_dlist_is_empty(&w->sow_file_head)) {
			while (1) {
				if (w->sow_file_cur == w->sow_file_max) {
					return -ENFILE;
				}
				fp = w->sow_file_table[w->sow_file_cur];
				if (fp == NULL) {
					break;
				}
				w->sow_file_cur++;
			}

			fp = gt_malloc(shm_cache(), gt_so_struct_size(),
				       GT_MF_ZERO);
			if (fp == NULL) {
				return -ENOMEM;
			}
			fp->fl_fd = GT_FIRST_FD + w->sow_file_cur;
			w->sow_file_cur++;
		} else {
			fp = GT_DLIST_FIRST(&w->sow_file_head, struct gt_file,
					    fl_link);
			GT_DLIST_REMOVE(fp, fl_link);
		}
	} else {
		if (fd < GT_FIRST_FD) {
			return -EBADF;
		}

		id = fd - GT_FIRST_FD;
		if (id >= w->sow_file_max) {
			return -EBADF;
		}

		fp = w->sow_file_table[id];
		if (fp != NULL) {
			if (!fp->fl_freed) {
				return -EBUSY;
			}
		} else {
			fp = gt_malloc(shm_cache(), gt_so_struct_size(),
				       GT_MF_ZERO);
			if (fp == NULL) {
				return -ENOMEM;
			}
			fp->fl_fd = fd;
		}
	}

	*fpp = fp;
	file_init(fp, type);
	fp->fl_freed = 0;
	id = fp->fl_fd - GT_FIRST_FD;
	assert(w->sow_file_table[id] == NULL);
	w->sow_file_table[id] = fp;

	return 0;
}

int
file_get(int fd, struct gt_file **fpp)
{
	int id;
	struct gt_file *fp;
	struct gt_socket_worker *w;

	*fpp = NULL;
	if (fd < GT_FIRST_FD) {
		return -EBADF;
	}
	id = fd - GT_FIRST_FD;

	w = gt_so_main->so_workers + gt_get_worker_index();
	if (id >= w->sow_file_max) {
		return -EBADF;
	}

	fp = w->sow_file_table[id];
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
file_free(struct gt_file *fp)
{
	struct gt_socket_worker *w;

	w = gt_so_main->so_workers + fp->fl_worker_index;
	w->sow_file_table[fp->fl_fd - GT_FIRST_FD] = NULL;
	GT_DLIST_INSERT_TAIL(&w->sow_file_head, fp, fl_link);
	fp->fl_freed = 1;
}

void
file_open(struct gt_file *fp)
{
	fp->fl_referenced = 1;
}

void
file_close(struct gt_file *fp)
{
	if (fp->fl_referenced) {
		file_wakeup(fp, POLLNVAL);
		fp->fl_referenced = 0;
		switch (fp->fl_type) {
		case FILE_SOCK:
			gt_so_close(fp);
			break;

		case FILE_EPOLL:
			u_epoll_close(fp);
			break;

		default:
			GT_BUG0;
			break;
		}
	}
}

int
file_fcntl(struct gt_file *fp, int cmd, uintptr_t arg)
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
		if (flags & ~(O_RDWR | O_NONBLOCK)) {
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
file_ioctl(struct gt_file *fp, unsigned long request, uintptr_t arg)
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
		rc = gt_so_nread(fp);
		if (rc < 0) {
			break;
		}
		*((int *)arg) = rc;
		break;
	default:
		rc = gt_so_ioctl(fp, request, arg);
		break;
	}
	return rc;
}

void
file_wakeup(struct gt_file *fp, short revents)
{
	int fd;
	struct file_aio *aio, *tmp;

	assert(revents);
	fd = file_get_fd(fp);
	GT_DLIST_FOREACH_SAFE(aio, &fp->fl_aio_head, faio_list, tmp) {
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
file_wait(struct gt_file *fp, short events)
{
	struct file_aio aio;

	file_wait_filter = events;
	file_aio_init(&aio);
	file_aio_add(fp, &aio, file_wait_handler);
	do {
		wait_for_fd_events();
	} while (aio.faio_fn != 0);
}

short
file_get_events(struct gt_file *fp)
{
	short revents;

	if (fp->fl_type == FILE_SOCK) {
		revents = gt_so_get_events(fp);
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
file_aio_add(struct gt_file *fp, struct file_aio *aio, gt_aio_f fn)
{
	int fd;
	short revents;

	assert(fn != NULL);
	assert(fp->fl_type == FILE_SOCK);
	if (!file_aio_is_added(aio)) {
		fd = file_get_fd(fp);
		aio->faio_fn = fn;
		GT_DLIST_INSERT_HEAD(&fp->fl_aio_head, aio, faio_list);
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
		GT_DLIST_REMOVE(aio, faio_list);
	}
}
