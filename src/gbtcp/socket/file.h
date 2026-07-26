// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_FILE_H
#define GBTCP_FILE_H

#include <gbtcp/kernel/list.h>

struct file_aio;
struct service;

enum file_type {
	FILE_SOCK,
	FILE_EPOLL,
};

struct file_aio {
	struct gt_dlist faio_list;
	gt_aio_f faio_fn;
};

struct gt_file {
	struct gt_dlist fl_link;
	struct file_aio fl_aio;
	struct gt_dlist fl_aio_head;
	int fl_fd;
	u_char fl_type;
	u8 fl_freed;
	u8 fl_referenced;
	u8 fl_blocked;
	u8 fl_worker_index;
};

#define GT_FILE_FOREACH(worker_index, fp) \
	for (int fd = 0; (fp = file_next(worker_index, fd)) != NULL; \
	     fd = file_get_fd(fp) + 1)

struct gt_socket_worker;

int init_files(struct gt_socket_worker *w);
void deinit_files(struct service *);

struct gt_file *file_next(u8 worker_index, int);
int file_alloc3(struct gt_file **, int, int);
#define file_alloc(fpp, type) file_alloc3(fpp, 0, type)
void file_free(struct gt_file *);
void file_open(struct gt_file *);
void file_close(struct gt_file *);
int file_fcntl(struct gt_file *, int, uintptr_t);
int file_ioctl(struct gt_file *, unsigned long, uintptr_t);
int file_get(int, struct gt_file **);
int file_get_fd(struct gt_file *);
short file_get_events(struct gt_file *);
void file_wakeup(struct gt_file *, short);
void file_wait(struct gt_file *, short);
#define file_aio_is_added(aio) ((aio)->faio_fn != NULL)
void file_aio_init(struct file_aio *);
void file_aio_add(struct gt_file *, struct file_aio *, gt_aio_f);
void file_aio_cancel(struct file_aio *);

#endif // GBTCP_FILE_H
