// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_FILE_H
#define GBTCP_FILE_H

#include "mbuf.h"

struct file_aio;
struct service;

enum file_type {
	FILE_SOCK,
	FILE_EPOLL,
};

struct file_aio {
	struct mbuf faio_mbuf;
#define faio_list faio_mbuf.mb_list
	gt_aio_f faio_fn;
};

struct file {
	struct mbuf fl_mbuf;
	struct file_aio fl_aio;
	struct gt_dlist fl_aio_head;
	u_char fl_type;
	u_char fl_referenced;
	u_char fl_blocked;
	u_char fl_sid;
};

#define FILE_FOREACH2(s, fp) \
	for (int GT_UNIQ_VAR(fd) = 0; \
			(fp = file_next(s, GT_UNIQ_VAR(fd))) != NULL; \
			GT_UNIQ_VAR(fd) = file_get_fd(fp) + 1)

#define FILE_FOREACH_SAFE3(s, fp, tmp_fd) \
	for (int GT_UNIQ_VAR(fd) = 0; \
			((fp = file_next(s, GT_UNIQ_VAR(fd))) != NULL) && \
			((tmp_fd = file_get_fd(fp) + 1), 1); \
			GT_UNIQ_VAR(fd) = tmp_fd)

int file_mod_init(void);

int init_files(struct service *);
void deinit_files(struct service *);

struct file *file_next(struct service *, int);
int file_alloc3(struct file **, int, int);
#define file_alloc(fpp, type) file_alloc3(fpp, 0, type)
void file_free(struct file *);
void file_free_rcu(struct file *);
void file_open(struct file *);
void file_close(struct file *);
int file_fcntl(struct file *, int, uintptr_t);
int file_ioctl(struct file *, unsigned long, uintptr_t);
int file_get(int, struct file **);
int file_get_fd(struct file *);
short file_get_events(struct file *);
void file_wakeup(struct file *, short);
void file_wait(struct file *, short);
#define file_aio_is_added(aio) ((aio)->faio_fn != NULL)
void file_aio_init(struct file_aio *);
void file_aio_add(struct file *, struct file_aio *, gt_aio_f);
void file_aio_cancel(struct file_aio *);

#endif // GBTCP_FILE_H
