#ifndef GBTCP_FILE_H
#define GBTCP_FILE_H

#include "mbuf.h"

struct gt_file_cb;

enum gt_file_type {
	GT_FILE_OTHER,
	GT_FILE_SOCK,
	GT_FILE_EPOLL,
};

struct gt_file {
	struct gt_mbuf fl_mbuf;
	union {
		uint32_t fl_flags;
		struct {
			unsigned int fl_type : 3;
			unsigned int fl_opened : 1;
			unsigned int fl_blocked : 1;
		};
	};
	struct dllist fl_cbq;
};

typedef void (*gt_file_cb_f)(struct gt_file_cb *cb, int fd, short revents);

struct gt_file_cb {
	struct gt_mbuf fcb_mbuf;
	gt_file_cb_f fcb_fn;
	int fcb_fd;
	short fcb_filter;
};

#define GT_FILE_FOREACH(fp) \
	for (int GT_UNIQV(fd) = 0; \
	     (fp = gt_file_next(GT_UNIQV(fd))) != NULL; \
	     GT_UNIQV(fd) = gt_file_get_fd(fp) + 1)

#define GT_FILE_FOREACH_SAFE(fp, tmp_fd) \
	for (int GT_UNIQV(fd) = 0; \
	     ((fp = gt_file_next(GT_UNIQV(fd))) != NULL) && \
	     ((tmp_fd = gt_file_get_fd(fp) + 1), 1); \
	     GT_UNIQV(fd) = tmp_fd)

int gt_file_mod_init();

void gt_file_mod_deinit();

struct gt_file *gt_file_next(int fd);

int gt_file_alloc(struct gt_log *log, struct gt_file **fpp, int type);

int gt_file_alloc4(struct gt_log *log, struct gt_file **fpp, int type, int fd);

void gt_file_free(struct gt_file *fp);

void gt_file_close(struct gt_file *fp, int how);

int gt_file_cntl(struct gt_file *fp, int cmd, uintptr_t arg);

int gt_file_ioctl(struct gt_file *fp, unsigned long request, uintptr_t arg);

int gt_file_get(int fd, struct gt_file **fpp);

int gt_file_get_fd(struct gt_file *fp);

short gt_file_get_events(struct gt_file *fp, struct gt_file_cb *cb);

void gt_file_wakeup(struct gt_file *fp, short revents);

int gt_file_wait(struct gt_file *fp, short events);

void gt_file_cb_set(struct gt_file *fp, struct gt_file_cb *cb,
	short filter, gt_file_cb_f fn);

void gt_file_cb_cancel(struct gt_file_cb *cb);

void gt_file_cb_init(struct gt_file_cb *cb);

int gt_file_try_fd(int fd);

#endif /* GBTCP_FILE_H */
