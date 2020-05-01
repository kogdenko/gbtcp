/* GPL2 license */
#ifndef GBTCP_FILE_H
#define GBTCP_FILE_H

#include "mbuf.h"

struct file_aio;

enum file_type {
	FILE_OTHER,
	FILE_SOCK,
	FILE_EPOLL,
};

struct file {
	struct mbuf fl_mbuf;
	union {
		uint32_t fl_flags;
		struct {
			unsigned int fl_type : 3;
			unsigned int fl_opened : 1;
			unsigned int fl_blocked : 1;
		};
	};
	struct dlist fl_aioq;
};

typedef void (*file_aio_f)(struct file_aio *, int, short);

struct file_aio {
	struct mbuf faio_mbuf;
#define faio_list faio_mbuf.mb_list
	file_aio_f faio_fn;
	int faio_fd;
	short faio_filter;
};

#define FILE_FOREACH(fp) \
	for (int GT_UNIQV(fd) = 0; \
	     (fp = file_next(GT_UNIQV(fd))) != NULL; \
	     GT_UNIQV(fd) = file_get_fd(fp) + 1)

#define FILE_FOREACH_SAFE(fp, tmp_fd) \
	for (int GT_UNIQV(fd) = 0; \
	     ((fp = file_next(GT_UNIQV(fd))) != NULL) && \
	     ((tmp_fd = file_get_fd(fp) + 1), 1); \
	     GT_UNIQV(fd) = tmp_fd)

int file_mod_init(struct log *, void **);
int file_mod_attach(struct log *, void *);
void file_mod_deinit(struct log *, void *);
void file_mod_detach(struct log *);

struct file *file_next(int);
int file_alloc(struct log *, struct file **, int);
int file_alloc4(struct log *, struct file **, int, int);
void file_free(struct file *);
void file_close(struct file *, int);
int file_cntl(struct file *, int, uintptr_t);
int file_ioctl(struct file *, unsigned long, uintptr_t);
int file_get(int, struct file **);
int file_get_fd(struct file *);
short file_get_events(struct file *, struct file_aio *);
void file_wakeup(struct file *, short);
int file_wait(struct file *, short);
void file_aio_set(struct file *, struct file_aio *, short, file_aio_f);
void file_aio_cancel(struct file_aio *);
void file_aio_init(struct file_aio *);
int file_first_fd();

#endif /* GBTCP_FILE_H */
