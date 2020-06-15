// gpl2 license
#ifndef GBTCP_FILE_H
#define GBTCP_FILE_H

#include "mbuf.h"

struct file_aio;

enum file_type {
	FILE_OTHER,
	FILE_SOCK,
	FILE_EPOLL,
};

typedef void (*file_aio_f)(struct file_aio *, int, short);

struct file_aio {
	struct mbuf faio_mbuf;
#define faio_list faio_mbuf.mb_list
	file_aio_f faio_fn;
	int faio_fd;
	short faio_filter;
	short faio_revents;
};

struct file {
	struct mbuf fl_mbuf;
	union {
		uint32_t fl_flags;
		struct {
			u_int fl_type : 3;
			u_int fl_referenced : 1;
			u_int fl_blocked : 1;
			u_int fl_sid : 8;
		};
	};
	struct dlist fl_aioq;
};

#define FILE_FOREACH2(s, fp) \
	for (int UNIQV(fd) = 0; \
	     (fp = file_next(s, UNIQV(fd))) != NULL; \
	     UNIQV(fd) = file_get_fd(fp) + 1)

#define FILE_FOREACH_SAFE3(s, fp, tmp_fd) \
	for (int UNIQV(fd) = 0; \
	     ((fp = file_next(s, UNIQV(fd))) != NULL) && \
	     ((tmp_fd = file_get_fd(fp) + 1), 1); \
	     UNIQV(fd) = tmp_fd)

extern int file_sizeof;

int file_mod_init();
int file_mod_service_init(struct service *);
void file_mod_deinit();
void file_mod_service_deinit(struct service *);

struct file *file_next(struct service *, int);
int file_alloc3(struct file **, int, int);
#define file_alloc(fpp, type) file_alloc3(fpp, 0, type)
void file_free(struct file *);
void file_free_rcu(struct file *);
void file_close(struct file *);
void file_clean(struct file *);
int file_fcntl(struct file *, int, uintptr_t);
int file_ioctl(struct file *, unsigned long, uintptr_t);
int file_get(int, struct file **);
int file_get_fd(struct file *);
short file_get_events(struct file *, struct file_aio *);
void file_wakeup(struct file *, short);
void file_wait(struct file *, short);
void file_aio_set(struct file *, struct file_aio *, short, file_aio_f);
void file_aio_cancel(struct file_aio *);
void file_aio_init(struct file_aio *);
int file_first_fd();

#endif /* GBTCP_FILE_H */
