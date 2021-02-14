// GPL v2
#ifndef GBTCP_FILE_H
#define GBTCP_FILE_H

#include "mbuf.h"

struct file_aio;

enum file_type {
	FILE_SOCK,
	FILE_EPOLL,
};

struct file_aio {
	struct dlist faio_list;
	gt_aio_f faio_fn;
};

struct file {
	struct file_aio fl_aio;
	struct dlist fl_aio_head;
	int fl_fd;
	int fl_pid;
	u_char fl_type;
	u_char fl_referenced;
	u_char fl_blocked;
};

extern int file_sizeof;

int file_mod_init();

int init_files(struct cpu *);
void deinit_files(struct cpu *);

struct file *file_alloc3(int, int, int);
#define file_alloc(type, size) file_alloc3(0, type, size)
void file_free(struct file *);
void file_free_rcu(struct file *);
void file_close(struct file *);
int file_fcntl(struct file *, int, uintptr_t);
int file_ioctl(struct file *, unsigned long, uintptr_t);
int file_get(int, struct file **);
short file_get_events(struct file *);
void file_wakeup(struct file *, short);
void file_wait(struct file *, short);

#define file_aio_is_added(aio) ((aio)->faio_fn != NULL)
void file_aio_init(struct file_aio *);
void file_aio_add(struct file *, struct file_aio *, gt_aio_f);
void file_aio_cancel(struct file_aio *);

#endif // GBTCP_FILE_H
