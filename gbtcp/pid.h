// GPL2 License
#ifndef GBTCP_PID_H
#define GBTCP_PID_H

#include "subr.h"

#define PID_PATH GT_PREFIX"/pid"
#define PID_WAIT_NONBLOCK IN_NONBLOCK

struct pid_wait_entry {
	int pid;
	int wd;
};

struct pid_wait {
	int pw_fd;
	int pw_nentries;
	struct pid_wait_entry pw_entries[GT_SERVICES_MAX];
};

int pid_mod_init(void **);
int pid_mod_attach(void *);
void pid_mod_deinit(void *);
void pid_mod_detach();

char *pid_file_path(char *, const char *);
int pid_file_open(const char *);
int pid_file_lock(int);
int pid_file_read(int);
int pid_file_write(int, int);
int pid_file_acquire(int, int);

int pid_wait_init(struct pid_wait *, int);
void pid_wait_deinit(struct pid_wait*);
int pid_wait_is_empty(struct pid_wait *);
int pid_wait_add(struct pid_wait *, int);
int pid_wait_del(struct pid_wait *, int);
int pid_wait_read(struct pid_wait *, uint64_t *, int *, int);
int pid_wait_kill(struct pid_wait *, int, int *, int);

#endif // GBTCP_PID_H
