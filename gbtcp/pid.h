// GPL2 License
#ifndef GBTCP_PID_H
#define GBTCP_PID_H

#include "gbtcp.h"

#define PID_WAIT_NONBLOCK IN_NONBLOCK

struct log;

struct pid_file {
	int pf_fd;
	const char *pf_name;
};

struct pid_wait_entry {
	int pid;
	int wd;
};

struct pid_wait {
	int pw_fd;
	int pw_nentries;
	struct pid_wait_entry pw_entries[GT_SERVICE_COUNT_MAX];
};

int pid_mod_init(struct log *, void **);
int pid_mod_attach(struct log *, void *);
void pid_mod_deinit(struct log *, void *);
void pid_mod_detach(struct log *);

char *pid_file_path(char *, const char *);
int pid_file_open(struct log *, struct pid_file *);
int pid_file_lock(struct log *, struct pid_file *);
int pid_file_read(struct log *, struct pid_file *);
int pid_file_read_locked(struct log *, const char *);
int pid_file_write(struct log *, struct pid_file *, int);
int pid_file_acquire(struct log *, struct pid_file *, int);
void pid_file_close(struct log *, struct pid_file *);

int pid_wait_init(struct log *, struct pid_wait *, int);
void pid_wait_deinit(struct log *, struct pid_wait*);
int pid_wait_is_empty(struct pid_wait *);
int pid_wait_add(struct log *, struct pid_wait *, int);
int pid_wait_del(struct log *, struct pid_wait *, int);
int pid_wait_read(struct log *, struct pid_wait *, uint64_t *, int *, int);
int pid_wait_kill(struct log *, struct pid_wait *, int, int *, int);

#endif // GBTCP_PID_H
