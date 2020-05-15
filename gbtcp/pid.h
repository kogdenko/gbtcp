/* GPL2 license */
#ifndef GBTCP_PID_H
#define GBTCP_PID_H

#include "gbtcp.h"

#define PID_WAIT_NONBLOCK IN_NONBLOCK

struct log;

struct pidfile {
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
	struct pid_wait_entry pw_entries[GT_PROC_COUNT_MAX];
};

int pid_mod_init(struct log *, void **);
int pid_mod_attach(struct log *, void *);
int pid_proc_init(struct log *, struct proc *);
void pid_mod_deinit(struct log *, void *);
void pid_mod_detach(struct log *);

char *pidfile_path(char *, const char *);
int pidfile_open(struct log *, struct pidfile *);
int pidfile_lock(struct log *, struct pidfile *);
int pidfile_read(struct log *, struct pidfile *);
int pidfile_write(struct log *, struct pidfile *, int);
void pidfile_close(struct log *, struct pidfile *);

int read_pidfile(struct log *, const char *);
int write_pidfile(struct log * , const char *, int);

int pid_wait_init(struct log *, struct pid_wait *, int);
void pid_wait_deinit(struct log *, struct pid_wait*);
int pid_wait_is_empty(struct pid_wait *);
int pid_wait_add(struct log *, struct pid_wait *, int);
int pid_wait_del(struct log *, struct pid_wait *, int);
int pid_wait_read(struct log *, struct pid_wait *, uint64_t *, int *, int);
int pid_wait_kill(struct log *, struct pid_wait *, int, int *, int);

#endif /* GBTCP_PID_H */
