/* GPL2 license */
#ifndef GBTCP_PID_H
#define GBTCP_PID_H

#include "gbtcp.h"

#define PIDWAIT_NONBLOCK IN_NONBLOCK
#define PIDWAIT_NENTRIES_MAX GT_SERVICE_COUNT_MAX 

struct log;

struct pidfile {
	int pf_fd;
	const char *pf_name;
};

struct pidwait_entry {
	int pid;
	int wd;
};
struct pidwait {
	int pw_fd;
	int pw_nentries;
	struct pidwait_entry pw_entries[GT_SERVICE_COUNT_MAX];
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

int pidwait_init(struct log *, struct pidwait *, int);
void pidwait_deinit(struct log *, struct pidwait*);
int pidwait_is_empty(struct pidwait *);
int pidwait_add(struct log *, struct pidwait *, int);
int pidwait_del(struct log *, struct pidwait *, int);
int pidwait_read(struct log *, struct pidwait *, uint64_t *, int *, int);
int pidwait_kill(struct log *, struct pidwait *, int, int *, int);

#endif /* GBTCP_PID_H */
