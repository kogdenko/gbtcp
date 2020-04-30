/* GPL2 license */
#ifndef GBTCP_PROC_H
#define GBTCP_PROC_H

#include "subr.h"

struct proc {
	struct spinlock p_lock;
	int p_pid;
	u_char p_rssq_id;
	char p_name[32];
};

extern struct proc *current;
uint64_t nanoseconds;

#endif /* GBTCP_PROC_H */
