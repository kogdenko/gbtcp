// GPL2 license
#ifndef GBTCP_PROC_H
#define GBTCP_PROC_H

#include "subr.h"
#include "mbuf.h"

#define PROC_SERVICE 0
#define PROC_CONTROLLER 1

#define PROC_NAME_SIZE_MAX 32

struct proc {
	struct spinlock p_lock;
	int p_pid;
	u_char p_rssq_id;
	char p_name[PROC_NAME_SIZE_MAX];
	struct mbuf_pool p_file_pool;
	struct mbuf_pool p_sockbuf_pool;
	struct mbuf_pool p_arp_entry_pool;
	struct mbuf_pool p_arp_pkt_pool;
};

int proc_controller_init(struct log *, int, const char *);
void proc_controller_loop();

extern struct proc *current;
uint64_t nanoseconds;

#endif // GBTCP_PROC_H
