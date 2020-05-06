// GPL2 license
#ifndef GBTCP_PROC_H
#define GBTCP_PROC_H

#include "subr.h"
#include "mbuf.h"
#include "route.h"

#define PROC_NAME_SIZE_MAX 32

#define SERVICE_LOCK do { \
	spinlock_lock(&current->p_lock); \
	rdtsc_update_time(); \
	if (current->p_rss_qid != current->p_rss_qid_saved) { \
		route_set_rss_qid(NULL); \
	} \
} while (0)

#define SERVICE_UNLOCK \
	spinlock_unlock(&current->p_lock)

#define service_id() current->p_service_id

struct proc {
	struct spinlock p_lock;
	int p_pid;
	u_char p_service_id;
	int p_rss_qid;
	int p_rss_qid_saved;
	u_char p_active;
	u_int p_init_id;
	struct mbuf_pool p_file_pool;
	struct mbuf_pool p_sockbuf_pool;
	struct mbuf_pool p_arp_entry_pool;
	struct mbuf_pool p_arp_pkt_pool;
	char p_name[PROC_NAME_SIZE_MAX];
};

void proc_init();

int controller_init(int, const char *);
void controller_loop();
void controller_set_rss_nq(struct log *, int);

int service_init();
int service_activate(struct log *);

int get_rss_nq();

extern struct proc *current;
extern struct proc *services;
uint64_t nanoseconds;

#endif // GBTCP_PROC_H
