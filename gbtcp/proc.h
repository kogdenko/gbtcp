// GPL2 license
#ifndef GBTCP_PROC_H
#define GBTCP_PROC_H

#include "subr.h"
#include "mbuf.h"
#include "route.h"

#define PROC_NAME_SIZE_MAX 32

#define PROC_TYPE_SERVICE 0
#define PROC_TYPE_CONTROLLER 1

#define SERVICE_LOCK do { \
	spinlock_lock(&current->p_lock); \
	rdtsc_update_time(); \
	if (current->p_dirty_devs) { \
		service_update_devs(NULL); \
	} \
} while (0)

#define SERVICE_UNLOCK \
	spinlock_unlock(&current->p_lock)

#define service_id() current->p_service_id

struct proc {
	struct spinlock p_lock;
	int p_pid;
	u_char p_service_id;
	u_char p_active;
	u_char p_dirty_devs;
	u_char p_rss_qid;
	u_char p_rss_qid_min;
	u_char p_rss_qid_max;
	int p_service_fd[2];
	struct mbuf_pool p_file_pool;
	struct mbuf_pool p_sockbuf_pool;
	struct mbuf_pool p_arp_entry_pool;
	struct mbuf_pool p_arp_incomplete_pool;
	char p_name[PROC_NAME_SIZE_MAX];
};

void proc_init();

int controller_init(int, const char *);
void controller_loop();

int service_init();
int service_activate(struct log *);
void service_deactivate(struct log *);
void service_update_devs(struct log *);

void rss_table_update();

extern struct proc *current;
extern int proc_type;
uint64_t nanoseconds;

#endif // GBTCP_PROC_H
