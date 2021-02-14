// GPL v2
#ifndef GBTCP_SERVICE_H
#define GBTCP_SERVICE_H

// 457    3201

#include "subr.h"
#include "mod.h"
#include "mbuf.h"
#include "route.h"
#include "inet.h"
#include "itable.h"

#include "fd_event.h"

#define SERVICE_ID_INVALID GT_SERVICES_MAX

#define SERVICE_MSG_RX 0
#define SERVICE_MSG_TX 1
#define SERVICE_MSG_BYPASS 2

#define SERVICE_LOCK do { \
	spinlock_lock(&current_cpu->p_lock); \
} while (0)

#define SERVICE_UNLOCK \
	service_unlock()



#define CPU_LOCK(cpu) \
	if (cpu != current_cpu) \
		spinlock_lock(&cpu->p_lock);

#define CPU_UNLOCK(cpu) \
	if (cpu != current_cpu) \
		spinlock_unlock(&cpu->p_lock);


struct cpu {
	struct spinlock p_lock;
	struct dlist p_tx_head;	

	void *cpu_mem;

	u_char p_inited;
//	u_char p_sid;
	u_char p_need_update_rss_bindings;
	u_char p_rss_nq;
	u_char p_rr_redir;

	struct spinlock cpu_mem_cache_lock;
	struct mem_cache cpu_mem_cache[GLOBAL_BUDDY_ORDER_MIN - SLAB_ORDER_MIN];

	u_int mw_rcu_epoch;
	short mw_rcu_active;
	struct dlist mw_rcu_head[2];
	u_int mw_rcu[CPU_NUM];
	struct dlist mw_garbage;

	struct mem_buf *cpu_percpu_buf[PERCPU_BUF_NUM];
	

	struct timer_ring p_timer_rings[TIMER_N_RINGS];
	struct itable p_file_fd_table;
	struct tcp_stat p_tcps;
	struct udp_stat p_udps;
	struct ip_stat p_ips;
	struct icmp_stat p_icmps;
	struct arp_stat p_arps;
	int p_pid;
	int p_fd;
	uint64_t p_start_time;
};

struct process_percpu {
	struct dev ps_interface_dev[N_INTERFACES_MAX];
	struct fd_thread ps_fd_thread;
};



struct process {
	int ps_pid;
	struct dlist ps_list;
	struct process_percpu ps_percpu[CPU_NUM];
};

#define current_fd_thread &(current->ps_percpu[current_cpu_id].ps_fd_thread)

struct process *proc_add(int pid, int);
int proc_add_interface(struct process *, struct route_if *);

int service_pid_file_acquire(int, int);

int service_init_shared(struct cpu *, int, int);

int service_init_private();
//void service_deinit_private();

int attach_worker();

void service_detach();
void service_unlock();

//void service_update_rss_bindings();

int service_can_connect(struct route_if *, be32_t, be32_t, be16_t, be16_t);

int vale_not_empty_txr(struct route_if *, struct dev_pkt *, int);
void vale_transmit(struct route_if *, int, struct dev_pkt *);

int service_sigprocmask(int, const sigset_t *, sigset_t *);

int service_fork();

#ifdef __linux__
int service_clone(int (*)(void *), void *, int, void *,
	void *, void *, void *);
#endif // __linux__

int init_proc();

#endif // GBTCP_SERVICE_H
