// GPL v2
#ifndef GBTCP_SERVICE_H
#define GBTCP_SERVICE_H

#include "subr.h"
#include "mod.h"
#include "mbuf.h"
#include "route.h"
#include "inet.h"
#include "itable.h"

#ifdef __linux__
#define GT_COMMLEN 32
#elif __FreeBSD__
#define GT_COMMLEN COMMLEN
#else
#error "Unsupported platform"
#endif

#define SERVICE_ID_INVALID GT_SERVICES_MAX

#define SERVICE_MSG_RX 0
#define SERVICE_MSG_TX 1
#define SERVICE_MSG_BYPASS 2

#define SERVICE_LOCK do { \
	spinlock_lock(&current->p_lock); \
	rd_nanoseconds(); \
	if (current->p_need_update_rss_bindings) { \
		service_update_rss_bindings(); \
	} \
} while (0)

#define SERVICE_UNLOCK \
	service_unlock()

#define SERVICE_FOREACH(s) \
	for ((s) = shared->shm_services; \
	     (s) != shared->shm_services + ARRAY_SIZE(shared->shm_services); \
	     (s)++)

struct service {
	struct spinlock p_lock;
	struct dlist p_tx_head;	
	u_char p_inited;
	u_char p_sid;
	u_char p_need_update_rss_bindings;
	u_char p_rss_nq;
	u_char p_rr_redir;

	struct mem_cache mw_slab[BUDDY_ORDER_MIN - SLAB_ORDER_MIN];
	u_int mw_rcu_epoch;
	short mw_rcu_max;
	short mw_rcu_active;
	struct dlist mw_rcu_head[2];
	u_int mw_rcu[GT_SERVICES_MAX];
	struct dlist mw_garbage;

	struct timer_ring *p_timer_rings[TIMER_N_RINGS];
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

int service_pid_file_acquire(int, int);

struct service *worker_get(u_int);

int service_init_shared(struct service *, int, int);
void service_deinit_shared(struct service *, int);

int service_init_private();
void service_deinit_private();

int service_attach(const char *);
void service_detach();
void service_unlock();

void service_update_rss_bindings();

int service_can_connect(struct route_if *, be32_t, be32_t, be16_t, be16_t);

int vale_not_empty_txr(struct route_if *, struct dev_pkt *, int);
void vale_transmit(struct route_if *, int, struct dev_pkt *);

int service_sigprocmask(int, const sigset_t *, sigset_t *);

int service_fork();

#ifdef __linux__
int service_clone(int (*)(void *), void *, int, void *,
	void *, void *, void *);
#endif // __linux__

#endif // GBTCP_SERVICE_H
