// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_WORKER_H
#define GBTCP_WORKER_H

#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/inet.h>
#include <gbtcp/kernel/mm.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/route.h>
#include <gbtcp/kernel/subr.h>

#define SERVICE_COMM_MAX 32
#define SERVICE_ID_INVALID GT_SERVICES_MAX

#define SERVICE_MSG_RX 0
#define SERVICE_MSG_TX 1
#define SERVICE_MSG_BYPASS 2

#define SERVICE_UNLOCK service_unlock()

#define tcpstat current->p_tcpstat
#define udpstat current->p_udpstat
#define ipstat current->p_ipstat
#define icmpstat current->p_icmpstat
#define arpstat current->p_arpstat

// Process-wide worker state, guarded by pc_lock. Multiple
// service-threads share one process: the heavy process-once setup (gt_init,
// signal handlers, the single shm mapping) is done by the first thread to
// attach and torn down by the last to detach. pc_n_workers counts the
// attached service-threads in this process.
struct gt_process {
	struct spinlock pc_lock;
	int pc_inited;
	int pc_n_workers;

#if GT_HAVE_BFD
	struct gt_dlist pc_bfd_head;
#endif
};

extern struct gt_process gt_current_process;

struct gt_thread {
	u64 trd_tsc_nsec;
	u64 trd_tsc_tick;

	sigset_t trd_sigprocmask;

	// The service this thread is currently bound to (NULL before slot claim).
	struct service *trd_current;

	// Cache-backed allocator handed to api/cli code via gt_get_allocator();
	// bound to trd_current->p_mm_cache when the slot is claimed
	// (service_attach()). Thread-local, not shm-resident: its function
	// pointers are only valid in this process, unlike the shm-resident
	// cache data they dispatch into (every process attaching a service
	// independently dlopens/links this library, so a code pointer set by
	// one process's shm_init() is not a valid address in another's).
	struct gt_kallocator trd_kallocator;

	// Connection to the controller, owned by this worker thread. NULL only
	// in the controller thread itself: its own service is added by a
	// direct call (gt_worker_attach()), not over the API. Sibling threads
	// of the controller process connect like remote workers.
	struct gt_api_conn *trd_worker_conn;

	u64 trd_fd_event_drain_time;
	u64 trd_fd_event_timeout;
	int trd_fd_event_n_used;
	int trd_fd_poll_is_waiting;
	struct fd_event *trd_fd_event_used[FD_SETSIZE];
	struct fd_event trd_fd_event_buf[FD_SETSIZE];
};

extern __thread struct gt_thread gt_current_thread;

#define nanoseconds gt_current_thread.trd_tsc_nsec
#define ticks gt_current_thread.trd_tsc_tick
#define current gt_current_thread.trd_current
#define gt_worker_conn gt_current_thread.trd_worker_conn

struct service {
	u_char p_inited;
	u_char p_sid;
	// Controller-private (controller thread only): a worker_update RPC
	// should be sent to this worker. Set instead of executing the RPC in
	// place because rss rebinding happens inside conn handlers (worker_add,
	// conn close) — an exec there can nest on the conn being processed or
	// collide with an exec already in flight. The controller's main loop
	// (controller_process) drains the flags, one sync exec at a time.
	u_char p_ctl_pending_update;
	// Worker-private (owning thread only): a worker_update RPC arrived
	// before this worker's own service_attach() had run
	// gt_worker_module_sync() (see gt_worker_update_api_handler and the
	// pickup in service_attach()), so the rss rebind it asked for was
	// deferred instead of run against not-yet-loaded modules.
	u_char p_worker_update_pending;
	u_char p_rss_nq;
	u_char p_rr_redir;
	u_int p_epoch;
	u_int p_okpps;
	uint64_t p_okpps_time;
	uint64_t p_opkts;
	struct gt_timer_wheel wrk_timer_wheel;

	struct tcp_stat p_tcpstat;
	struct udp_stat p_udpstat;
	struct ip_stat p_ipstat;
	struct icmp_stat p_icmpstat;
	struct arp_stat p_arpstat;

	int p_pid;
	int p_tid;
	struct gt_api_conn *wrk_conn;
	uint64_t p_start_time;
	struct gt_dlist p_dev_head;

	// Per-worker RCU deferred-free state (used by the owning worker only).
	int p_rcu_max;
	struct gt_dlist p_rcu_active_head;
	struct gt_dlist p_rcu_shadow_head;
	u_int p_rcu[GT_SERVICES_MAX];

	// Cache backing this service's allocations. Data only (heap indices/
	// counters) — safe to share as-is; see gt_thread.trd_kallocator for
	// why the allocator built on top of it is thread-local instead.
	struct gt_mcache p_mm_cache;

	struct dev wrk_handoff;
#if !GT_HAVE_VALE
	struct dev wrk_handoff_peer;
#endif

	struct gt_worker_module worker_modules_buf[GT_MODULE_MAX];
	// Loaded worker modules, in load order; see struct gt_worker_module.wmod_list.
	struct gt_dlist worker_module_head;
	int n_worker_modules;
};

// The controller thread's own service. Process-local: non-NULL only in the
// controller process (there is no reserved sid — the controller claims its
// slot like any worker).
extern struct service *gt_controller_service;

#define service_load_epoch(s) \
	({ \
		u_int epoch; \
		__atomic_load(&(s)->p_epoch, &epoch, __ATOMIC_SEQ_CST); \
		epoch; \
	})

#define service_store_epoch(s, epoch) \
	({ \
		u_int tmp = epoch; \
		__atomic_store(&(s)->p_epoch, &tmp, __ATOMIC_SEQ_CST); \
	})

struct service *service_get_by_sid(u_int);

// Defer-free an object after an RCU grace period. The gt_dlist node must be the
// first field of the object.
void gt_free_rcu(struct gt_dlist *node);

int gt_kernel_module_worker_init(struct service *s, int pid, int tid,
				 struct gt_api_conn *cp);
void gt_kernel_module_worker_deinit(u8);

int service_attach(void);
// Process-local setup for a utility tool (gbtcpctl, gbtcp-netstat). A utility
// is not a worker: it claims no service slot and does not touch shared memory
// at all — while current == NULL the ambient allocator (gt_get_allocator()) backs
// api/cli/protobuf allocations with sys_malloc.
int gt_utility_init(void);
void service_detach(void);
void service_unlock(void);

void service_account_opkt(void);

void service_update_rss_bindings(void);

#define gt_get_worker_index() current->p_sid

u8 gt_worker_rss_is_symmetric(struct route_if *ifp, be32_t laddr, be32_t faddr,
			      be16_t lport, be16_t fport);

int redirect_dev_get_tx_packet(struct route_if *, struct dev_pkt *);
void redirect_dev_transmit(struct route_if *, int, struct dev_pkt *);

int service_sigprocmask(int, const sigset_t *, sigset_t *);

#ifdef __linux__
int service_clone(int (*)(void *), void *, int, void *, void *, void *, void *);
#endif // __linux__

void interface_dev_host_rx(struct dev *, void *, int);
int transmit_to_host(struct route_if *, void *, int);

void update_rss_table(void);

int gt_controller_init(int);
void gt_controller_deinit(void);
void controller_process(void);

#endif // GBTCP_WORKER_H
