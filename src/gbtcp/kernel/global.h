// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_GLOBAL_H
#define GBTCP_GLOBAL_H

#include <gbtcp/kernel/gbtcp.h>
#include <gbtcp/kernel/htable.h>
#include <gbtcp/kernel/lptree.h>

struct service;
struct shm_hdr;
struct route_entry_long;

#define GT_MODULE_MAX 128
#define GT_MODULE_NAME_MAX 16

extern struct shm_hdr *shared;
extern uint64_t nanoseconds;

#define GT_FUNCTION_INVALID_ID 0xff

// Process-portable reference to a module function. The controller stores
// (module_id, fn_id); the worker turns it back into a pointer with
// gt_worker_func_get(), because the worker may live in another process where
// the controller's pointers are meaningless. Defined here rather than in
// mod.h so that shm-resident, per-module structs (struct gt_main, struct
// gt_so_main) can embed it directly without a mod.h -> global.h cycle.
struct gt_worker_func {
	u8 fn_module_id;
	u8 fn_id;
};

static inline int
gt_worker_func_is_set(const struct gt_worker_func *fn)
{
	return fn->fn_id != GT_FUNCTION_INVALID_ID;
}

static inline void
gt_worker_func_clear(struct gt_worker_func *fn)
{
	fn->fn_module_id = 0;
	fn->fn_id = GT_FUNCTION_INVALID_ID;
}

struct log_scope {
	char lgs_name[16];
	int lgs_name_len;
	int lgs_level;
};

struct gt_main {
	u8 main_module_id;

	int log_level;
	struct log_scope dev_logger;
	struct log_scope sys_logger;
	struct log_scope infra_logger;
	struct log_scope arp_logger;
	struct log_scope inet_logger;
	struct log_scope route_logger;

	int inet_cksum_offload_rx;
	int inet_cksum_offload_tx;

	// route
	struct lptree route_lptree;
	struct gt_dlist route_if_head;
	struct route_entry_long *route_default;
	struct gt_dlist route_addr_head;

	// arp
	struct htable arp_htable;
	u64 arp_reachable_time;

	// Registered handle for the ARP entry timer (arp.c), resolved via
	// GT_WORKER_FUNC_EXEC() when the timer fires. Filled once
	// by gt_kernel_module_init() in the controller; gt_main lives in shm,
	// so every worker later reads back the same value.
	struct gt_worker_func main_timer_fn;

	// Registered handle for the kernel module's own tx flush callback
	// (gt_kernel_module_tx), added to tx_callbacks below from
	// gt_kernel_module_postinit(). Filled once by gt_kernel_module_init().
	struct gt_worker_func main_tx_fn;

	// Rx handlers, in registration (== load) order. A module registers its
	// handler in module_init (GT_WORKER_FUNC_REGISTER(..., rx, ...)) but only
	// appends it here from module_postinit, via gt_add_rx_callback() —
	// gt_worker_rx() (handoff.c) walks this list instead of relying on a
	// dedicated per-module field, so there's nothing module-system-specific
	// for it to know about a given module. Lives here rather than in
	// struct shm_hdr because gt_main is already the general cross-module
	// anchor (e.g. every gt_debug/gt_notice call goes through
	// gt_main->infra_logger). Deferring the append to postinit (which runs
	// after gt__module_load's fan-out has loaded the module on every
	// currently-attached worker) is what makes a config-driven "module
	// load" safe: no worker can observe an entry in this list before it
	// has already resolved that module locally.
	int n_rx_callbacks;
	struct gt_worker_func rx_callbacks[GT_MODULE_MAX];

	// Tx flush handlers, in registration (== load) order. Same
	// register-in-init/append-in-postinit split as rx_callbacks above, via
	// gt_add_tx_callback(). gt_worker_tx() (mod.c) walks this in REVERSE,
	// so the LAST-loaded module runs first — e.g. socket (loaded after
	// kernel) must push its queued packets into the device queue before
	// kernel's dev_tx_flush() drains it, so socket has to run first despite
	// kernel having registered first. Unlike rx, every resolved entry is
	// called, not just the first.
	int n_tx_callbacks;
	struct gt_worker_func tx_callbacks[GT_MODULE_MAX];
};

extern struct gt_main *gt_main;

#endif // GBTCP_GLOBAL_H
