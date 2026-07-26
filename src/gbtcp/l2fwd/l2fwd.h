// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_L2FWD_H
#define GBTCP_L2FWD_H

#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/log.h>

struct route_if;

#define GT_L2FWD_PAIR_MAX 32

// One unidirectional forwarding rule: packets received on the interface with
// index `in_ifindex` are transmitted out the interface with `out_ifindex`.
struct gt_l2fwd_pair {
	int l2fwd_in_ifindex;
	int l2fwd_out_ifindex;
};

struct gt_l2fwd_main {
	u8 l2fwd_module_id;
	struct log_scope l2fwd_logger;
	int l2fwd_n_pairs;
	struct gt_l2fwd_pair l2fwd_pairs[GT_L2FWD_PAIR_MAX];

	// Registered handle for gt_l2fwd_module_rx, added to
	// gt_main->rx_callbacks from gt_l2fwd_module_postinit(). Filled once by
	// gt_l2fwd_module_init() in the controller.
	struct gt_worker_func l2fwd_rx_fn;
};

// Lives in shared memory, pointed at by every worker.
extern struct gt_l2fwd_main *gt_l2fwd_main;

int gt_l2fwd_module_init(u8 module_id, void **puser);
int gt_l2fwd_module_postinit(void *mod);
void gt_l2fwd_module_deinit(void *user);
void gt_l2fwd_module_worker_start(void *m);
void gt_l2fwd_module_worker_stop(void);
int gt_l2fwd_module_rx(struct route_if *ifp, void *data, int len);

#endif // GBTCP_L2FWD_H
