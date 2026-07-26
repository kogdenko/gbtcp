// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_NODE_H
#define GBTCP_NODE_H

#include <gbtcp/kernel/mod.h>

// Append an already-registered rx handler to the shm-resident list of rx
// callbacks (gt_main->rx_callbacks). `fn` must already have been registered
// in module_init (typically via GT_WORKER_FUNC_REGISTER(module_id, rx, ...)); call
// this from module_postinit instead, once every worker attached before this
// module loaded has already resolved the module locally (postinit runs after
// gt__module_load's fan-out) — so no worker can observe this entry before it
// can resolve it. handoff.c's gt_worker_rx() walks this list and calls the
// first entry that resolves in the calling process, so a module needs no
// dedicated field anywhere for mod.c to find it by — congruent with how
// timer handlers are registered.
int gt_add_rx_callback(const struct gt_worker_func *fn);

// Same idea for tx flush handlers: append an already-registered `fn` to
// gt_main->tx_callbacks. Call from module_postinit, same as gt_add_rx_callback
// above. gt_worker_tx() walks the whole list, in reverse — see the comment on
// struct gt_main.tx_callbacks for why order matters here.
int gt_add_tx_callback(const struct gt_worker_func *fn);

// Call every registered tx flush handler that resolves in this process, in
// reverse registration order — see the comment on struct gt_main.tx_callbacks
// for why order matters. Called from fd_event.c's fd_poll_wait() on every
// poll iteration.
void gt_worker_tx(void);

#endif // GBTCP_NODE_H
