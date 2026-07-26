// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/node.h>
#include <gbtcp/kernel/worker.h>

// Append an already-registered handler to the rx callback list. Call from
// module_postinit.
int
gt_add_rx_callback(const struct gt_worker_func *fn)
{
	if (gt_main->n_rx_callbacks == GT_ARRAY_SIZE(gt_main->rx_callbacks)) {
		return -ENOSPC;
	}

	gt_main->rx_callbacks[gt_main->n_rx_callbacks] = *fn;
	gt_main->n_rx_callbacks++;
	return 0;
}

// Append an already-registered handler to the tx flush callback list. Call
// from module_postinit.
int
gt_add_tx_callback(const struct gt_worker_func *fn)
{
	if (gt_main->n_tx_callbacks == GT_ARRAY_SIZE(gt_main->tx_callbacks)) {
		return -ENOSPC;
	}

	gt_main->tx_callbacks[gt_main->n_tx_callbacks] = *fn;
	gt_main->n_tx_callbacks++;
	return 0;
}

void
gt_worker_tx(void)
{
	int i;

	// gt_main (this process's own copy, set by gt_kernel_module_worker_
	// start()) isn't valid yet during the attach handshake: fd_poll_wait()
	// calls gt_worker_tx() whenever current != NULL, but service_attach()
	// runs gt_worker_attach()'s RPC handshake (itself polling) BEFORE
	// gt_worker_module_sync() loads any module. Nothing to flush yet.
	//
	// gt_main is a process-global, not per-thread: a sibling service-thread
	// in this same process may have already loaded the kernel module (and
	// so set gt_main) before THIS thread has loaded anything at all, so
	// gt_main == NULL alone doesn't catch this thread's own not-yet-synced
	// state. current->n_worker_modules is per-thread and stays 0 until
	// gt_worker_module_sync() runs, so check that too — otherwise
	// GT_WORKER_FUNC_EXEC() resolves an entry for a module this
	// thread hasn't loaded, and gt_worker_func_get() asserts.
	if (gt_main == NULL || current->n_worker_modules == 0) {
		return;
	}

	// Reverse registration order: whichever module registered LAST (e.g.
	// socket, which queues packets for the device to send) must run
	// before whichever registered FIRST (kernel, whose dev_tx_flush()
	// drains that queue) — see the comment on struct gt_main.tx_callbacks.
	for (i = gt_main->n_tx_callbacks - 1; i >= 0; --i) {
		GT_WORKER_FUNC_EXEC(&gt_main->tx_callbacks[i], tx);
	}
}
