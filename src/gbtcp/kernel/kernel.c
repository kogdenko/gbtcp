// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/api.h>
#include <gbtcp/kernel/arp.h>
#include <gbtcp/kernel/backtrace.h>
#include <gbtcp/kernel/handoff.h>
#include <gbtcp/kernel/inet.h>
#include <gbtcp/kernel/kernel.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/node.h>
#include <gbtcp/kernel/route.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/worker.h>

int
gt_kernel_module_init(u8 module_id, void **puser)
{
	int rc;

	gt_main = gt_malloc(shm_cache(), sizeof(*gt_main), 0);
	if (gt_main == NULL) {
		return -ENOMEM;
	}
	memset(gt_main, 0, sizeof(*gt_main));
	*puser = gt_main;
	gt_main->main_module_id = module_id;
	gt_main->log_level = log_get_level();
	log_scope_init(&gt_main->dev_logger, "dev");
	log_scope_init(&gt_main->sys_logger, "sys");
	log_scope_init(&gt_main->infra_logger, "infra");

	gt_inet_init();

	rc = gt_route_init();
	if (rc) {
		return rc;
	}

	rc = gt_arp_init();
	assert(rc == 0);

	rc = GT_WORKER_FUNC_REGISTER(module_id, timer, gt_kernel_module_timer,
				&gt_main->main_timer_fn);
	if (rc) {
		return rc;
	}

	return GT_WORKER_FUNC_REGISTER(module_id, tx, gt_kernel_module_tx,
				  &gt_main->main_tx_fn);
}

int
gt_kernel_module_postinit(void *mod)
{
	return gt_add_tx_callback(&gt_main->main_tx_fn);
}

int
gt_kernel_module_worker_init(struct service *s, int pid, int tid,
			     struct gt_api_conn *cp)
{
	int rc;

	// Identity, epoch and the other worker-owned state are set by the
	// worker itself when it claims the slot (service_claim_slot()); here
	// the controller resets its scheduling state and initializes the
	// controller-side machinery.
	assert(s->p_pid == pid);
	assert(s->p_tid == tid);
	s->p_rss_nq = 0;
	s->p_ctl_pending_update = 0;
	s->p_rr_redir = 0;
	s->wrk_conn = cp;
	s->p_start_time = shared_ns();

	rc = gt_timer_wheel_init(&s->wrk_timer_wheel);
	if (rc) {
		return rc;
	}
	rc = gt_main_handoff_init(s);
	if (rc) {
		return rc;
	}
	return service_init_arp(s);
}

void
gt_kernel_module_worker_deinit(u8 worker_index)
{
	int i;
	struct dev *dev;
	struct route_if *ifp;
	struct service *s;

	s = service_get_by_sid(worker_index);

	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
			dev = &(ifp->rif_dev[worker_index][i]);
			memset(dev, 0, sizeof(*dev));
		}
	}

	// The migration destination is the controller's service, not
	// `current`: on the remote-del path they are the same thing (the
	// controller thread deletes), but a local sibling deletes itself in
	// service_detach() with current already NULL. It holds the
	// controller's wrk_lock there, which also serializes the access to the
	// controller's wheel (the controller runs it under that lock).
	if (s != gt_controller_service) {
		gt_timer_wheel_migrate(&gt_controller_service->wrk_timer_wheel,
				       &s->wrk_timer_wheel, s->p_sid);
	}

	gt_timer_wheel_deinit(&s->wrk_timer_wheel);

	gt_main_handoff_deinit(s);
	service_deinit_arp(s);

	// Reclaim the dying worker's memory: return all pages owned by the dead
	// cache to the heap and reset its cache for reuse by a future worker.
	gt_mheap_free_cache(&shared->shm_heap, s->p_sid);
	gt_mcache_init(&s->p_mm_cache, &shared->shm_heap, s->p_sid);

	service_store_epoch(s, 0);

	// Free the slot last, under the slot lock: a claimer
	// (service_claim_slot) must only ever see a fully torn-down slot.
	shm_lock();
	s->p_inited = 0;
	s->p_pid = 0;
	s->p_tid = 0;
	shm_unlock();
}

void
gt_kernel_module_worker_start(void *m)
{
	int rc;

	// RCU state is initialized at slot claim (service_claim_slot) — it is
	// already live by the time modules attach; do not reset it here.
	rc = gt_worker_handoff_init(current);
	assert(rc == 0);

	gt_main = m;
}

void
gt_kernel_module_worker_stop(void)
{
	// A forked child detaches while `current` still points at the parent's
	// service slot; wrk_handoff there (in shm) belongs to the live parent
	// and must not be torn down. The child's inherited fd/mmap copies were
	// already closed by the p_dev_head sweep in service_in_child0().
	if (current != NULL && current->p_pid == getpid()) {
		gt_worker_handoff_deinit();
	}
	// gt_main points at the shared kernel-module object (the route/arp tables)
	// used by every service-thread in this process; it must not be cleared on a
	// per-thread detach or siblings would dereference NULL. It is set
	// (idempotently, to the same shared pointer) in worker_attach and goes away
	// with the process.
}

void
gt_kernel_module_tx(void)
{
	dev_tx_flush();
}

void
gt_init(void)
{
	char pathbuf[PATH_MAX];
	char *path;
	Dl_info info;

	GT_SYS_X(GT_SYS_DLSYM_DEFAULT);
	rd_nanoseconds();
	srand48(nanoseconds ^ getpid());
	log_init_early();

	gt_bfd_init();

	if (dladdr(gt_init, &info) != 0) {
		gt_bfd_open(NULL, info.dli_fname, GT_BFD_SHARED_LIBRARY);
	}

	path = gt_get_executable_path(pathbuf, sizeof(pathbuf));
	if (path != NULL) {
		gt_bfd_open(NULL, path, GT_BFD_EXECUTABLE);
	}
}
