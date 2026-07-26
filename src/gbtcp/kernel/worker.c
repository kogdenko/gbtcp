// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/api.h>
#include <gbtcp/kernel/backtrace.h>
#include <gbtcp/kernel/cli.h>
#include <gbtcp/kernel/vector.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/handoff.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/pid.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/subr.h>
#include <gbtcp/kernel/worker.h>

#include <gbtcp/kernel/gbtcp.pb-c.h>

#define gt_debug(...) gt_debug3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_info(...) gt_info3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_notice(...) gt_notice3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_warning(...) gt_warning3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_err(...) gt_err3(&gt_main->infra_logger, ##__VA_ARGS__)

struct gt_process gt_current_process;

__thread struct gt_thread gt_current_thread = {
	.trd_fd_event_timeout = FD_EVENT_TIMEOUT_MIN,
};

struct gt_api_conn gt_main_conn;

static int controller_pid_fd = -1;
static u8 controller_cli_inited;
static int sid_max = 0;

// Pid of the controller process, set in gt_controller_init() (after
// daemonization). Only the controller thread's own attach is local (added by
// a direct function call): every other service thread — a sibling thread in
// this pid included — connects to the controller socket and execs worker_add
// like any remote worker. Comparing against getpid() keeps a forked child of
// the controller off the local path: its pid no longer matches.
static int gt_controller_pid;

// The controller thread's own service, set once it attached. Process-local:
// non-NULL only in the controller process. The scheduler uses it to keep the
// controller off the RSS fanout, and the handoff bypass path tests `current`
// against it.
struct service *gt_controller_service;

static int controller_add_service(struct service *s, int pid, int tid,
				  struct gt_api_conn *cp);
static void controller_del_service(struct service *s);

struct service *
service_get_by_sid(u_int sid)
{
	assert(sid < GT_ARRAY_SIZE(shared->shm_services));
	return shared->shm_services + sid;
}

static void
gt_sighandler(int signum)
{
	gt_print_backtrace(STDERR_FILENO);

	// Reset handler to default
	sys_signal(signum, NULL, SIG_DFL);

	raise(signum); // Exit

	_exit(128 + signum);
}

static int
gt_worker_module_load_api_handler(struct gt_api_conn *cp,
				  Gt__WorkerModuleLoad *rq)
{
	Gt__WorkerModuleLoadReply *rp;

	rp = gt_api_alloc_reply(cp, rp, worker_module_load);
	if (rp == NULL) {
		return -ENOMEM;
	}

	gt_worker_module_load(rq->name);

	return gt_api_send_reply(cp, rp, worker_module_load);
}

GT_API_SERVER_DEFINE_HANDLER(worker_module_load,
			     gt_worker_module_load_api_handler)

// The controller asks this worker to refresh its rss-queue bindings
// (service_update_rss_bindings must run on the owning thread — it inits and
// deinits this thread's devs). Dispatched under this worker's locked
// baseline like any conn event.
//
// May arrive mid-attach: the controller may rebalance right after replying
// to worker_add, so the request can land while this thread still spins for
// that reply (both messages can even arrive in one batch), before
// service_attach() has run gt_worker_module_sync() — binding a queue installs
// rx callbacks that dispatch into the worker modules, so binding before they
// are loaded would resolve into nothing. Rather than sync modules here too,
// defer: service_attach() picks p_worker_update_pending up right after its
// own module sync (see there).
static int
gt_worker_update_api_handler(struct gt_api_conn *cp, Gt__WorkerUpdate *rq)
{
	Gt__WorkerUpdateReply *rp;

	rp = gt_api_alloc_reply(cp, rp, worker_update);
	if (rp == NULL) {
		return -ENOMEM;
	}

	if (current->n_worker_modules == 0) {
		current->p_worker_update_pending = 1;
	} else {
		service_update_rss_bindings();
	}

	return gt_api_send_reply(cp, rp, worker_update);
}

GT_API_SERVER_DEFINE_HANDLER(worker_update, gt_worker_update_api_handler)

// Process-once teardown: drop the single shm mapping shared by all
// service-threads. Called under pc_lock when the last
// service-thread detaches (or an early attach failure leaves none counted).
static void
worker_process_deinit(void)
{
	if (gt_current_process.pc_inited) {
		shm_detach();
		gt_current_process.pc_inited = 0;
	}
}

// Per-thread teardown of the calling service-thread. Safe to call on a partial
// attach (current == NULL). Does not touch the process-once state.
static void
service_detach_locked(void)
{
	if (gt_worker_conn != NULL) {
		if (current != NULL && current->p_pid != getpid()) {
			// Fork child detaching the inherited parent slot: the
			// conn and its buffers live in SHARED memory and still
			// belong to the parent — freeing them here would
			// corrupt the parent's live connection. Only close
			// this process's fd copy and drop it from the
			// (inherited, process-private) poll set.
			sys_close(gt_worker_conn->cn_fd);
			fd_event_del(gt_worker_conn->cn_event);
		} else {
			gt_api_conn_close(gt_worker_conn);
			gt_api_conn_free(gt_worker_conn);
		}
		gt_worker_conn = NULL;
	}

	// Same ownership rule as the conn above: a fork child detaching the
	// inherited parent slot must not unload the parent's worker modules —
	// worker_modules_buf lives in the parent's service struct in SHARED
	// memory, and wiping it makes the parent's next gt_worker_module_sync
	// reload the kernel module and gt_dev_init the still-linked handoff
	// dev, corrupting the parent's p_dev_head (self-looped node, the
	// worker then spins forever in dev_tx_flush). The child's inherited
	// dlopen handles are process-private and go away with the child (or
	// are refcount-reused when it attaches its own slot).
	if (current == NULL || current->p_pid == getpid()) {
		gt_worker_modules_unload();
	}

	current = NULL;

	clean_fd_events();

	sys_sigprocmask(SIG_SETMASK, &gt_current_thread.trd_sigprocmask, NULL);
}

// The worker claims a service slot by itself, under the shared slot lock.
// Only the identity fields are set here: the controller completes the
// controller-side initialization (timer wheel, handoff, ARP, wrk_conn) when it
// processes worker_add and only then marks the slot with p_inited — until that
// the controller scheduler and the handoff datapath ignore the slot.
static struct service *
service_claim_slot(int pid, int tid)
{
	int i;
	struct service *s;

	s = NULL;
	shm_lock();
	// No reserved slot: the controller claims like everyone else (it
	// attaches first, so it normally gets slot 0, but nothing relies on
	// that — gt_controller_service identifies it).
	for (i = 0; i < GT_ARRAY_SIZE(shared->shm_services); ++i) {
		if (shared->shm_services[i].p_pid == 0) {
			s = shared->shm_services + i;
			break;
		}
	}
	if (s != NULL) {
		s->p_pid = pid;
		s->p_tid = tid;
		s->p_sid = s - shared->shm_services;

		// Worker-owned state, used by this thread's event loop
		// (service_unlock/RCU) from the moment `current` is set —
		// must be valid before the claim is returned.
		s->p_rcu_max = 0;
		gt_dlist_init(&s->p_rcu_active_head);
		gt_dlist_init(&s->p_rcu_shadow_head);
		memset(s->p_rcu, 0, sizeof(s->p_rcu));
		gt_dlist_init(&s->p_dev_head);
		s->p_okpps = 0;
		s->p_okpps_time = 0;
		s->p_opkts = 0;
		// gt_worker_tx() walks this from the first fd_poll_wait(),
		// so a stale count from the slot's previous occupant must
		// not survive the claim. A crashed occupant also leaves
		// stale objects in the buf — gt_worker_module_sync() must
		// see them as unloaded.
		s->n_worker_modules = 0;
		s->p_worker_update_pending = 0;
		memset(s->worker_modules_buf, 0, sizeof(s->worker_modules_buf));
		gt_dlist_init(&s->worker_module_head);
		service_store_epoch(s, 1);
	}
	shm_unlock();
	return s;
}

// Release a slot claimed by service_claim_slot() when the handshake with the
// controller did not complete. Once worker_add succeeded (p_inited), the
// controller owns the slot lifetime via the connection close handler. The
// pid/tid guard makes this a no-op if the controller freed the slot
// concurrently (and a third party re-claimed it).
static void
service_unclaim_slot(struct service *s, int pid, int tid)
{
	shm_lock();
	if (s->p_pid == pid && s->p_tid == tid && !s->p_inited) {
		service_store_epoch(s, 0);
		s->p_pid = 0;
		s->p_tid = 0;
	}
	shm_unlock();
}

#define GT_PROCESS_LOCK spinlock_lock(&(proc)->pc_lock)
#define GT_PROCESS_UNLOCK spinlock_unlock(&(proc)->pc_lock);

// Register a claimed slot with the controller. Only the controller's own
// attach is a direct call: the controller is this very thread, so it cannot
// synchronously RPC itself (and it attaches before the API server is even
// started). Every other worker — including a sibling thread of the controller
// process — connects to the controller socket and execs worker_add, so all
// controller-side machinery keyed on wrk_conn (module fanout, liveness probe,
// slot teardown on conn close) works the same for local and remote workers.
static int
gt_worker_attach(struct service *s, int pid, int tid)
{
	int rc;

	if (gt_controller_pid == getpid() && gt_controller_service == NULL) {
		// Publish gt_controller_service BEFORE the add:
		// controller_sched_balance() (run by the main loop as soon as
		// p_inited is set) must see this service as the controller's.
		gt_controller_service = s;
		rc = controller_add_service(s, pid, tid, NULL);
		if (rc) {
			gt_controller_service = NULL;
		}
		return rc;
	}

	gt_worker_conn = gt_api_conn_alloc(gt_get_kallocator());
	if (gt_worker_conn == NULL) {
		return -ENOMEM;
	}
	rc = gt_api_client_connect(gt_worker_conn, GT_API_SOCK_PATH);
	if (rc) {
		gt_warning(0, "Failed connect to controller");
		return rc;
	}

	Gt__WorkerAdd *rq;
	Gt__WorkerAddReply *rp;

	rq = gt_api_alloc_request(gt_worker_conn, rq, worker_add);
	if (rq == NULL) {
		return -ENOMEM;
	}

	rq->pid = pid;
	rq->tid = tid;

	// Register BEFORE the worker_add exec: the controller may exec
	// worker_update on this conn from inside the worker_add handler
	// (controller_sched_balance rebalances onto the new worker), i.e.
	// before the worker_add reply — this thread dispatches the request
	// while spinning for the reply, so the handlers must already be
	// known. Part of the attach handshake, not of module loading.
	gt_api_register_request(gt_worker_conn, worker_module_load);
	gt_api_register_request(gt_worker_conn, worker_update);

	rc = gt_api_exec_request(gt_worker_conn, rp, rq, worker_add);
	if (rc) {
		return rc;
	}
	gt__worker_add_reply__free_unpacked(
		rp, &gt_worker_conn->cn_pbc_allocator.protobuf_allocator);

	return 0;
}

int
service_attach(void)
{
	int rc, pid, tid, added;
	sigset_t sigprocmask_block;
	struct service *s;
	struct gt_process *proc;

	proc = &gt_current_process;

	GT_PROCESS_LOCK;
	// Check (current != NULL) again under the lock
	if (current != NULL) {
		GT_PROCESS_UNLOCK;
		return 0;
	}
	pid = getpid();
	tid = gt_gettid();
	added = 0;

	// Process-once setup (first service-thread only). gt_init() resolves libc
	// symbols needed by the connect below, so it must run before it.
	// The shm mapping is shared by every service-thread in this process and
	// is attached exactly once, before any other allocation, so everything
	// below can allocate from the heap. Attaching before the controller
	// handshake is safe: the heap file is published atomically (rename)
	// only fully initialized. A stale heap of a dead controller is
	// detached again by the error path when the connect below fails.
	if (!proc->pc_inited) {
		gt_init();
		sys_signal(SIGABRT, NULL, gt_sighandler);
		sys_signal(SIGSEGV, NULL, gt_sighandler);
		rc = shm_attach();
		if (rc) {
			goto err;
		}
		set_hz(shared->shm_hz);
		gt_current_process.pc_inited = 1;
	}

	// Claim a service slot before anything else allocates: from here
	// shm_cache() returns this worker's own cache.
	s = service_claim_slot(pid, tid);
	if (s == NULL) {
		rc = -ENOENT;
		goto err;
	}
	current = s;

	// This thread's own code addresses, bound to this slot's shm-resident
	// cache: safe unlike storing the vtable in shm itself, since every
	// process attaching a service links this library independently and a
	// code pointer written by one process's shm_init() is not a valid
	// address in another's.
	gt_kallocator_init(&gt_current_thread.trd_kallocator, &s->p_mm_cache);

	sigfillset(&sigprocmask_block);
	sigdelset(&sigprocmask_block, SIGSEGV);
	sigdelset(&sigprocmask_block, SIGABRT);
	rc = sys_sigprocmask(SIG_BLOCK, &sigprocmask_block,
			     &gt_current_thread.trd_sigprocmask);
	if (rc) {
		goto err;
	}

	rc = gt_worker_attach(s, pid, tid);
	if (rc) {
		goto err;
	}
	// From here the controller owns the slot lifetime: a remote worker's
	// slot is freed when its connection closes, the controller's own slot
	// lives until gt_controller_deinit().
	added = 1;

	// Loading the worker shared-library modules is a separate step from
	// the attach handshake above.
	rc = gt_worker_modules_load();
	if (rc) {
		goto err;
	}

	// Bind the rss queues the controller assigned during the worker_add
	// handshake (controller_sched_balance runs inside the handler) right
	// here instead of waiting for the worker_update RPC: a worker of a
	// privilege-dropping app (nginx) is still root only while inside
	// fork() — a later nm_open would fail with EACCES. Also picks up a
	// worker_update that arrived mid-handshake before modules were synced
	// (gt_worker_update_api_handler deferred it here instead of binding
	// against not-yet-loaded modules). Not on the controller's own early
	// attach (no modules loaded yet — no route state to walk).
	if (current->n_worker_modules > 0) {
		current->p_worker_update_pending = 0;
		service_update_rss_bindings();
	}

	gt_current_process.pc_n_workers++;

	gt_err(0, "service %d attached", current->p_sid);
	spinlock_unlock(&gt_current_process.pc_lock);
	return 0;

err:
	// Free cache-backed allocations (gt_worker_conn) BEFORE releasing the
	// slot: once unclaimed, another thread may claim the slot and become
	// the single owner of its mm_cache.
	s = current;
	service_detach_locked();
	if (s != NULL && !added) {
		service_unclaim_slot(s, pid, tid);
	}
	if (gt_current_process.pc_n_workers == 0) {
		worker_process_deinit();
	}

	GT_PROCESS_UNLOCK;
	return rc;
}

// Process-local setup for a utility tool (gbtcpctl, gbtcp-netstat). A utility
// is not a worker: it claims no service slot and does not touch shared memory
// at all — while current == NULL the ambient allocator (gt_get_allocator()) backs
// api/cli/protobuf allocations with sys_malloc, and fd_poll_wait() skips the
// worker-only steps (SERVICE_LOCK, timer wheel, gt_worker_tx). Only the
// process plumbing is needed: libc symbols (gt_init), a measured hz for the
// poll timeouts, and the ppoll() sigmask — the tool's signal disposition
// (readline, Ctrl-C) is left untouched.
int
gt_utility_init(void)
{
	int64_t hz;

	gt_init();

	hz = sleep_compute_hz();
	if (hz > 0) {
		set_hz(hz);
	}

	return sys_sigprocmask(SIG_BLOCK, NULL,
			       &gt_current_thread.trd_sigprocmask);
}

void
service_detach(void)
{
	int attached;
	struct service *s;

	spinlock_lock(&gt_current_process.pc_lock);

	s = current;
	attached = (s != NULL);
	if (attached) {
		gt_notice(0, "worker %u: detach", s->p_sid);
	}

	// Closing gt_worker_conn above is what frees the slot: the controller
	// notices the conn close and runs controller_del_service
	// (service_conn_close) — for a local sibling worker just like for a
	// remote one. The controller's own service has no conn; it goes down
	// with the heap in gt_controller_deinit().
	// TODO: a dying sibling's rss-queue devs (p_dev_head) hold fds of the
	// shared process; they are memset by the kernel worker deinit but
	// never closed — the controller-side delete should sweep them.
	service_detach_locked();

	if (attached) {
		gt_current_process.pc_n_workers--;
	}
	if (gt_current_process.pc_n_workers == 0) {
		worker_process_deinit();
	}

	spinlock_unlock(&gt_current_process.pc_lock);
}

static void
service_rcu_reload(void)
{
	int i;
	struct service *s;

	gt_dlist_replace_init(&current->p_rcu_active_head,
			      &current->p_rcu_shadow_head);
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		s = shared->shm_services + i;
		if (s != current) {
			current->p_rcu[i] = service_load_epoch(s);
			if (current->p_rcu[i]) {
				current->p_rcu_max = i + 1;
			}
		}
	}
	//if (service_rcu_max == 0) {
	//	service_rcu_free();
	//}
}

// Defer-free an object after an RCU grace period. `node` must be an embedded
// gt_dlist that is the first field of the object (so it is also the allocation
// base passed to gt_free).
void
gt_free_rcu(struct gt_dlist *node)
{
	gt_dlist_insert_tail(&current->p_rcu_shadow_head, node);
	if (current->p_rcu_max == 0) {
		assert(gt_dlist_is_empty(&current->p_rcu_active_head));
		service_rcu_reload();
	}
}

static void
service_rcu_free(void)
{
	struct gt_dlist *head, *node;

	head = &current->p_rcu_active_head;
	while (!gt_dlist_is_empty(head)) {
		node = head->dls_next;
		gt_dlist_remove(node);
		gt_free_internal(shm_cache(), node);
	}
}

static void
service_rcu_check(void)
{
	u_int i, epoch, rcu_max;
	struct service *s;

	rcu_max = 0;
	for (i = 0; i < current->p_rcu_max; ++i) {
		s = shared->shm_services + i;
		if (current->p_rcu[i]) {
			epoch = service_load_epoch(s);
			if (current->p_rcu[i] != epoch) {
				current->p_rcu[i] = 0;
			} else {
				rcu_max = i + 1;
			}
		}
	}
	current->p_rcu_max = rcu_max;
	if (current->p_rcu_max == 0) {
		service_rcu_free();
		if (!gt_dlist_is_empty(&current->p_rcu_shadow_head)) {
			service_rcu_reload();
		}
	}
}

void
service_unlock(void)
{
	u_int epoch;

	// FIXME: current?
	if (current == NULL) {
		return;
	}

	epoch = current->p_epoch + 1;
	if (epoch == 0) {
		epoch++;
	}

	service_store_epoch(current, epoch);
}

void
service_account_opkt(void)
{
	uint64_t dt;

	current->p_opkts++;
	dt = nanoseconds - current->p_okpps_time;
	if (dt >= GT_NSEC_PER_MSEC) {
		if (dt > 2 * GT_NSEC_PER_MSEC) {
			// Gap in more then 1 millisecond
			WRITE_ONCE(current->p_okpps, 0);
		} else {
			WRITE_ONCE(current->p_okpps, current->p_opkts);
		}
		current->p_okpps_time = nanoseconds;
		current->p_opkts = 0;
	}
}

static void
service_update_rss_binding(struct route_if *ifp, int queue_id)
{
	int id, ifflags;
	struct dev *dev;

	ifflags = READ_ONCE(ifp->rif_flags);
	id = READ_ONCE(shared->shm_rss_table[queue_id]);
	dev = &(ifp->rif_dev[current->p_sid][queue_id]);
	if ((ifflags & IFF_UP) && id == current->p_sid) {
		if (!dev_is_inited(dev)) {
			//			PRF_INIT(dev);
			//			PRF_ENTER(dev);
			gt_dev_init(dev, ifp->rif_dev_io, ifp->rif_name,
				    queue_id, service_rssq_rx);
			//			PRF_LEAVE(dev);
			dev->dev_ifp = ifp;
		}
	} else {
		// Other service occupy this queue or interface down
		gt_dev_deinit(dev, false);
	}
}

void
service_update_rss_bindings(void)
{
	int i;
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < ifp->rif_rss_queue_num; ++i) {
			service_update_rss_binding(ifp, i);
		}
	}
}

// TODO: What if the service have no rssq under control???
u8
gt_worker_rss_is_symmetric(struct route_if *ifp, be32_t laddr, be32_t faddr,
			   be16_t lport, be16_t fport)
{
	u32 q, h, n;
	struct gt_rss *rss;

	n = ifp->rif_rss_queue_num;
	rss = &ifp->rif_rss;
	if (n == 1 || rss->rss_key_size == 0) {
		return 1;
	}

	h = gt_rss_hash4(laddr, faddr, lport, fport, rss->rss_key,
			 rss->rss_key_size);
	q = gt_rss_get_queue(h, n, rss->rss_indir_table,
			     rss->rss_indir_table_size);

	return READ_ONCE(shared->shm_rss_table[q]) == current->p_sid;
}

int
service_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;
	sigset_t tmp;

	// unblock, @tmp - block mask
	sys_sigprocmask(SIG_SETMASK, &gt_current_thread.trd_sigprocmask, &tmp);

	// change @trd_sigprocmask
	rc = sys_sigprocmask(how, set, oldset);

	// block again, and retrive changed @trd_sigprocmask
	sys_sigprocmask(SIG_SETMASK, &tmp, &gt_current_thread.trd_sigprocmask);

	return rc;
}

void
interface_dev_host_rx(struct dev *dev, void *data, int len)
{
	int rc;
	struct route_if *ifp;
	struct dev_pkt pkt;

	ifp = container_of(dev, struct route_if, rif_host_dev);
	rc = route_get_tx_packet(ifp, &pkt, TX_CAN_REDIRECT);
	if (rc == 0) {
		memcpy(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		route_transmit(ifp, &pkt);
	} else {
		// TODO: increment counter
	}
}

int
transmit_to_host(struct route_if *ifp, void *data, int len)
{
	int rc;
	struct dev_pkt pkt;

	rc = dev_get_tx_packet(&ifp->rif_host_dev, &pkt);
	if (rc == 0) {
		memcpy(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		dev_transmit(&pkt);
	} else {
		// TODO: increment counter
	}
	return rc;
}

// Sync RPC: the reply carries no payload, but waiting for it keeps at most
// one outstanding request per conn (gt_api__send_request refuses — and
// closes the conn — when a reply is still pending).
static int
gt_api_exec_worker_update(struct service *w)
{
	int rc;
	Gt__WorkerUpdate *rq;
	Gt__WorkerUpdateReply *rp;

	rq = gt_api_alloc_request(w->wrk_conn, rq, worker_update);
	if (rq == NULL) {
		return -ENOMEM;
	}

	rc = gt_api_exec_request(w->wrk_conn, rp, rq, worker_update);
	if (rc) {
		return rc < 0 ? rc : -rc;
	}
	gt__worker_update_reply__free_unpacked(
		rp, &w->wrk_conn->cn_pbc_allocator.protobuf_allocator);
	return 0;
}

static void
update_rss_bindings(struct service *s)
{
	if (s == current) {
		service_update_rss_bindings();
	} else {
		// Rss-queue devs are owned by the worker's thread: it is told
		// over the API (worker_update). Not exec'd here — rebinding
		// runs inside conn handlers (worker_add, conn close), where a
		// sync exec can nest on the conn being processed or collide
		// with an exec already in flight (one outstanding request per
		// conn); either closes the worker's conn and cascades into
		// deleting a live worker. The main loop drains the flag.
		s->p_ctl_pending_update = 1;
	}
}

static void
controller_sched_alg(struct service **ppick, struct service **pkick)
{
	int i;
	struct service *s, *pick, *kick, *ctl;

	// Not `current`: with local sibling workers this can run on a thread
	// other than the controller (direct controller_add_service call).
	ctl = gt_controller_service;
	pick = kick = NULL;
	for (i = 0; i <= sid_max; ++i) {
		s = shared->shm_services + i;
		// The controller's service polls packets only as the fallback
		// below.
		if (s != ctl && s->p_inited) {
			if (pick == NULL || pick->p_rss_nq > s->p_rss_nq) {
				pick = s;
			}
			if (kick == NULL || kick->p_rss_nq < s->p_rss_nq) {
				kick = s;
			}
		}
	}
	if (pick == NULL) {
		pick = ctl;
	}
	if (kick == NULL || ctl->p_rss_nq) {
		kick = ctl;
	} else {
		if (kick->p_rss_nq <= pick->p_rss_nq + 1 &&
		    kick->p_start_time >= pick->p_start_time) {
			// Do not preempt
			kick = pick;
		}
	}

	if (ppick != NULL) {
		*ppick = pick;
	}
	if (pkick != NULL) {
		*pkick = kick;
	}
}

static void
set_rss_binding(u_int rssq, int sid)
{
	int old_sid;

	assert(rssq < GT_RSS_NQ_MAX);
	assert(sid == SERVICE_ID_INVALID || sid < GT_SERVICES_MAX);
	old_sid = shared->shm_rss_table[rssq];
	if (old_sid == sid) {
		return;
	}
	if (sid != SERVICE_ID_INVALID) {
		gt_notice(0, "Bind rssq %d to service %d (pid:%d)", rssq, sid,
			  shared->shm_services[sid].p_pid);
	}
	WRITE_ONCE(shared->shm_rss_table[rssq], sid);
}

static void
controller_sched_balance(void)
{
	int i;
	struct service *pick, *kick;

	controller_sched_alg(&pick, &kick);

	if (pick == gt_controller_service || pick == kick ||
	    kick->p_rss_nq == 0) {
		return;
	}

	for (i = 0; i < shared->shm_rss_table_size; ++i) {
		if (shared->shm_rss_table[i] == kick->p_sid) {
			set_rss_binding(i, pick->p_sid);
			kick->p_rss_nq--;
			pick->p_rss_nq++;
			update_rss_bindings(kick);
			update_rss_bindings(pick);
			return;
		}
	}
}

static void
controller_del_service(struct service *s)
{
	int i, sid, rss_nq;
	struct service *new;

	gt_notice(0, "delete service; sid:%d, pid:%d", s->p_sid, s->p_pid);
	sid = s->p_sid;
	rss_nq = s->p_rss_nq;
	if (rss_nq) {
		controller_sched_alg(&new, NULL);
		for (i = 0; i < shared->shm_rss_table_size; ++i) {
			if (shared->shm_rss_table[i] == sid) {
				set_rss_binding(i, new->p_sid);
				assert(rss_nq > 0);
				rss_nq--;
				new->p_rss_nq++;
			}
		}
		assert(rss_nq == 0);
		update_rss_bindings(new);
	}
	gt_main_modules_worker_deinit(s);
}

static int
controller_add_service(struct service *s, int pid, int tid,
		       struct gt_api_conn *cp)
{
	int rc;

	// call module_worker_init with worker foreach module
	rc = gt_main_modules_worker_init(s, pid, tid, cp);
	if (rc) {
		return rc;
	}
	sid_max = GT_MAX(sid_max, s->p_sid);
	// Publish under the slot lock: from here the scheduler and the handoff
	// datapath consider the service, and the worker-side unclaim guard
	// (service_unclaim_slot) becomes a no-op.
	shm_lock();
	s->p_inited = 1;
	shm_unlock();
	gt_notice(0, "add service; sid:%d, pid:%d", s->p_sid, pid);
	return 0;
}

static void
rss_table_reduce(int rss_table_size)
{
	int i, n;
	u_char id;
	struct service *s;

	n = shared->shm_rss_table_size;
	WRITE_ONCE(shared->shm_rss_table_size, rss_table_size);
	for (i = rss_table_size; i < n; ++i) {
		id = shared->shm_rss_table[i];
		set_rss_binding(i, SERVICE_ID_INVALID);
		assert(id < GT_SERVICES_MAX);
		s = shared->shm_services + id;
		assert(s->p_rss_nq > 0);
		s->p_rss_nq--;
		if (s->p_rss_nq == 0) {
			update_rss_bindings(s);
		}
	}
}

static void
rss_table_expand(int rss_table_size)
{
	int i;
	struct service *s;

	controller_sched_alg(&s, NULL);
	for (i = shared->shm_rss_table_size; i < rss_table_size; ++i) {
		set_rss_binding(i, s->p_sid);
		s->p_rss_nq++;
	}
	WRITE_ONCE(shared->shm_rss_table_size, rss_table_size);
}

void
update_rss_table(void)
{
	int i, rss_table_size;
	struct route_if *ifp;
	struct service *s;

	rss_table_size = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_flags & IFF_UP) {
			if (rss_table_size < ifp->rif_rss_queue_num) {
				rss_table_size = ifp->rif_rss_queue_num;
			}
		}
	}
	if (shared->shm_rss_table_size > rss_table_size) {
		rss_table_reduce(rss_table_size);
	} else if (shared->shm_rss_table_size < rss_table_size) {
		rss_table_expand(rss_table_size);
	}
	if (current->p_rss_nq) {
		update_rss_bindings(current);
	}
	for (i = 0; i <= sid_max; ++i) {
		s = shared->shm_services + i;
		if (s->p_inited && s->p_rss_nq) {
			update_rss_bindings(s);
		}
	}
}

static int
service_conn_close(struct gt_api_conn *cp)
{
	struct service *s;

	s = gt_api_conn_get_udata(cp);
	if (s != NULL) {
		controller_del_service(s);
	}
	return 0;
}

// "Inited" means fully added by the controller (worker_add processed): the
// scheduler, module fanout and handoff may use the service. A slot with
// p_pid != 0 but !p_inited is merely claimed by a worker whose handshake is
// still in flight.
#define gt_worker_is_inited(s) ((s)->p_inited)

static int
gt_worker_add_api_handler(struct gt_api_conn *cp, Gt__WorkerAdd *rq)
{
	int i, rc;
	struct service *s;
	Gt__WorkerAddReply *rp;

	// The worker claims its slot itself (service_claim_slot()) before the
	// handshake; locate the claim by its identity.
	s = NULL;
	for (i = 0; i < GT_ARRAY_SIZE(shared->shm_services); ++i) {
		if (shared->shm_services[i].p_pid == (int)rq->pid &&
		    shared->shm_services[i].p_tid == (int)rq->tid) {
			s = shared->shm_services + i;
			break;
		}
	}
	if (s == NULL) {
		return -ENOENT;
	}
	if (s->p_inited) {
		return -EEXIST;
	}
	rc = controller_add_service(s, rq->pid, rq->tid, cp);
	if (rc) {
		return rc;
	}
	rp = gt_api_alloc_reply(cp, rp, worker_add);
	if (rp == NULL) {
		return -ENOMEM;
	}
	gt_api_conn_set_udata(cp, s);
	gt_api_conn_set_close_handler(cp, service_conn_close);
	return gt_api_send_reply(cp, rp, worker_add);
}

GT_API_SERVER_DEFINE_HANDLER(worker_add, gt_worker_add_api_handler)

static int
gt_api_exec_worker_module_load(struct service *w, const char *name)
{
	int rc;
	Gt__WorkerModuleLoad *rq;
	Gt__WorkerModuleLoadReply *rp;

	rq = gt_api_alloc_request(w->wrk_conn, rq, worker_module_load);
	if (rq == NULL) {
		return -ENOMEM;
	}

	// Owned by the request message: freed via free_unpacked/gt_pbc_free.
	rq->name = gt_pbc_strdup(w->wrk_conn, name);
	rc = gt_api_exec_request(w->wrk_conn, rp, rq, worker_module_load);
	if (rc) {
		return rc < 0 ? rc : -rc;
	}
	gt__worker_module_load_reply__free_unpacked(
		rp, &w->wrk_conn->cn_pbc_allocator.protobuf_allocator);
	return 0;
}

static int
gt_module_load(const char *name)
{
	int rc;
	struct service *w;

	rc = gt_main_module_load(name);
	if (rc) {
		return rc;
	}

	GT_WORKER_FOREACH(w) {
		if (!gt_worker_is_inited(w)) {
			continue;
		}

		rc = gt_main_module_worker_init(name, w);
		if (rc) {
			return rc;
		}

		if (w == current) {
			// The controller's own service: no API connection
			// (gt_worker_attach() adds it by a direct call).
			gt_worker_module_load(name);
		} else {
			// Every other worker — local sibling threads included —
			// attached over the API and has a conn for the fanout.
			gt_api_exec_worker_module_load(w, name);
		}
	}

	return gt_main_module_postinit(name);
}

static int
gt_module_load_api_handler(struct gt_api_conn *cp, Gt__ModuleLoad *rq)
{
	Gt__ModuleLoadReply *rp;

	rp = gt_api_alloc_reply(cp, rp, module_load);
	if (rp == NULL) {
		return -ENOMEM;
	}

	gt_module_load(rq->name);

	return gt_api_send_reply(cp, rp, module_load);
}

GT_API_SERVER_DEFINE_HANDLER(module_load, gt_module_load_api_handler)

static int
gt_module_load_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	const char *name;
	struct gt_cli_arg *arg;

	name = NULL;

	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "name")) {
			name = arg->arg_value;
		}
	}

	assert(name != NULL);
	gt_module_load(name);

	return 0;
}

static void
controller_unbind(int pid)
{
	gt_api_conn_close(&gt_main_conn);
}

static int
main_pid_file_acquire(int pid)
{
	int rc, fd;

	rc = pid_file_open("/var/run/gbtcp.pid");
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = pid_file_acquire(fd, pid);
	if (rc >= 0 && rc != pid) {
		rc = -EBUSY;
	}
	if (rc < 0) {
		sys_close(fd);
		return rc;
	} else {
		return fd;
	}
}

static int
gt_worker_show_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	char *s;
	struct service *w;

	s = NULL;
	GT_WORKER_FOREACH(w) {
		if (!gt_worker_is_inited(w)) {
			continue;
		}
		gt_str_printf(s, "Worker %d\n", w->p_sid);
		gt_str_printf(s, "  pid: %d\n", w->p_pid);
		gt_str_printf(s, "  tid: %d\n", w->p_tid);
	}
	gt_cli_output(ctx, s);
	return 0;
}

int
gt_controller_init(int daemonize)
{
	int i, rc, pid;
	u64 hz;

	gt_init();

	shared = NULL;
	if (daemonize) {
		rc = sys_daemon(1, 1);
		assert(rc == 0);
		if (rc) {
			goto err;
		}
	}

	// After daemonization (daemon() forks): from here every service
	// thread with this pid attaches locally, by direct call.
	pid = getpid();
	gt_controller_pid = pid;
	rc = main_pid_file_acquire(pid);
	assert(rc >= 0);
	if (rc < 0) {
		goto err;
	}
	controller_pid_fd = rc;

	// Create the shared heap as early as possible — right after the pid
	// file (the lock that keeps a second controller from truncating a live
	// heap) — so everything below can allocate from it.
	rc = shm_init();
	assert(rc == 0);
	if (rc) {
		goto err;
	}

	// hz and the rss table must exist before the attach: the process-once
	// block in service_attach() does set_hz(shm_hz) (mHZ == 0 would
	// SIGFPE in rd_nanoseconds() on the first SERVICE_LOCK), and
	// controller_add_service() walks the rss table. Neither allocates.
	hz = sleep_compute_hz();
	set_hz(hz);
	shared->shm_hz = hz;
	shared->shm_rss_table_size = 0;

	for (i = 0; i < GT_ARRAY_SIZE(shared->shm_rss_table); ++i) {
		shared->shm_rss_table[i] = SERVICE_ID_INVALID;
	}

	// Attach before ANY shared-memory allocation: from here shm_cache()
	// returns the controller's own claimed cache (see the assert there).
	// No modules are loaded yet, so gt_main_modules_worker_init() and
	// gt_worker_module_load_all() see an empty shm_mods and do nothing;
	// the kernel module's per-service state (timer wheel, handoff, ARP) is
	// initialized retroactively when the module loads below — nothing may
	// poll (fd_poll_wait would run the still-uninitialized timer wheel)
	// until then.
	rc = service_attach();
	assert(rc == 0);

	// Must precede the kernel module load: the module init (route, arp,
	// inet) registers CLI commands and API requests on gt_main_conn.
	gt_api_server_init(&gt_main_conn, gt_get_kallocator());
	gt_cli_server_init();

	gt_set_module_directory();

	// Through gt__module_load, not gt_main_module_load: the fanout loads
	// the worker-side kernel module into the controller's own service
	// (before the early attach, service_attach did that via
	// gt_worker_module_load_all).
	rc = gt_module_load("kernel");
	assert(rc == 0);

	rc = gt_api_server_start(&gt_main_conn);
	assert(rc == 0);

	if (daemonize == 0) {
		controller_cli_inited = 1;
		gt_cli_client_init();
	}

	gt_cli_register_command("worker show", gt_worker_show_cli_handler, NULL,
				"[verbose]");

	gt_cli_register_command("module load", gt_module_load_cli_handler, NULL,
				"<name string>");

	gt_api_register_request(&gt_main_conn, worker_add);
	gt_api_register_request(&gt_main_conn, module_load);

	rc = gt_cli_server_play_file();
	if (rc) {
		goto err;
	}

	gt_notice(0, "Controller initialized");
	return 0;

err:
	gt_err(-rc, "Controller initialization failed");
	gt_controller_deinit();
	return rc;
}

void
gt_controller_deinit(void)
{
	int pid;

	gt_notice(0, "controller shutdown");

	if (controller_cli_inited) {
		controller_cli_inited = 0;
		gt_cli_client_deinit();
	}

	pid = getpid();
	controller_unbind(pid);

	service_detach();

	if (shared != NULL) {
		gt_main_modules_unload();
	}

	shm_deinit();
	sys_close(controller_pid_fd);
	controller_pid_fd = -1;
}

// Send the worker_update RPCs marked pending by update_rss_bindings(). Main
// loop only: the sync exec spins in wait_for_fd_events, so nothing else may
// be mid-exec and no conn request may be being processed (the exec-inside-
// handler hazards described in update_rss_bindings). Events dispatched
// during the spin (a worker dying, a new worker_add) only mark more flags —
// they are picked up here, one exec at a time. A failed exec (ECONNRESET —
// the worker died mid-exec and its conn was closed and freed by the close
// handler during the spin) needs no handling: the slot is already deleted.
static void
controller_send_pending_updates(void)
{
	int i;
	struct service *s;

	for (i = 0; i <= sid_max; ++i) {
		s = shared->shm_services + i;
		if (!s->p_inited || !s->p_ctl_pending_update) {
			continue;
		}
		s->p_ctl_pending_update = 0;
		if (s == current) {
			service_update_rss_bindings();
		} else if (s->wrk_conn != NULL) {
			gt_api_exec_worker_update(s);
		}
	}
}

void
controller_process(void)
{
	rd_nanoseconds();
	WRITE_ONCE(shared->shm_ns, nanoseconds);
	wait_for_fd_events();
	service_rcu_check();
	controller_sched_balance();
	controller_send_pending_updates();
}
