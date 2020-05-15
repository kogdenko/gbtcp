// GPL2 license
#include "internals.h"

struct proc_mod {
	struct log_scope log_scope;
};

#define MOD_FOREACH(x, a0, a1) \
	x(sysctl, a0, a1) \
	x(log, a0, a1) \
	x(proc, a0, a1) \
	x(subr, a0, a1) \
	x(pid, a0, a1) \
	x(poll, a0, a1) \
	x(epoll, a0, a1) \
	x(sys, a0, a1) \
	x(mbuf, a0, a1) \
	x(htable, a0, a1) \
	x(timer, a0, a1) \
	x(fd_event, a0, a1) \
	x(signal, a0, a1) \
	x(dev, a0, a1) \
	x(api, a0, a1) \
	x(lptree, a0, a1) \
	x(route, a0, a1) \
	x(arp, a0, a1) \
	x(file, a0, a1) \
	x(inet, a0, a1) \
	x(sockbuf, a0, a1) \
	x(tcp, a0, a1)

#define MOD_ENUM(name, a0, a1) MOD_##name,

#define MOD_INIT(name, log, a1) \
	if (rc == 0) { \
		rc = name##_mod_init(log, &(ih)->ih_mods[MOD_##name]); \
	}

#define MOD_ATTACH(name, log, a1) \
	if (rc == 0) { \
		rc = name##_mod_attach(log, (ih)->ih_mods[MOD_##name]); \
	}

#define PROC_INIT(name, log, p) \
	if (rc == 0) { \
		rc = name##_proc_init(log, p); \
	}

#define MOD_DEINIT(name, log, a1) \
	name##_mod_deinit(log, (ih)->ih_mods[MOD_##name]);

#define MOD_DETACH(name, log, a1) \
	name##_mod_detach(log);

enum {
	MOD_FOREACH(MOD_ENUM, 0, 0)
	MOD_COUNT_MAX
};

int proc_type = PROC_TYPE_SERVICE;
struct proc *current;

static struct spinlock service_init_lock;
static struct sysctl_conn *controller_cp;
static struct init_hdr *ih;
static struct proc_mod *curmod;

#define IH_VERSION 2

struct init_hdr {
	int ih_version;
	uint64_t ih_HZ;
	void *ih_mods[MOD_COUNT_MAX];
	union {
		struct proc ih_procs[GT_PROC_COUNT_MAX];
		struct {
			struct proc ih_controller;
			struct proc ih_services[GT_PROC_COUNT_MAX - 1];
		};
	};
	int ih_rss_table_size;
	int ih_rss_table[GT_RSS_NQ_MAX];
};

int
proc_mod_init(struct log *log, void **pp)
{
	int rc;
	struct proc_mod *mod;

	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc == 0) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "proc");
	}
	return rc;
}
int
proc_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

int
proc_proc_init(struct log *log, struct proc *p)
{
	return 0;
}

void
proc_mod_deinit(struct log *log, void *raw_mod)
{
	struct proc_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
proc_mod_detach(struct log *log)
{
	curmod = NULL;
}

static void
mod_foreach_mod_deinit(struct log *log)
{
	MOD_FOREACH(MOD_DEINIT, log, 0);
}

static int
mod_foreach_mod_init(struct log *log)
{
	int rc;

	rc = 0;
	MOD_FOREACH(MOD_INIT, log, 0);
	if (rc) {
		mod_foreach_mod_deinit(log);
	}
	return rc;
}

static void
mod_foreach_mod_detach(struct log *log)
{
	MOD_FOREACH(MOD_DETACH, log, 0);
}

static int
mod_foreach_mod_attach(struct log *log)
{
	int rc;

	ASSERT(current != NULL);
	rc = 0;
	MOD_FOREACH(MOD_ATTACH, log, 0);
	if (rc) {
		mod_foreach_mod_detach(log);
	}
	return rc;
}

static void
mod_foreach_proc_deinit(struct log *log, struct proc *proc)
{
}

static int
mod_foreach_proc_init(struct log *log, struct proc *proc)
{
	int rc;

	rc = 0;
	MOD_FOREACH(PROC_INIT, log, proc);
	if (rc) {
		mod_foreach_proc_deinit(log, proc);
	}
	return rc;
}

void
proc_init()
{
	dlsym_all();
	rdtsc_update_time();
	srand48(time(NULL));
	log_init_early();
}

#define CONTROLLER_LOCK_PATH GT_PREFIX"/controller.lock"

static int
controller_lock(struct log *log)
{
	int rc, fd;

	LOG_TRACE(log);
	rc = sys_open(log, CONTROLLER_LOCK_PATH, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		die(log, -rc, "open('%s') failed;", CONTROLLER_LOCK_PATH);
	}
	fd = rc;
	rc = sys_flock(log, fd, LOCK_EX);
	if (rc < 0) {
		die(log, -rc, "flock('%s') failed", CONTROLLER_LOCK_PATH);
	}
	return fd;
}

static void
controller_unlock(struct log *log, int fd)
{
	sys_close(log, fd);
	sys_unlink(log, CONTROLLER_LOCK_PATH);
}

static int
sleep_compute_HZ()
{
	int rc;
	uint64_t t0, t1, HZ;
	struct timespec ts, rem;

	ts.tv_sec = 0;
	ts.tv_nsec = 10 * 1000 * 1000;
	t0 = rdtsc();
restart:
	rc = nanosleep(&ts, &rem);
	if (rc == -1) {
		if (errno == EINTR) {
			memcpy(&ts, &rem, sizeof(ts));
			goto restart;
		} else {
			return -errno;
		}
	}
	t1 = rdtsc();
	HZ = (t1 - t0) * 100;
	mHZ = HZ / 1000000;
	return 0;
}

static int
can_connect(struct log *log, int pid)
{
	int rc, fd;
	uint64_t to;
	struct sockaddr_un a;

	LOG_TRACE(log);
	rc = sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sysctl_make_sockaddr_un(&a, pid);
	to = 0;
	rc = connect_timed(log, fd, (struct sockaddr *)&a, sizeof(a), &to);
	sys_close(log, fd);
	if (rc == 0 || rc == -ETIMEDOUT) {
		return 1;
	} else {
		sys_unlink(log, a.sun_path);
		return 0;
	}
}

static int
kill_wait_pids(struct log *log)
{
	int i, rc, pid, npids, again;
	uint64_t to;
	int pids[GT_PROC_COUNT_MAX];
	struct sockaddr_un a;
	DIR *dir;
	struct dirent *entry;
	struct pid_wait pw;

	LOG_TRACE(log);
restart:
	again = 0;
	pid_wait_init(log, &pw, PID_WAIT_NONBLOCK);
	rc = sys_opendir(log, &dir, SYSCTL_PATH);
	if (rc) {
		return rc;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.sock", &pid);
		if (rc != 1) {
			continue;
		}
		rc = can_connect(log, pid);
		if (rc < 0) {
			closedir(dir);
			return rc;
		} else if (rc) {
			rc = pid_wait_add(log, &pw, pid);
			if (rc == -ENOSPC) {
				again = 1;
				break;
			} else if (rc < 0) {
				goto out;
			}
		}
	}
	closedir(dir);
	npids = 0;
	to = 3 * NANOSECONDS_SECOND;
	while (to && !pid_wait_is_empty(&pw)) {
		rc = pid_wait_kill(log, &pw, SIGKILL,
		                   pids, ARRAY_SIZE(pids) - npids);
		if (rc < 0) {
			goto out;
		}
		npids += rc;
		rc = pid_wait_read(log, &pw, &to,
		                   pids + npids, ARRAY_SIZE(pids) - npids);
		if (rc > 0) {
			npids += rc;
		}
	}
	for (i = 0; i < npids; ++i) {
		sysctl_make_sockaddr_un(&a, pids[i]);
		sys_unlink(log, a.sun_path);
	}
	if (pid_wait_is_empty(&pw)) {
		rc = 0;
	} else {
		LOGF(log, LOG_ERR, -ETIMEDOUT, "failed;");
		rc = -ETIMEDOUT;
	}
out:
	pid_wait_deinit(log, &pw);
	if (rc == 0 && again) {
		goto restart;
	}
	return rc;
}

// TODO: priority - tx pps
static int
service_priority(struct proc *s)
{
	return 0;
}

static int
service_compar(const void *p1, const void *p2)
{
	int prio1, prio2;
	struct proc **ps1, **ps2;

	ps1 = (struct proc **)p1;
	ps2 = (struct proc **)p2;
	prio1 = service_priority(*ps1);
	prio2 = service_priority(*ps2);
	return prio1 - prio2;
}

static struct proc *
service_get(int pid)
{
	int i;
	struct proc *s;

	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		s = ih->ih_services + i;
		if (s->p_pid == pid) {
			return s;
		}
	}
	return NULL;
}

static void
service_lock(struct log *log, struct proc *s)
{
}

static void
service_unlock(struct proc *s)
{
}


/*static int
rss_table_get(int N)
{
	int n;

	n = READ_ONCE(ih->ih_rss_table_size);
	if (n
}*/

static int
service_activate2(struct log *log, struct proc *s)
{
	int i;

	for (i = 0; i < ih->ih_rss_table_size; ++i) {
		if (ih->ih_rss_table[i] == 0) {
			service_lock(log, s);
			s->p_dirty_devs = 1;
			s->p_rss_qid = i;
			s->p_rss_qid_min = i;
			s->p_rss_qid_max = i;
			service_unlock(s);
			WRITE_ONCE(ih->ih_rss_table[i], s->p_pid);
			break;
		}
	}
	return 0;
}

static void
service_deactivate2(struct log *log, struct proc *s)
{
	if (s->p_rss_qid < 0) {
		return;
	}
}


static void
rss_table_reduce(struct log *log, int n)
{
	int i, N, pid;
	struct proc *s;

	N = ih->ih_rss_table_size;
	WRITE_ONCE(ih->ih_rss_table_size, n);
	for (i = 0; i < N; ++i) {
		pid = ih->ih_rss_table[i];
		if (pid == 0) {
			return;
		}
		s = service_get(pid);
		ASSERT(s != NULL);
		ASSERT(s->p_rss_qid_min == i);
		service_lock(log, s);
		if (i < n) {
			if (s->p_rss_qid_max >= n) {
				s->p_rss_qid_max = n - 1;
			}
		} else {
			WRITE_ONCE(ih->ih_rss_table[i], 0);
			s->p_rss_qid_min = -1;
			s->p_rss_qid_max = -1;
		}
		s->p_dirty_devs = 1;
		service_unlock(s);
	}
}

static void
rss_table_expand(struct log *log, int N)
{
	int i, j, pid, qlen;
	struct proc *s, *q[GT_PROC_COUNT_MAX];

	qlen = 0;
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		s = ih->ih_services + i;
		if (s->p_pid && s->p_active && s->p_rss_qid_min == -1) {
			q[qlen++] = s;
		}
	}
	qsort(q, qlen, sizeof(struct proc *), service_compar);
	for (i = 0; i < N; ++i) {
		pid = ih->ih_rss_table[i];
		if (pid == 0) {
			break;
		}
	}
	for (j = 0; i < N && j < qlen; ++i, ++j) {
		WRITE_ONCE(ih->ih_rss_table[i], q[j]->p_pid);
	}
	for (i = 0; i < N; ++i) {
		pid = ih->ih_rss_table[i];
		if (pid == 0) {
			break;
		}
		s = service_get(pid);
		ASSERT(s != 0);
		service_lock(log, s);
		s->p_rss_qid_min = i;
		if (i < N - 1 && ih->ih_rss_table[i + 1] == 0) {
			s->p_rss_qid_max = N - 1;	
		} else {
			s->p_rss_qid_max = i;
		}
		s->p_dirty_devs = 1;
		service_unlock(s);
	}
	WRITE_ONCE(ih->ih_rss_table_size, N);
}

void
rss_table_update(struct log *log)
{
	int fd, rss_nq_max;
	struct route_if *ifp;

	LOG_TRACE(log);
	rss_nq_max = 0;
	ROUTE_IF_FOREACH(ifp) {
		if (ifp->rif_flags & IFF_UP) {
			if (rss_nq_max < ifp->rif_rss_nq) {
				rss_nq_max = ifp->rif_rss_nq;
			}
		}
	}
	fd = controller_lock(log);
	if (ih->ih_rss_table_size <= rss_nq_max) {
		rss_table_reduce(log, rss_nq_max);
	} else {
		rss_table_expand(log, rss_nq_max);
	}
	controller_unlock(log, fd);
}

static void
service_close(struct log *log, struct proc *s)
{
	service_deactivate2(log, s);
	s->p_pid = 0;
}

static void
controller_service_close(struct log *log, struct sysctl_conn *cp)
{
	int fd, pid;
	struct proc *s;

	pid = cp->sccn_peer_pid;
	if (pid == 0) {
		return;
	}
	LOG_TRACE(log);
	fd = controller_lock(log);
	s = service_get(pid);
	if (s != NULL) {
		service_lock(log, s);
		service_close(log, s);
		service_unlock(s);
	}
	controller_unlock(log, fd);
}

static int
controller_bind(struct log *log, int pid)
{
	int rc, fd;
	struct sockaddr_un a;

	sysctl_add_int(log, SYSCTL_PROC_CONTROLLER_PID, SYSCTL_RD,
	               &ih->ih_controller.p_pid, 0, 0);
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(log, &a, 1);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sysctl_conn_open(log, &controller_cp, fd);
	if (rc) {
		sys_close(log, fd);
		return rc;	
	}
	sys_unlink(log, SYSCTL_CONTROLLER_PATH);
	rc = sys_symlink(log, a.sun_path, SYSCTL_CONTROLLER_PATH);
	if (rc) {
		sysctl_conn_close(log, controller_cp);
	}
	controller_cp->sccn_accept_conn = 1;
	controller_cp->sccn_close_fn = controller_service_close;
	return rc;
}

int
controller_init(int daemonize, const char *proc_name)
{
	int i, rc, pid;
	struct log *log;
	struct proc *proc;

	log = log_trace0();
	if (daemonize) {
		rc = sys_daemon(log, 0, 1);
		if (rc) {
			return rc;
		}
	}
	rc = kill_wait_pids(log);
	if (rc) {
		return rc;
	}
	rc = sysctl_root_init(log);
	if (rc) {
		goto err;
	}
	rc = shm_init(log, (void **)&ih, sizeof(*ih));
	if (rc) {
		goto err;
	}
	memset(ih, 0, sizeof(*ih));
	rc = mod_foreach_mod_init(log);
	if (rc) {
		goto err;
	}
	pid = getpid();
	ih->ih_version = IH_VERSION;
	ih->ih_HZ = sleep_compute_HZ();
	for (i = 0; i < ARRAY_SIZE(ih->ih_procs); ++i) {
		proc = ih->ih_procs + i;
		mod_foreach_proc_init(log, proc);
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		ih->ih_services[i].p_service_id = i;
	}
	current = &ih->ih_controller;
	current->p_pid = pid;
	rc = mod_foreach_mod_attach(log);
	if (rc) {
		goto err;
	}
	sysctl_read_file(log, proc_name);
	rc = controller_bind(log, pid);
	if (rc) {
		goto err;
	}
	LOGF(log, LOG_NOTICE, 0, "ok; pid=%d", pid);
	return 0;
err:
	if (current != NULL) {
		current->p_pid = 0;
		current = NULL;
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_procs); ++i) {
		proc = ih->ih_procs + i;
		mod_foreach_proc_deinit(log, proc);
	}
	mod_foreach_mod_deinit(log);
	mod_foreach_mod_detach(log);
	shm_deinit(log);
	sysctl_root_deinit(log);
	return rc;
}

void
controller_loop()
{
	while (1) {
		gt_fd_event_mod_wait();
	}
}

static int
wait_controller_init(struct log *log, int pipe_fd[2])
{
	int rc, msg;
	uint64_t to;

	to = 4 * NANOSECONDS_SECOND;
	rc = read_timed(log, pipe_fd[0], &msg, sizeof(msg), &to);
	if (rc == 0) {
		LOGF(log, LOG_ERR, 0, "peer closed;");
		rc = -EPIPE;
	} else if (rc == 4) {
		if (msg == 0) {
			rc = 0;
			LOGF(log, LOG_ERR, 0, "ok;");
		} else if (msg > 0) {
			rc = -EINVAL;
			LOGF(log, LOG_ERR, 0, "invalid reply; msg=%d", msg);
		} else {
			rc = msg;
			LOGF(log, LOG_ERR, -rc, "failed;");
		}
	} else if (rc > 0) {
		LOGF(log, LOG_ERR, 0, "truncated reply; len=%d", rc);
		return -EINVAL;
	}
	return 0;
}

static int
fork_controller(struct log *log, const char *proc_name)
{
	int rc, pipe_fd[2];

	LOG_TRACE(log);
	rc = sys_pipe(log, pipe_fd);
	if (rc) {
		return rc;
	}
	rc = sys_fork(log);
	if (rc < 0) {
		return rc;
	} else if (rc == 0) {
		proc_type = PROC_TYPE_CONTROLLER;
		log = log_trace0();
		sys_close(log, pipe_fd[0]);
		rc = controller_init(1, proc_name);
		send_full_buf(log, pipe_fd[1], &rc, sizeof(rc), MSG_NOSIGNAL);
		sys_close(log, pipe_fd[1]);
		if (rc == 0) {
			controller_loop();
		}
		return rc;
	}
	rc = wait_controller_init(log, pipe_fd);
	sys_close(log, pipe_fd[0]);
	sys_close(log, pipe_fd[1]);
	return rc;
}

int
service_attach(struct log *log, int fd, const char *proc_name)
{
	int rc, pid;
	uint64_t to;
	struct sockaddr_un a;

	rc = shm_attach(log, (void **)&ih);
	if (rc) {
		return rc;
	}
	if (ih->ih_version != IH_VERSION) {
		return -EINVAL;
	}
	pid = ih->ih_controller.p_pid;
	sysctl_make_sockaddr_un(&a, pid);
	to = 2 * NANOSECONDS_SECOND;
	rc = connect_timed(log, fd, (struct sockaddr *)&a, sizeof(a), &to);
	if (rc == 0) {
		LOGF(log, LOG_NOTICE, 0, "attached; pid=%d", pid);
	}
	return rc;
}

int
service_init_locked(struct log *log)
{
	int i, rc, fd, pid;
	struct sockaddr_un a;
	char proc_name[PROC_NAME_SIZE_MAX];
	char buf[GT_SYSCTL_BUFSIZ];

	// Check again under the lock
	if (current != NULL) {
		return 0;
	}
	pid = getpid();
	rc = proc_get_name(log, proc_name, pid);
	if (rc) {
		goto err;
	}
	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(log, &a, 0);
	if (rc < 0) {
		goto err;
	}
	fd = rc;
	for (i = 0; i < 3; ++i) {
		if (i == 0) {
			rc = 0;
		} else {
			rc = fork_controller(log, proc_name);
		}
		if (rc == 0) {
			rc = service_attach(log, fd, proc_name);
			if (rc == 0) {
				break;
			}
		}
	}
	if (rc < 0) {
		goto err;
	}
	for (i = 0; i < ARRAY_SIZE(ih->ih_services); ++i) {
		current = ih->ih_services + i;
		if (current->p_pid == 0) {
			break;
		}
	}
	if (current->p_pid) {
		rc = -ENOENT;
		goto err;
	}
	rc = sysctl_req(log, fd, SYSCTL_PROC_CONTROLLER_PID, buf, "");
	if (rc < 0) {
		goto err;
	}
	current->p_pid = pid;
	current->p_service_fd = fd;
	current->p_rss_qid = UCHAR_MAX;
	current->p_rss_qid_min = UCHAR_MAX;
	current->p_rss_qid_max = UCHAR_MAX;
	current->p_dirty_devs = 0;
	strzcpy(current->p_name, proc_name, sizeof(current->p_name));
	rc = mod_foreach_mod_attach(log);
	if (rc) {
		goto err;
	}
	return 0;
err:
	if (fd >= 0) {
		sys_close(log, fd);
		fd = -1;
	}
	if (current != NULL) {
		current->p_pid = 0;
		current = NULL;
	}
	mod_foreach_mod_detach(log);
	shm_detach(log);
	return rc;
}

int
service_init()
{
	int rc, fd;
	struct log *log;

	assert(api_locked == 0);
	api_locked++;
	spinlock_lock(&service_init_lock);
	proc_init();
	ASSERT(current == NULL);
	log = log_trace0();
	LOGF(log, LOG_INFO, 0, "Hit;");
	fd = controller_lock(log);
	rc = service_init_locked(log);
	if (rc) {
		LOGF(log, LOG_ERR, -rc, "failed;");
	} else {
		LOGF(log, LOG_INFO, 0, "ok; current=%p", current);
	}
	controller_unlock(log, fd);
	spinlock_unlock(&service_init_lock);
	api_locked--;
	return rc;
}

int
service_activate(struct log *log)
{
	int rc, fd;

	if (current->p_active) {
		return 0;
	}
	dbg("aaaaaaaa");
	LOG_TRACE(log);
	LOGF(log, LOG_NOTICE, 0, "hit; pid=%d", current->p_pid);
	current->p_active = 1;
	rc = 0;
	if (current->p_rss_qid == UCHAR_MAX) {
		SERVICE_UNLOCK;
		fd = controller_lock(log);
		rc = service_activate2(log, current);
		controller_unlock(log, fd);
		SERVICE_LOCK;
	}
	if (rc == 0) {
		LOGF(log, LOG_NOTICE, 0, "ok; rss_qid=%u", current->p_rss_qid);
	} else {
		LOGF(log, LOG_NOTICE, 0, "failed;");
	}
	return rc;
}

void
service_deactivate(struct log *log)
{
	int fd;

	if (current->p_active) {
		LOG_TRACE(log);
		SERVICE_UNLOCK;
		fd = controller_lock(log);
		service_deactivate2(log, current);
		controller_unlock(log, fd);
		SERVICE_LOCK;
	}
}

static int
service_in(struct route_if *ifp, uint8_t *data, int len)
{
	int rc;
	struct sock_tuple so_tuple;
	struct gt_inet_context ctx;

	rc = gt_inet_eth_in(&ctx, ifp, data, len);
	if (rc == GT_INET_OK &&
	    (ctx.inp_ipproto == IPPROTO_UDP ||
	     ctx.inp_ipproto == IPPROTO_TCP)) {
		so_tuple.sot_laddr = ctx.inp_ip4_h->ip4h_daddr;
		so_tuple.sot_faddr = ctx.inp_ip4_h->ip4h_saddr;
		so_tuple.sot_lport = ctx.inp_udp_h->udph_dport;
		so_tuple.sot_fport = ctx.inp_udp_h->udph_sport;
		rc = gt_sock_in(ctx.inp_ipproto, &so_tuple, &ctx.inp_tcb,
		                ctx.inp_payload);
	} else if (rc == GT_INET_BCAST && 
	           ctx.inp_ipproto == IPPROTO_ICMP && ctx.inp_eno &&
	           (ctx.inp_emb_ipproto == IPPROTO_UDP ||
	            ctx.inp_emb_ipproto == IPPROTO_TCP)) {
		so_tuple.sot_laddr = ctx.inp_emb_ip4_h->ip4h_saddr;
		so_tuple.sot_faddr = ctx.inp_emb_ip4_h->ip4h_daddr;
		so_tuple.sot_lport = ctx.inp_emb_udp_h->udph_sport;
		so_tuple.sot_fport = ctx.inp_emb_udp_h->udph_dport;
		gt_sock_in_err(ctx.inp_emb_ipproto, &so_tuple, ctx.inp_eno);
	}
	return rc;
}

static void
service_if_in(struct route_if *ifp, uint8_t *data, int len)
{
	int rc;
//	struct gt_service_msg msg;

	rc = service_in(ifp, data, len);
	switch (rc) {
	case GT_INET_OK:
	case GT_INET_DROP:
		break;
	case GT_INET_BYPASS:
	case GT_INET_BCAST:
//		msg.svcm_cmd = rc;
//		msg.svcm_if_idx = ifp->rif_idx;
//		memcpy(data + len, &msg, sizeof(msg));
//		len += sizeof(msg);
//		dev_tx3(&gt_service_pipe, data, len);
		break;
	default:
		BUG;
		break;
	}
}

static void
service_rxtx(struct dev *dev, short revents)
{
	int i, n, len;
	void *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
	struct route_if *ifp;

	ifp = dev->dev_ifp;
	DEV_FOREACH_RXRING(rxr, dev) {
		n = dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			//DEV_RX_PREFETCH(rxr);
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			service_if_in(ifp, data, len);
			route_if_rxr_next(ifp, rxr);
		}
	}
}

static void
service_update_dev(struct log *log, struct route_if *ifp, int rss_qid)
{
	int ifflags;
	char dev_name[NM_IFNAMSIZ];
	struct dev *dev;

	ifflags = READ_ONCE(ifp->rif_flags);
	dev = &(ifp->rif_dev[service_id()][rss_qid]);
	if ((ifflags & IFF_UP) &&
	    rss_qid >= current->p_rss_qid_min &&
	    rss_qid <= current->p_rss_qid_max &&
	    !dev_is_inited(dev)) {
		snprintf(dev_name, sizeof(dev_name), "%s-%d",
		         ifp->rif_name, rss_qid);
		dev_init(log, dev, dev_name, service_rxtx);
		dev->dev_ifp = ifp;
	} else {
		dev_deinit(log, dev);
	}
}

void
service_update_devs(struct log *log)
{
	int i;
	struct route_if *ifp;

	LOG_TRACE(log);
	LOGF(log, LOG_INFO, 0, "hit; rss_qid=%u-%u",
	     current->p_rss_qid_min, current->p_rss_qid_max);
	ROUTE_IF_FOREACH(ifp) {
		for (i = 0; i < GT_RSS_NQ_MAX; ++i) {
			service_update_dev(log, ifp, i);
		}
	}
	current->p_dirty_devs = 0;
}
