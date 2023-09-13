// SPDX-License-Identifier: LGPL-2.1-only

#include "controller.h"
#include "fd_event.h"
#include "pid.h"
#include "shm.h"

static struct sysctl_conn *controller_conn;
static int controller_pid_fd = -1;
static int sid_max = 0;
static int controller_done;

static struct service *
service_get_by_pid(int pid)
{
	int i;

	for (i = 0; i <= sid_max; ++i) {
		if (shared->shm_services[i].p_pid == pid) {
			return shared->shm_services + i;
		}
	}
	return NULL;
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

static int
controller_clean_kill(int fd)
{
	int rc, pid;

	rc = pid_file_acquire(fd, 0);
	if (rc <= 0) {
		return rc;
	}
	pid = rc;
	rc = sys_kill(pid, SIGKILL);
	if (rc == 0) {
		rc = sys_flock(fd, LOCK_EX);
		if (rc < 0) {
			return rc;
		}
	} else if (rc == -ESRCH) {
		rc = 0;
	}
	return rc;
}

static int
controller_clean(void)
{
	int rc, fd, id;
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *entry;

	rc = sys_opendir(&dir, PID_PATH);
	if (rc) {
		return rc;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.pid", &id);
		if (rc != 1 || id == CONTROLLER_SID) {
			continue;
		}
		snprintf(path, sizeof(path), "%s/%s", PID_PATH, entry->d_name);
		rc = pid_file_open(path);
		if (rc < 0) {
			sys_closedir(dir);
			return rc;
		}
		fd = rc;
		rc = controller_clean_kill(fd);
		if (rc) {
			sys_closedir(dir);
			return rc;
		}
		sys_unlink(path);
	}
	sys_closedir(dir);
	rc = sys_opendir(&dir, SYSCTL_SOCK_PATH);
	if (rc) {
		return rc;
	}
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.sock", &id);
		if (rc == 1) {
			snprintf(path, sizeof(path), "%s/%s", SYSCTL_SOCK_PATH, entry->d_name);
			sys_unlink(path);
		}
	}
	sys_closedir(dir);
	return 0;
}

static void
controller_lock_service(struct service *s)
{
	int rc;

	rc = spinlock_trylock(&s->p_lock);
	if (rc == 0) {
		GT_ERR(CONTROLLER, 0, "Sevice DEADLOCK, pid=%d", s->p_pid);
		exit(69);
	}
}

static void
controller_lock_service_safe(struct service *s)
{
	int i, b, rc;

	while (1) {
		for (i = 0; i < 1000; ++i) {
			rc = spinlock_trylock(&s->p_lock);
			if (rc) {
				return;
			}
			cpu_pause();
		}
		rc = sys_recv(s->p_fd, &b, sizeof(b), MSG_PEEK|MSG_DONTWAIT);
		if (rc == 0 || (rc < 0 && rc != -EAGAIN)) {
			// connection closed - service not running
			controller_lock_service(s);
			return;
		}
	}
}

static void
controller_unlock_service(struct service *s)
{
	spinlock_unlock(&s->p_lock);
}

static void
controller_check_service_deadlock(struct service *s)
{
	controller_lock_service(s);
	controller_unlock_service(s);	
}

static void
update_rss_bindings(struct service *s)
{
	if (s == current) {
		service_update_rss_bindings();
	} else {
		controller_lock_service_safe(s);
		s->p_need_update_rss_bindings = 1;
		controller_unlock_service(s);
	}
}

static void
controller_sched_alg(struct service **ppick, struct service **pkick)
{
	int i;
	struct service *s, *pick, *kick;
	
	pick = kick = NULL;
	for (i = 1; i <= sid_max; ++i) {
		s = shared->shm_services + i;
		if (s->p_pid) {
			if (pick == NULL ||
			    pick->p_rss_nq > s->p_rss_nq) {
				pick = s;
			}
			if (kick == NULL ||
			    kick->p_rss_nq < s->p_rss_nq) {
				kick = s;
			}
		}
	}
	if (pick == NULL) {
		pick = current;
	}
	if (kick == NULL || current->p_rss_nq) {
		kick = current;
	} else {
		if (kick->p_rss_nq <= pick->p_rss_nq + 1 &&
		    kick->p_start_time >= pick->p_start_time) {
			// do not preempt
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
set_rss_binding(u_int rss_qid, int sid)
{
	int old_sid;

	assert(rss_qid < GT_RSS_NQ_MAX);
	assert(sid == SERVICE_ID_INVALID || sid < GT_SERVICES_MAX);
	old_sid = shared->shm_rss_table[rss_qid];
	if (old_sid == sid) {
		return;
	}
	if (old_sid != SERVICE_ID_INVALID) {
		GT_NOTICE(CONTROLLER, 0, "Unbind tx/rx queue (%d) from service (pid=%d)",
			rss_qid, shared->shm_services[old_sid].p_pid);
	}
	if (sid != SERVICE_ID_INVALID) {
		GT_NOTICE(CONTROLLER, 0, "Bind tx/rx queue (%d) to service (pid=%d)",
			rss_qid, shared->shm_services[sid].p_pid);
	}
	WRITE_ONCE(shared->shm_rss_table[rss_qid], sid);
}

static void
controller_sched_balance(void)
{
	int i;
	struct service *pick, *kick;

	controller_sched_alg(&pick, &kick);
	if (pick == current ||
	    pick == kick ||
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
	int i, sid, rss_nq, service_num;
	struct sockaddr_un a;
	struct service *new;

	GT_NOTICE(CONTROLLER, 0, "Delete service (pid=%d)", s->p_pid);
	sid = s->p_sid;
	rss_nq = s->p_rss_nq;
	controller_check_service_deadlock(s);
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
	sysctl_make_sockaddr_un(&a, s->p_pid);
	sys_unlink(a.sun_path);
	service_deinit_shared(s, 0);
	service_num = 0;
	SERVICE_FOREACH(s) {
		if (s->p_pid != 0 && s->p_pid != current->p_pid) {
			service_num++;	
		}
	}
	if (service_num == 0) {
		controller_done = 1;
	}
}

static void
controller_add_service(struct service *s, int pid, struct sysctl_conn *cp)
{
	int fd;

	assert(s != current);
	fd = sysctl_conn_fd(cp);
	GT_NOTICE(CONTROLLER, 0, "Add service process (pid=%d), fd=%d", pid, fd);
	service_init_shared(s, pid, fd);
	sid_max = MAX(sid_max, s->p_sid);
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
	} else if (shared->shm_rss_table_size < rss_table_size)  {
		rss_table_expand(rss_table_size);
	}
	if (current->p_rss_nq) {
		update_rss_bindings(current);
	}
	for (i = 0; i <= sid_max; ++i) {
		s = shared->shm_services + i;
		if (s->p_pid && s->p_rss_nq) {
			update_rss_bindings(s);
		}
	}
}

static int
sysctl_controller_add(struct sysctl_conn *cp, void *udata, const char *new, struct strbuf *old)
{
	int i, pid;
	char *endptr;
	struct service *s;

	if (new == NULL) {
		return 0;
	}
	if (cp == NULL) {
		return -EPERM;
	}
	pid = strtoul(new, &endptr, 10);
	if (pid == 0 || *endptr != '\0')
		return -EINVAL;
	s = service_get_by_pid(pid);
	if (s != NULL) {
		return -EEXIST;
	}
	for (i = 0; i < ARRAY_SIZE(shared->shm_services); ++i) {
		s = shared->shm_services + i;
		if (s->p_pid == 0) {
			controller_add_service(s, pid, cp);
			cp->scc_udata = s;
			return 0;
		}
	}
	return -ENOENT;
}

static int
sysctl_controller_service_list_next(void *udata, const char *ident, struct strbuf *out)
{
	int i;

	if (ident == NULL) {
		i = 0;
	} else {
		i = strtoul(ident, NULL, 10) + 1;
	}
	for (; i < ARRAY_SIZE(shared->shm_services); ++i) {
		if (shared->shm_services[i].p_pid) {
			strbuf_addf(out, "%d", i);
			return 0;
		}
	}
	return -ENOENT;
}

static int
sysctl_controller_service_list(void *udata, const char *ident,
	const char *new, struct strbuf *out)
{
	int i;
	u_int okpps;
	struct service *s;

	if (ident == NULL) {
		i = 0;
	} else {
		i = strtoul(ident, NULL, 10);
	}
	if (i >= ARRAY_SIZE(shared->shm_services)) {
		return -ENOENT;
	}
	s = shared->shm_services + i;
	if (!s->p_pid) {
		return -ENOENT;
	} else {
		okpps = READ_ONCE(s->p_okpps);
		strbuf_addf(out, "%d,%d,%u", s->p_pid, s->p_rss_nq, okpps);
		return 0;
	}
}

static void
service_conn_close(struct sysctl_conn *cp)
{
	struct service *s;

	s = cp->scc_udata;
	if (s != NULL) {
		controller_del_service(s);
	}
}

static int
controller_bind(int pid)
{
	int rc, fd;
	struct sockaddr_un a;

	sysctl_make_sockaddr_un(&a, pid);
	rc = sysctl_bind(&a);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sys_listen(fd, GT_SERVICES_MAX);
	if (rc) {
		sys_close(fd);
		return rc;
	}
	rc = sysctl_conn_open(&controller_conn, fd);
	if (rc) {
		sys_close(fd);
		return rc;	
	}
	sys_unlink(SYSCTL_CONTROLLER_PATH);
	rc = sys_symlink(a.sun_path, SYSCTL_CONTROLLER_PATH);
	if (rc) {
		sysctl_conn_close(controller_conn);
		controller_conn = NULL;
		return rc;
	}
	controller_conn->scc_accept_conn = 1;
	controller_conn->scc_close_fn = service_conn_close;
	return 0;
}

static void
controller_unbind(int pid)
{
	struct sockaddr_un a;

	if (controller_conn != NULL) {
		sysctl_conn_close(controller_conn);
		controller_conn = NULL;
		sysctl_make_sockaddr_un(&a, pid);
		sys_unlink(a.sun_path);
		sys_unlink(SYSCTL_CONTROLLER_PATH);
	}
}

int
gt_controller_init(int daemonize)
{
	int i, rc, pid;
	uint64_t hz;

	gt_init();
	gt_preload_passthru = 1;
	shared = NULL;
	if (daemonize) {
		rc = sys_daemon(1, 1);
		if (rc) {
			goto err;
		}
	}
	pid = getpid();
	rc = service_pid_file_acquire(CONTROLLER_SID, pid);
	if (rc < 0) {
		goto err;
	}
	controller_pid_fd = rc;
	rc = controller_clean();
	if (rc) {
		goto err;
	}
	rc = sysctl_root_init();
	if (rc) {
		goto err;
	}
	rc = shm_init();
	if (rc) {
		goto err;
	}
	hz = sleep_compute_hz();
	set_hz(hz);
	shared->shm_hz = hz;
	shared->shm_rss_table_size = 0;
	rc = sysctl_read_file(1);
	if (rc) {
		goto err;
	}
	for (i = 0; i < ARRAY_SIZE(shared->shm_rss_table); ++i) {
		shared->shm_rss_table[i] = SERVICE_ID_INVALID;
	}
	current = shared->shm_services + CONTROLLER_SID;
	rc = service_init_shared(current, pid, 0);
	if (rc) {
		goto err;
	}
	rc = service_init_private();
	if (rc) {
		goto err;
	}
	rc = controller_bind(pid);
	if (rc) {
		goto err;
	}
	rc = sysctl_read_file(0);
	if (rc) {
		goto err;
	}
	sysctl_add(SYSCTL_CONTROLLER_ADD, SYSCTL_WR, NULL, NULL, sysctl_controller_add);
	sysctl_add_list(GT_SYSCTL_CONTROLLER_SERVICE_LIST, SYSCTL_RD, NULL,
		sysctl_controller_service_list_next, sysctl_controller_service_list);
	GT_NOTICE(CONTROLLER, 0, "Controller initialized");
	return 0;
err:
	GT_ERR(CONTROLLER, -rc, "Controller initialization failed");
	gt_controller_deinit();
	return rc;
}

void
gt_controller_deinit(void)
{
	int pid;

	GT_NOTICE(CONTROLLER, 0, "Controller shutdown");
	pid = getpid();
	controller_unbind(pid);
	if (current != NULL) {
		service_deinit_private();
		service_deinit_shared(current, 1);
		current = NULL;
	}
	shm_deinit();
	sysctl_root_deinit();
	sys_close(controller_pid_fd);
	controller_pid_fd = -1;
}

void
controller_process(void)
{
	rd_nanoseconds();
	WRITE_ONCE(shared->shm_ns, nanoseconds);
	wait_for_fd_events();
	if (1)
		controller_sched_balance();
}

void
gt_controller_start(int persist)
{
	while (!controller_done || persist) {
		controller_process();
	}
	gt_controller_deinit();
}
