#include "internals.h"

struct pid_mod {
	struct log_scope log_scope;
};

static struct pid_mod *curmod;

int
pid_mod_init(struct log *log, void **pp)
{
	int rc;
	struct pid_mod *mod;

	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "pid");
	}
	return rc;
}

int
pid_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

int
pid_proc_init(struct log *log, struct proc *p)
{
	return 0;
}

void
pid_mod_deinit(struct log *log, void *raw_mod)
{
	struct pid_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
pid_mod_detach(struct log *log)
{
	curmod = NULL;
}

char *
pid_file_path(char *path, const char *filename)
{
	snprintf(path, PATH_MAX, "%s/pid/%s", GT_PREFIX, filename);
	return path;
}

int
pid_file_open(struct log *log, struct pid_file *pf)
{
	int rc;
	char path[PATH_MAX];

	LOG_TRACE(log);
	pid_file_path(path, pf->pf_name);
	rc = sys_open(log, path, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		return rc;
	}
	pf->pf_fd = rc;
	return 0;
}

int
pid_file_lock(struct log *log, struct pid_file *pf)
{
	int rc;

	LOG_TRACE(log);	
	rc = sys_flock(log, pf->pf_fd, LOCK_EX|LOCK_NB);
	return rc;
}

int
pid_file_read(struct log *log, struct pid_file *pf)
{
	int rc, pid;
	char buf[32];
	char path[PATH_MAX];

	LOG_TRACE(log);
	rc = sys_read(log, pf->pf_fd, buf, sizeof(buf) - 1);
	if (rc < 0) {
		return rc;
	}
	buf[rc] = '\0';
	rc = sscanf(buf, "%d", &pid);
	if (rc != 1 || pid <= 0) {
		LOGF(log, LOG_ERR, 0, "bad format; pid_file='%s'",
		     pid_file_path(path, pf->pf_name));
		return -EINVAL;
	} else {
		return pid;
	}
}

int
pid_file_write(struct log *log, struct pid_file *pf, int pid)
{
	int rc, len;
	char buf[32];

	LOG_TRACE(log);
	ASSERT(pid > 0);
	len = snprintf(buf, sizeof(buf), "%d", pid);
	rc = write_full_buf(log, pf->pf_fd, buf, len);
	return rc;
}

int
pid_file_acquire(struct log * log, struct pid_file *pf, int pid)
{
	int rc;

	rc = pid_file_lock(log, pf);
	if (rc == -EWOULDBLOCK) {
		rc = pid_file_read(log, pf);
		return rc;
	} else if (rc < 0) {
		return rc;
	}
	rc = pid_file_write(log, pf, pid);
	if (rc) {
		return rc;
	}
	return pid;
}

void
pid_file_close(struct log *log, struct pid_file *pf)
{
	if (pf->pf_fd >= 0) {
		LOG_TRACE(log);
		sys_close(log, pf->pf_fd);
		pf->pf_fd = -1;
	}
}

int
pid_wait_init(struct log *log, struct pid_wait * pw, int flags)
{
	LOG_TRACE(log);
	pw->pw_nentries = 0;
	pw->pw_fd = sys_inotify_init1(log, flags);
	return pw->pw_fd;
}

void
pid_wait_deinit(struct log *log, struct pid_wait* pw)
{
	if (pw->pw_fd >= 0) {
		LOG_TRACE(log);
		sys_close(log, pw->pw_fd);
		pw->pw_fd = -1;
		pw->pw_nentries = 0;
	}
}

int
pid_wait_is_empty(struct pid_wait *pw)
{
	return pw->pw_nentries == 0;
}

int
pid_wait_add(struct log *log, struct pid_wait *pw, int pid)
{
	int i, rc;
	char path[32];

	LOG_TRACE(log);
	ASSERT(pw->pw_fd >= 0);
	for (i = 0; i < pw->pw_nentries; ++i) {
		if (pw->pw_entries[i].pid == pid) {
			rc = -EEXIST;
			goto err;
		}
	}
	if (pw->pw_nentries == GT_PROC_COUNT_MAX) {
		rc = -ENOSPC;
		goto err;
	}
	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	rc = sys_inotify_add_watch(log, pw->pw_fd, path,
	                           IN_CLOSE_NOWRITE|IN_ONESHOT);
	if (rc >= 0) {
		pw->pw_entries[pw->pw_nentries].pid = pid;
		pw->pw_entries[pw->pw_nentries].wd = rc;
		pw->pw_nentries++;
	}
	return rc;
err:
	LOGF(log, LOG_ERR, -rc, "failed; pw_fd=%d, pid=%d", pw->pw_fd, pid);
	return rc;
}

static int 
pid_wait_del_entry(struct log *log, struct pid_wait *pw, int i)
{
	int rc;
	struct pid_wait_entry *e;

	e = pw->pw_entries + i;
	rc = sys_inotify_rm_watch(log, pw->pw_fd, e->wd);
	*e = pw->pw_entries[--pw->pw_nentries];
	return rc;
}

int
pid_wait_del(struct log *log, struct pid_wait *pw, int pid)
{
	int i, rc;

	LOG_TRACE(log);
	for (i = 0; i < pw->pw_nentries; ++i) {
		if (pw->pw_entries[i].pid == pid) {
			rc = pid_wait_del_entry(log, pw, i);
			return rc;
		}
	}
	rc = -ENOENT;
	LOGF(log, LOG_ERR, -rc, "failed; wp_fd=%d", pw->pw_fd);
	return rc;
}

int
pid_wait_read(struct log *log, struct pid_wait *pw, uint64_t *to,
	int *pids, int npids)
{
	int i, n, rc;
	struct inotify_event ev;

	ASSERT(npids);
	LOG_TRACE(log);
	n = 0;
	while (!pid_wait_is_empty(pw)) {
		rc = read_timed(log, pw->pw_fd, &ev, sizeof(ev), to);
		if (rc < 0) {
			return n ? n : rc;
		}
		ASSERT(rc == sizeof(ev));
		for (i = 0; i < pw->pw_nentries; ++i) {
			if (pw->pw_entries[i].wd == ev.wd) {
				if (n < npids) {
					pids[n] = pw->pw_entries[i].pid;
				}
				n++;
				pid_wait_del_entry(log, pw, i);
				break;
			}
		}
	}
	return n;
}

int
pid_wait_kill(struct log *log, struct pid_wait *pw, int signum,
	int *pids, int npids)
{
	int i, n, rc, pid;

	LOG_TRACE(log);
	n = 0;
	for (i = 0; i < pw->pw_nentries;) {
		pid = pw->pw_entries[i].pid;
		rc = sys_kill(log, pid, signum);
		if (rc == -ESRCH) {
			if (n < npids) {
				pids[n] = pid;
			}
			n++;
			pid_wait_del_entry(log, pw, i);	
		} else if (rc < 0) {
			return rc;
		} else {
			++i;
		}
	}
	return n;
}
