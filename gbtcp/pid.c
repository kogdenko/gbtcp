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
pidfile_path(char *path, const char *filename)
{
	snprintf(path, PATH_MAX, "%s/pid/%s", GT_PREFIX, filename);
	return path;
}

int
pidfile_open(struct log *log, struct pidfile *pf)
{
	int rc;
	char path[PATH_MAX];

	LOG_TRACE(log);
	pidfile_path(path, pf->pf_name);
	rc = sys_open(log, path, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		return rc;
	}
	pf->pf_fd = rc;
	return 0;
}

int
pidfile_lock(struct log *log, struct pidfile *pf)
{
	int rc;

	LOG_TRACE(log);	
	rc = sys_flock(log, pf->pf_fd, LOCK_EX|LOCK_NB);
	return rc;
}

int
pidfile_read(struct log *log, struct pidfile *pf)
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
		LOGF(log, LOG_ERR, 0, "pidfile='%s' bad format",
		     pidfile_path(path, pf->pf_name));
		return -EINVAL;
	} else {
		return pid;
	}
}

int
pidfile_write(struct log *log, struct pidfile *pf, int pid)
{
	int rc, len;
	char buf[32];

	LOG_TRACE(log);
	len = snprintf(buf, sizeof(buf), "%d", pid);
	rc = write_all(log, pf->pf_fd, buf, len);
	return rc;
}
void
pidfile_close(struct log *log, struct pidfile *pf)
{
	if (pf->pf_fd >= 0) {
		LOG_TRACE(log);
		sys_close(log, pf->pf_fd);
		pf->pf_fd = -1;
	}
}

int
read_pidfile(struct log *log, const char * filename)
{
	int rc;
	struct pidfile pf;

	pf.pf_name = filename;
	rc = pidfile_open(log, &pf);
	if (rc) {
		return rc;
	}
	rc = pidfile_lock(log, &pf);
	if (rc == -EWOULDBLOCK) {
		rc = pidfile_read(log, &pf);
	}
	pidfile_close(log, &pf);
	return rc;
}

int
write_pidfile(struct log * log, const char *filename, int pid)
{
	int rc;
	struct pidfile pf;

	pf.pf_name = filename;
	rc = pidfile_open(log, &pf);
	if (rc) {
		return rc;
	}
	rc = pidfile_lock(log, &pf);
	if (rc) {
		return rc;
	}
	rc = pidfile_write(log, &pf, pid);
	if (rc) {
		return rc;
	}
	return pf.pf_fd;
}

int
pidwait_init(struct log *log, struct pidwait * pw, int flags)
{
	LOG_TRACE(log);
	pw->pw_nentries = 0;
	pw->pw_fd = sys_inotify_init1(log, flags);
	return pw->pw_fd;
}

void
pidwait_deinit(struct log *log, struct pidwait* pw)
{
	if (pw->pw_fd >= 0) {
		LOG_TRACE(log);
		sys_close(log, pw->pw_fd);
		pw->pw_fd = -1;
		pw->pw_nentries = 0;
	}
}

int
pidwait_is_empty(struct pidwait *pw)
{
	return pw->pw_nentries == 0;
}

int
pidwait_add(struct log *log, struct pidwait *pw, int pid)
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
	if (pw->pw_nentries == PIDWAIT_NENTRIES_MAX) {
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
pidwait_del_entry(struct log *log, struct pidwait *pw, int i)
{
	int rc;
	struct pidwait_entry *e;

	e = pw->pw_entries + i;
	rc = sys_inotify_rm_watch(log, pw->pw_fd, e->wd);
	*e = pw->pw_entries[--pw->pw_nentries];
	return rc;
}

int
pidwait_del(struct log *log, struct pidwait *pw, int pid)
{
	int i, rc;

	LOG_TRACE(log);
	for (i = 0; i < pw->pw_nentries; ++i) {
		if (pw->pw_entries[i].pid == pid) {
			rc = pidwait_del_entry(log, pw, i);
			return rc;
		}
	}
	rc = -ENOENT;
	LOGF(log, LOG_ERR, -rc, "failed; wp_fd=%d", pw->pw_fd);
	return rc;
}

int
pidwait_read(struct log *log, struct pidwait *pw, uint64_t *to,
	int *pids, int npids)
{
	int i, n, rc;
	struct inotify_event ev;

	ASSERT(npids);
	LOG_TRACE(log);
	n = 0;
	if (pidwait_is_empty(pw)) {
		return 0;
	}
	while (1) {
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
				pidwait_del_entry(log, pw, i);
				break;
			}
		}
	}
}

int
pidwait_kill(struct log *log, struct pidwait *pw, int signum,
	int *pids, int npids)
{
	int i, n, rc, pid;

	LOG_TRACE(log);
	n = 0;
	for (i = 0; i < pw->pw_nentries;) {
		pid = pw->pw_entries[i].pid;
		rc = sys_kill(log, pid, signum);
		if (rc == ESRCH) {
			if (n < npids) {
				pids[n] = pid;
			}
			n++;
			pidwait_del_entry(log, pw, i);	
		} else {
			++i;
		}
	}
	return n;
}
