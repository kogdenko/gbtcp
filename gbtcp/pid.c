#include "internals.h"

struct pid_mod {
	struct log_scope log_scope;
};

static struct pid_mod *curmod;

int
pid_mod_init(void **pp)
{
	int rc;
	struct pid_mod *mod;

	rc = shm_malloc(pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "pid");
	}
	return rc;
}

int
pid_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
pid_mod_deinit(void *raw_mod)
{
	struct pid_mod *mod;

	mod = raw_mod;
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
pid_mod_detach()
{
	curmod = NULL;
}

char *
pid_file_path(char *path, const char *filename)
{
	snprintf(path, PATH_MAX, "%s/%s", PID_PATH, filename);
	return path;
}

int
pid_file_open(const char *filename)
{
	int rc;
	char path[PATH_MAX];

	pid_file_path(path, filename);
	rc = sys_open(path, O_CREAT|O_RDWR, 0666);
	if (rc >= 0) {
		NOTICE(0, "ok; fd=%d, filename='%s'", rc, filename);
	}
	return rc;
}

int
pid_file_lock(int fd)
{
	int rc;

	rc = sys_flock(fd, LOCK_EX|LOCK_NB);
	return rc;
}

int
pid_file_read(int fd)
{
	int rc, pid;
	char buf[32];

	rc = sys_read(fd, buf, sizeof(buf) - 1);
	if (rc < 0) {
		return rc;
	}
	buf[rc] = '\0';
	rc = sscanf(buf, "%d", &pid);
	if (rc != 1 || pid <= 0) {
		ERR(0, "bad format; fd=%d", fd);
		return -EINVAL;
	} else {
		return pid;
	}
}

int
pid_file_write(int fd, int pid)
{
	int rc, len;
	char buf[32];

	ASSERT(pid >= 0);
	len = snprintf(buf, sizeof(buf), "%d", pid);
	rc = write_full_buf(fd, buf, len);
	return rc;
}

int
pid_file_acquire(int fd, int pid)
{
	int rc;

	rc = pid_file_lock(fd);
	if (rc == -EWOULDBLOCK) {
		rc = pid_file_read(fd);
		if (rc >= 0) {
			WARN(0, "busy; fd=%d, pid=%d", fd, rc);
		}
		return rc;
	} else if (rc < 0) {
		return rc;
	}
	rc = pid_file_write(fd, pid);
	if (rc) {
		return rc;
	}
	return pid;
}

int
pid_wait_init(struct pid_wait * pw, int flags)
{
	pw->pw_nentries = 0;
	pw->pw_fd = sys_inotify_init1(flags);
	return pw->pw_fd;
}

void
pid_wait_deinit(struct pid_wait* pw)
{
	if (pw->pw_fd >= 0) {
		sys_close(pw->pw_fd);
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
pid_wait_add(struct pid_wait *pw, int pid)
{
	int i, rc;
	char path[32];

	ASSERT(pw->pw_fd >= 0);
	for (i = 0; i < pw->pw_nentries; ++i) {
		if (pw->pw_entries[i].pid == pid) {
			rc = -EEXIST;
			goto err;
		}
	}
	if (pw->pw_nentries == GT_SERVICE_COUNT_MAX) {
		rc = -ENOSPC;
		goto err;
	}
	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	rc = sys_inotify_add_watch(pw->pw_fd, path,
	                           IN_CLOSE_NOWRITE|IN_ONESHOT);
	if (rc >= 0) {
		pw->pw_entries[pw->pw_nentries].pid = pid;
		pw->pw_entries[pw->pw_nentries].wd = rc;
		pw->pw_nentries++;
	}
	return rc;
err:
	ERR(-rc, "failed; pw_fd=%d, pid=%d", pw->pw_fd, pid);
	return rc;
}

static int 
pid_wait_del_entry(struct pid_wait *pw, int i)
{
	int rc;
	struct pid_wait_entry *e;

	e = pw->pw_entries + i;
	rc = sys_inotify_rm_watch(pw->pw_fd, e->wd);
	*e = pw->pw_entries[--pw->pw_nentries];
	return rc;
}

int
pid_wait_del(struct pid_wait *pw, int pid)
{
	int i, rc;

	for (i = 0; i < pw->pw_nentries; ++i) {
		if (pw->pw_entries[i].pid == pid) {
			rc = pid_wait_del_entry(pw, i);
			return rc;
		}
	}
	rc = -ENOENT;
	ERR(-rc, "failed; wp_fd=%d", pw->pw_fd);
	return rc;
}

int
pid_wait_read(struct pid_wait *pw, uint64_t *to, int *pids, int npids)
{
	int i, n, rc;
	struct inotify_event ev;

	ASSERT(npids);
	n = 0;
	while (!pid_wait_is_empty(pw)) {
		rc = read_timed(pw->pw_fd, &ev, sizeof(ev), to);
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
				pid_wait_del_entry(pw, i);
				break;
			}
		}
	}
	return n;
}

int
pid_wait_kill(struct pid_wait *pw, int signum, int *pids, int npids)
{
	int i, n, rc, pid;

	n = 0;
	for (i = 0; i < pw->pw_nentries;) {
		pid = pw->pw_entries[i].pid;
		rc = sys_kill(pid, signum);
		if (rc == -ESRCH) {
			if (n < npids) {
				pids[n] = pid;
			}
			n++;
			pid_wait_del_entry(pw, i);	
		} else if (rc < 0) {
			return rc;
		} else {
			++i;
		}
	}
	return n;
}
