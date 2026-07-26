// SPDX-License-Identifier: LGPL-2.1-only

#include "gtt_subr.h"
#include "gtt_pid.h"

char *
gtt_pid_file_get_path(char *path, const char *pname, int port)
{
	snprintf(path, PATH_MAX, "/var/run/%s-%d.pid", pname, port);
	return path;
}

int
gtt_pid_file_open(const char *path)
{
	int rc;

	rc = open(path, O_CREAT | O_RDWR, 0666);
	if (rc == -1) {
		gtt_die(errno, "pid: open('%s') failed", path);
	}
	return rc;
}

int
gtt_pid_file_lock(int fd, bool nonblock)
{
	int rc, flags;

	flags = LOCK_EX;
	if (nonblock) {
		flags |= LOCK_NB;
	}
	rc = flock(fd, flags);
	if (rc == -1) {
		if (errno != EWOULDBLOCK) {
			gtt_die(errno, "pid: flock() failed");
		} else {
			rc = -errno;
		}
	}
	return rc;
}

int
gtt_pid_file_read(int fd)
{
	int rc, pid;
	char buf[32];

	rc = read(fd, buf, sizeof(buf) - 1);
	if (rc == -1) {
		gtt_die(errno, "pid: read() failed");
	}
	buf[rc] = '\0';
	rc = sscanf(buf, "%d", &pid);
	if (rc != 1 || pid <= 0) {
		gtt_die(0, "pid: Bad file format");
	}
	return pid;
}

int
gtt_pid_file_write(int fd, unsigned int pid)
{
	int rc, len;
	char buf[32];

	len = snprintf(buf, sizeof(buf), "%d", pid);
	rc = gtt_write_record(fd, buf, len);
	if (rc < 0) {
		gtt_die(-rc, "pid: write() failed");
	}
	return rc;
}

int
gtt_pid_file_acquire(int fd, unsigned int pid)
{
	int rc;

	rc = gtt_pid_file_lock(fd, true);
	if (rc < 0) {
		return rc;
	}
	gtt_pid_file_write(fd, pid);
	return pid;
}
