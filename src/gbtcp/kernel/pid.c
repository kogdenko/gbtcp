// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/pid.h>
#include <gbtcp/kernel/sys.h>

#define gt_err(...) gt_err3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_warning(...) gt_warning3(&gt_main->infra_logger, ##__VA_ARGS__)

int
pid_file_open(const char *path)
{
	int fd, rc;
	//struct stat buf;

	rc = sys_open(path, O_CREAT | O_RDWR, 0666);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	//fchgrp(fd, &buf, GT_GROUP_NAME);
	return fd;
}

int
pid_file_lock(int fd)
{
	int rc;

	rc = sys_flock(fd, LOCK_EX | LOCK_NB);
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
		gt_err(0, "Bad pidfile format");
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

	assert(pid >= 0);
	len = snprintf(buf, sizeof(buf), "%d", pid);
	rc = gt_write_all(fd, buf, len);
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
			gt_warning(0, "Pidfile locked (pid=%d)", rc);
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
