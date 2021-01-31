// GPL v2
#include "internals.h"

#define CURMOD pid

int
pid_file_open(const char *path)
{
	int fd, rc;
	struct stat buf;

	rc = sys_open(path, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	fchgrp(fd, &buf, GT_GROUP_NAME);
	return fd;
}

int
pid_file_lock(int fd, int block)
{
	int rc, op;

	op = LOCK_EX;
	if (!block) {
		op |= LOCK_NB;
	}
	rc = sys_flock(fd, op);
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
	if (rc != 1) {
		// TODO: err log
		return -EINVAL;
	}
	return pid;
}

int
pid_file_write(int fd, int pid)
{
	int rc, len;
	char buf[32];

	assert(pid >= 0);
	len = snprintf(buf, sizeof(buf), "%d", pid);
	rc = write_record(fd, buf, len);
	return rc;
}

int
pid_file_acquire(const char *path, int pid, int block)
{
	int rc, fd;

	rc = pid_file_open(path);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = pid_file_lock(fd, block);
	if (rc) {
		return rc;
	}
	rc = pid_file_write(fd, pid);
	return fd;
}
