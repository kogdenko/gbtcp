// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE
#include "subr.h"

static void
verror(int errnum, const char *format, va_list ap)
{
	vfprintf(stderr, format, ap);
	if (errnum) {
		fprintf(stderr, " (%s)\n", strerror(errnum));
	} else {
		fprintf(stderr, "\n");
	}
}

void
errorf(int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	verror(errnum, format, ap);
	va_end(ap);
}

void
die(int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	verror(errnum, format, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

void *
xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		die(0, "malloc(%zu) failed", size);
	}
	return ptr;
}

ssize_t
write_record(int fd, const void *buf, size_t cnt)
{
	ssize_t rc;
	size_t off;

	for (off = 0; off < cnt; off += rc) {
		rc = write(fd, (const u_char *)buf + off, cnt - off);
		if (rc == -1) {
			assert(errno);
			if (errno == EINTR) {
				rc = 0;
			} else if (errno == EAGAIN) {
				break;
			} else {
				return -errno;
			}
		}
	}
	return off;
}

int
read_record(int fd, void *buf, int cnt, int *len)
{
	int rc, n;

	*len = 0;
	while (*len < cnt) {
		n = cnt - *len;
		rc = read(fd, (u_char *)buf + *len, n);
		if (rc == 0) {
			return 0;
		} else if (rc == -1) {
			assert(errno);
			if (errno == EINTR) {
				continue;
			} else if (errno == EAGAIN) {
				break;
			} else {
				return -errno;
			}
		} else {
			*len += rc;
			if (rc < n) {
				break;
			}
		}
	}
	return 1;
}

int
set_affinity2(pthread_t thread, int cpu_id)
{
	int rc;
	cpuset_t cpumask;

	CPU_ZERO(&cpumask);
	CPU_SET(cpu_id, &cpumask);
	rc = pthread_setaffinity_np(thread, sizeof(cpumask), &cpumask);
	if (rc != 0) {
		errorf(rc, "pthread_setaffinity_np(%d) failed", cpu_id);
	}
	return -rc;
}

int
set_affinity(int cpu_id)
{
	return set_affinity2(pthread_self(), cpu_id);
}

static int
cpu_from_string(char *string)
{
	char *endptr;
	int rc;

	rc = strtoul(string, &endptr, 10);
	if (*endptr == '\0') {
		if (rc >= CPU_SETSIZE) {
			return -ERANGE;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

int
cpuset_from_string(cpuset_t *set, char *string)
{
	int i, cpu[2];
	char *range, *delim;

	for (range = strtok(string, ","); range != NULL; range = strtok(NULL, ",")) {
		delim = strchr(range, '-');
		if (delim == NULL) {
			cpu[0] = cpu[1] = cpu_from_string(range);
		} else {
			*delim = '\0';
			cpu[0] = cpu_from_string(range);
			cpu[1] = cpu_from_string(delim + 1);
		}
		for (i = 0; i < 2; ++i) {
			if (cpu[i] < 0) {
				return cpu[i];
			}
		}
		if (cpu[0] > cpu[1]) {
			return -EINVAL;
		}
		for (i = cpu[0]; i <= cpu[1]; ++i) {
			CPU_SET(i, set);
		}
	}
	return 0;
}
