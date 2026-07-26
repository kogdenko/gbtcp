// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_TOOLS_COMMON_SUBR_H
#define GBTCP_TOOLS_COMMON_SUBR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/epoll.h>
typedef cpu_set_t gtt_cpuset_t;
#else // __linux__
#include <pthread_np.h>
#include <sys/event.h>
typedef cpuset_t gtt_cpuset_t;
#endif // __linux__

#define GTT_ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define GTT_UNUSED(x) ((void)(x))

#define gtt_dbg(fmt, ...) \
	do { \
		printf("%-20s %-5d %-20s: ", __FILE__, __LINE__, __func__); \
		printf(fmt, ##__VA_ARGS__); \
		printf("\n"); \
	} while (0)

void gtt_errorf(int errnum, const char *, ...)
	__attribute__((format(printf, 2, 3)));

void gtt_die(int, const char *, ...) __attribute__((format(printf, 2, 3)));

void *gtt_xmalloc(size_t);

ssize_t gtt_write_record(int, const void *, size_t);
int gtt_read_record(int, void *, int, int *);

int gtt_set_affinity2(pthread_t thread, int cpu_id);
int gtt_set_affinity(int);

int gtt_cpuset_from_string(gtt_cpuset_t *, char *);

#endif // GBTCP_TOOLS_COMMON_SUBR_H
