#ifndef GBTCP_TOOLS_COMMON_SUBR_H
#define GBTCP_TOOLS_COMMON_SUBR_H

#define _GNU_SOURCE
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
typedef cpu_set_t cpuset_t;
#else // __linux__
#include <pthread_np.h>
#include <sys/event.h>
#endif // __linux__

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define UNUSED(x) ((void)(x))

#define dbg(fmt, ...) do { \
	printf("%-20s %-5d %-20s: ", __FILE__, __LINE__, __func__); \
	printf(fmt, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)

void errorf(int errnum, const char *, ...)
	__attribute__((format(printf, 2, 3)));

void die(int, const char *, ...)
	__attribute__((format(printf, 2, 3)));

void *xmalloc(size_t);

ssize_t write_record(int, const void *, size_t);
int read_record(int, void *, int, int *);

int set_affinity2(pthread_t thread, int cpu_id);
int set_affinity(int);

int cpuset_from_string(cpuset_t *, char *);

#endif // GBTCP_TOOLS_COMMON_SUBR_H
