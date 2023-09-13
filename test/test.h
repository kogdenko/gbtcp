// SPDX-License-Identifier: LGPL-2.1-only

#ifndef TEST_SUBR_H
#define TEST_SUBR_H

#define _GNU_SOURCE
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <sys/epoll.h>
#else
#endif

#define UNIQV_CAT3(x, res) res
#define UNIQV_CAT2(x, y) UNIQV_CAT3(~, x##y)
#define UNIQV_CAT(x, y) UNIQV_CAT2(x, y)
#define UNIQV(n) UNIQV_CAT(n, __LINE__)

#define STRSZ(s) (s), (sizeof(s) - 1)

#ifndef dbg
#define dbg(fmt, ...) do { \
	printf("%-20s %-5d %-20s: ", __FILE__, __LINE__, __func__); \
	printf(fmt, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)
#endif // dbg

#define ASSERT(e, expr) \
	if (!(expr)) { \
		assertion_failed(e, #expr, __FILE__, __LINE__); \
	}
#define TRACE_API(func, compar) \
do { \
	int UNIQV(rc); \
	printf("%s ... ", #func); \
	fflush(stdout); \
	UNIQV(rc) = (func); \
	if (!(UNIQV(rc) compar)) { \
		trace_api_failed(UNIQV(rc)); \
		exit(1); \
	} else { \
		printf("Ok, %d\n", UNIQV(rc)); \
	} \
} while (0)

void die(int errnum, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
void *xmalloc(int size);
void *xrealloc(void *ptr, int size);
char *strzcpy(char *dest, const char *src, size_t n);
void trace_api_failed(int rc);
void assertion_failed(int e, const char *expr, const char *file, int line);
int parse_sockaddr_in(struct sockaddr_in *addr, const char *s);

void init_testcase(int argc, char **argv);
void wait_SIGUSR1(void);

int test_accept(int argc, char **argv);
int test_connect(int argc, char **argv);

#endif // TEST_SUBR_H
