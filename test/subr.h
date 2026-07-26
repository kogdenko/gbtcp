// SPDX-License-Identifier: LGPL-2.1-only
//
// Shared fixture helpers for the cmocka-based tests. No assert machinery
// lives here — tests use cmocka asserts (assert_return_code & friends).

#ifndef TEST_SUBR_H
#define TEST_SUBR_H

#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif

#include <cmocka.h>

void die(int errnum, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
void *xmalloc(int size);

// Listen on 0.0.0.0:7385, print "Ready\n" (the runner's handshake) and
// return the accepted connection.
int test_accept(void);

void test_parse_argv(int argc, char **argv, char **intf_name, char **peer_name);

#endif // TEST_SUBR_H
