// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_GLOBAL_H
#define GBTCP_GLOBAL_H

#include "gbtcp.h"

struct service;
struct shm_hdr;

#define MOD_FOREACH(x) \
	x(SYSCTL) \
	x(LOG) \
	x(SYS) \
	x(SHM) \
	x(SUBR) \
	x(POLL) \
	x(EPOLL) \
	x(MBUF) \
	x(HTABLE) \
	x(TIMER) \
	x(FD) \
	x(SIGNAL) \
	x(DEV) \
	x(API) \
	x(LPTREE) \
	x(ROUTE) \
	x(ARP) \
	x(FILE) \
	x(INET) \
	x(SOCKET) \
	x(SERVICE) \
	x(CONTROLLER) \
	x(APP)

#define MOD_ENUM(name) GT_MODULE_##name,

enum {
	MOD_ZERO,
	MOD_FOREACH(MOD_ENUM)
	MODS_MAX
};

#define MOD_FIRST 1

extern struct service *current;
extern struct shm_hdr *shared;
extern sigset_t current_sigprocmask;
extern int current_sigprocmask_set;
extern uint64_t nanoseconds;

#endif // GBTCP_GLOBAL_H
