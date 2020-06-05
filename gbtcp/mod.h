// gpl2 license
#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include "subr.h"

enum {
	MOD_SYSCTL,
	MOD_LOG,
	MOD_SYS,
	MOD_SUBR,
	MOD_PID,
	MOD_POLL,
	MOD_EPOLL,
	MOD_MBUF,
	MOD_HTABLE,
	MOD_TIMER,
	MOD_FD_EVENT,
	MOD_SIGNAL,
	MOD_DEV,
	MOD_API,
	MOD_LPTREE,
	MOD_ROUTE,
	MOD_ARP,
	MOD_FILE,
	MOD_INET,
	MOD_SOCKBUF,
	MOD_TCP,
	MOD_SERVICE,
	MOD_CONTROLLER,
	MOD_N
};

int foreach_mod_init(struct init_hdr *);
int foreach_mod_service_init(struct service *);
int foreach_mod_attach(struct init_hdr *);
void foreach_mod_deinit(struct init_hdr *);
void foreach_mod_detach();
void foreach_mod_service_deinit(struct service *);

#endif // GBTCP_MOD_H
