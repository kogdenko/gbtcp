// GPL2 license
#ifndef GBTCP_POLL_H
#define GBTCP_POLL_H

#include "subr.h"

int poll_mod_init(void **);
int poll_mod_attach(void *);
void poll_mod_deinit();
void poll_mod_detach();

int u_poll(struct pollfd *, int, uint64_t, const sigset_t *);

#endif // GBTCP_POLL_H
