#ifndef GBTCP_POLL_H
#define GBTCP_POLL_H

#include "subr.h"

int gt_poll_mod_init();

void gt_poll_mod_deinit(struct gt_log *log);

int gt_poll(struct pollfd *pfds, int npfds, uint64_t to,
	const sigset_t *sigmask);

#endif /* GBTCP_POLL_H */
