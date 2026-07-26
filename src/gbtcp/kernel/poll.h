// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_POLL_H
#define GBTCP_POLL_H

#include <gbtcp/kernel/subr.h>

int gt__poll(struct pollfd *, int, uint64_t, const sigset_t *);

#endif // GBTCP_POLL_H
