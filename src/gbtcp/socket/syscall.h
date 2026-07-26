// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_SYSCALL_H
#define GBTCP_SYSCALL_H

#include <gbtcp/kernel/subr.h>

#define GT_SYSCALL_RETURN(rc) \
	if (rc < 0) { \
		gt_errno = -rc; \
		return -1; \
	} else { \
		return rc; \
	}

int gt_syscall_lock(void);
void gt_syscall_unlock(void);

#endif
