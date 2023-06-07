// SPDX-License-Identifier: GPL-2.0
#ifndef GBTCP_API_H
#define GBTCP_API_H

#include "subr.h"

#define GT_RETURN(rc) \
	if (rc < 0) { \
		gt_errno = -rc; \
		return -1; \
	} else { \
		return rc; \
	} \

int api_mod_init(void **);
int api_mod_attach(void *);
void api_mod_deinit(void);
void api_mod_detach(void);

int api_lock(void);
void api_unlock(void);

#endif // GBTCP_API_H
