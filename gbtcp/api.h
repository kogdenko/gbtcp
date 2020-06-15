// GPL2 license
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
void api_mod_deinit();
void api_mod_detach();

#endif // GBTCP_API_H
