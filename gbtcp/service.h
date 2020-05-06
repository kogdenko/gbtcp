#ifndef GBTCP_SERVICE_H
#define GBTCP_SERVICE_H

#include "subr.h"

#define GT_SERVICE_ACTIVE 0
#define GT_SERVICE_SHADOW 1
#define GT_SERVICE_NONE 2

struct gt_service_msg {
	uint8_t svcm_cmd;
	uint8_t svcm_if_idx;
} __attribute__((packed));

extern int gt_service_pid;

int service_mod_init(struct log *, void **);
int service_mod_attach(struct log *, void *);
void service_mod_deinit(struct log *, void *);
void service_mod_detach(struct log *);

const char *gt_service_status_str(int status);


int gt_service_fork(struct log *);

#ifdef __linux__
int gt_service_clone(int (*)(void *), void *, int, void *,
	void *, void *, void *);
#endif /* __linux__ */

#endif /* GBTCP_SERVICE_H */
