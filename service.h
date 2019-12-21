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
extern int gt_service_ctl_polling;

int gt_service_mod_init();

void gt_service_mod_deinit(struct gt_log *log);

const char *gt_service_status_str(int status);

int gt_service_init(struct gt_log *log);

int gt_service_fork(struct gt_log *log);

#ifdef __linux__
int gt_service_clone(int (*fn)(void *), void *child_stack,
                     int flags, void *arg,
                     void *ptid, void *tls, void *ctid);
#endif /* __linux__ */

#endif /* GBTCP_SERVICE_H */
