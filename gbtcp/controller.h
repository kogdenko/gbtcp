// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_CONTROLLER_H
#define GBTCP_CONTROLLER_H

#include "gbtcp.h"

struct dev;
struct route_if;

#define CONTROLLER_SID 0

void interface_dev_host_rx(struct dev *, void *, int);
int transmit_to_host(struct route_if *, void *, int);

void update_rss_table(void);

int gt_controller_init(int) GT_EXPORT;
void gt_controller_deinit(void) GT_EXPORT;
void gt_controller_start(int) GT_EXPORT;

#endif // GBTCP_CONTROLLER_H
