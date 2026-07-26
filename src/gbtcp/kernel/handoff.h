// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_HANDOFF_H
#define GBTCP_HANDOFF_H

#include <gbtcp/kernel/gbtcp.h>

struct service;
struct dev_pkt;

struct dev;
void service_rssq_rx(struct dev *dev, void *data, int len);

int gt_main_handoff_init(struct service *s);
void gt_main_handoff_deinit(struct service *s);
int gt_worker_handoff_init(struct service *s);
void gt_worker_handoff_deinit(void);

#endif // GBTCP_HANDOFF_H
