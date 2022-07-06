// gpl2
#ifndef GBTCP_CONTROLLER_H
#define GBTCP_CONTROLLER_H

#include "subr.h"

#define CONTROLLER_SID 0

void interface_dev_host_rx(struct dev *, void *, int);
int transmit_to_host(struct route_if *, void *, int);

void update_rss_table(void);

int gtl_controller_init(int) GT_EXPORT;
void gtl_controller_deinit(void) GT_EXPORT;
void gtl_controller_start(int) GT_EXPORT;

#endif // GBTCP_CONTROLLER_H
