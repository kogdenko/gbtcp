// gpl2
#ifndef GBTCP_CONTROLLER_H
#define GBTCP_CONTROLLER_H

#include "subr.h"

#define CONTROLLER_SID 0

void interface_dev_host_rx(struct dev *, void *, int);
int transmit_to_host(struct route_if *, void *, int);

void update_rss_table(void);

int controller_init(int, const char *);
void controller_deinit(void);
void controller_start(int);

#endif // GBTCP_CONTROLLER_H
