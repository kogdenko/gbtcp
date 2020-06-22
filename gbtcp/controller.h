// gpl2 license
#ifndef GBTCP_CONTROLLER_H
#define GBTCP_CONTROLLER_H

#include "subr.h"

#define SCHED_SID 0

void host_rxtx(struct dev *, short);
int transmit_to_host(struct route_if *, void *, int);
int init_sched(int, const char *);
void sched_loop();
void update_rss_table();

#endif // GBTCP_CONTROLLER_H
