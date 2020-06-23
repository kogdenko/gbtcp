// gpl2
#ifndef GBTCP_SCHED_H
#define GBTCP_SCHED_H

#include "subr.h"

#define SCHED_SID 0

void host_rxtx(struct dev *, short);
int transmit_to_host(struct route_if *, void *, int);

void update_rss_table();

int sched_init(int, const char *);
void sched_deinit();
void sched_loop();

#endif // GBTCP_SCHED_H
