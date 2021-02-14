// gpl2
#ifndef GBTCP_CONTROLLER_H
#define GBTCP_CONTROLLER_H

#include "subr.h"

#define AUX_CPU_ID (CPU_NUM - 1)
#define WORKER_CPU_NUM (CPU_NUM - 1)

extern int controller_done;

void host_rxtx(struct dev *, short);
int transmit_to_host(struct route_if *, void *, int);

void update_rss_table();

int controller_init(int, int, const char *);
void controller_deinit();
void controller_process();

#endif // GBTCP_CONTROLLER_H
