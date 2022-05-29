// gpl2
#ifndef GBTCP_CONTROLLER_H
#define GBTCP_CONTROLLER_H

#include "subr.h"

#define CONTROLLER_SID 0

void host_rxtx(struct dev *, short);
int transmit_to_host(struct route_if *, void *, int);

void update_rss_table();

int controller_init(int, const char *);
void controller_deinit();
void controller_start(int);

#endif // GBTCP_CONTROLLER_H
