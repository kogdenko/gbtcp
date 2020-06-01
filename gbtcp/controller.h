// GPL2 license
#ifndef GBTCP_CONTROLLER_H
#define GBTCP_CONTROLLER_H

#include "subr.h"

int controller_mod_init(void **);
int controller_mod_attach(void *);
void controller_mod_deinit();
void controller_mod_detach();

int controller_init(int, const char *);
void controller_loop();
void controller_update_rss_table();

#endif // GBTCP_CONTROLLER_H
