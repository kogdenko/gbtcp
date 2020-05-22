// GPL2 license
#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include "subr.h"

int mod_foreach_mod_init(struct init_hdr *);
int mod_foreach_mod_service_init(struct service *);
int mod_foreach_mod_attach(struct init_hdr *);
void mod_foreach_mod_deinit(struct init_hdr *);
void mod_foreach_mod_detach();
void mod_foreach_mod_service_deinit(struct service *);

#endif // GBTCP_MOD_H
