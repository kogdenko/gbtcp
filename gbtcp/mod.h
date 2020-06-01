// GPL2 license
#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include "subr.h"

int foreach_mod_init(struct init_hdr *);
int foreach_mod_service_init(struct service *);
int foreach_mod_attach(struct init_hdr *);
void foreach_mod_deinit(struct init_hdr *);
void foreach_mod_detach();
void foreach_mod_service_deinit(struct service *);

#endif // GBTCP_MOD_H
