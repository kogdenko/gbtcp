#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include "internals.h"

int mod_foreach_mod_init(struct log *);
int mod_foreach_mod_service_init(struct log *, struct proc *);
int mod_foreach_mod_attach(struct log *);
void mod_foreach_mod_deinit(struct log *);
void mod_foreach_mod_detach(struct log *);
void mod_foreach_mod_service_deinit(struct log *, struct proc *);

#endif // GBTCP_MOD_H
