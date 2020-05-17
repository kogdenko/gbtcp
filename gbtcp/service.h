#ifndef GBTCP_SERVICE_H
#define GBTCP_SERVICE_H

#include "subr.h"

int service_mod_init(struct log *, void **);
int service_mod_attach(struct log *, void *);
void service_mod_deinit(struct log *, void *);
void service_mod_detach(struct log *);

int service_fork(struct log *);

#ifdef __linux__
int service_clone(int (*)(void *), void *, int, void *,
	void *, void *, void *);
#endif /* __linux__ */

#endif /* GBTCP_SERVICE_H */
