/* GPL2 license */
#ifndef GBTCP_POLL_H
#define GBTCP_POLL_H

#include "subr.h"

int poll_mod_init(struct log *, void **);
int poll_mod_attach(struct log *, void *);
int poll_proc_init(struct log *, struct proc *);
void poll_mod_deinit(struct log *, void *);
void poll_mod_detach(struct log *);

int gt_poll(struct pollfd *, int, uint64_t, const sigset_t *);

#endif /* GBTCP_POLL_H */
