/* GPL2 license */
#ifndef GBTCP_SIGNAL_H
#define GBTCP_SIGNAL_H

#include "subr.h"

extern void *gt_signal_stack;
extern size_t gt_signal_stack_size;

int signal_mod_init(void **);
int signal_mod_attach(void *);
void signal_mod_deinit();
void signal_mod_detach();

int gt_signal_sigaction(int signum, const struct sigaction *act,
	struct sigaction *oldact);

int gt_signal_sigaltstack(const stack_t *ss, stack_t *oss);

int gt_signal_sigstack(struct sigstack *ss, struct sigstack *oss);

#endif /* GBTCP_SIGNAL_H */
