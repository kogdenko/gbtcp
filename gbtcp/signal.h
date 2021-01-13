// GPL v2
#ifndef GBTCP_SIGNAL_H
#define GBTCP_SIGNAL_H

#include "subr.h"

int init_signals();
void deinit_signals();

int signal_sigprocmask(int, const sigset_t *, sigset_t *);
const sigset_t *signal_sigprocmask_get();

#endif // GBTCP_SIGNAL_H
