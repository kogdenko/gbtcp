// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_PID_H
#define GBTCP_PID_H

#include "subr.h"

#define PID_PATH GT_PREFIX"/pid"

char *pid_file_path(char *, int sid);
int pid_file_open(const char *);
int pid_file_lock(int);
int pid_file_read(int);
int pid_file_write(int, int);
int pid_file_acquire(int, int);

#endif // GBTCP_PID_H
