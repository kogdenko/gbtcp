// gpl2
#ifndef GBTCP_PID_H
#define GBTCP_PID_H

#include "subr.h"

#define PID_PATH GT_PREFIX"/pid"

int pid_file_open(const char *);
int pid_file_lock(int, int);
int pid_file_read(int);
int pid_file_write(int, int);
int pid_file_acquire(const char *, int, int);

#endif // GBTCP_PID_H
