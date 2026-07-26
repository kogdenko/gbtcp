// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_TOOLS_COMMON_PID_H
#define GBTCP_TOOLS_COMMON_PID_H

#include <stdbool.h>

char *gtt_pid_file_get_path(char *, const char *, int);
int gtt_pid_file_open(const char *);
int gtt_pid_file_lock(int, bool);
int gtt_pid_file_read(int);
int gtt_pid_file_write(int, unsigned int);
int gtt_pid_file_acquire(int, unsigned int);

#endif // GBTCP_TOOLS_COMMON_PID_H
