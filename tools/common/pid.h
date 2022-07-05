#ifndef GBTCP_TOOLS_COMMON_PID_H
#define GBTCP_TOOLS_COMMON_PID_H

#include <stdbool.h>

char *pid_file_get_path(char *, const char *, int);
int pid_file_open(const char *);
int pid_file_lock(int, bool);
int pid_file_read(int);
int pid_file_write(int, unsigned int);
int pid_file_acquire(int, unsigned int);

#endif // GBTCP_TOOLS_COMMON_PID_H
