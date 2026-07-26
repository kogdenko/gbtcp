// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_BACKTRACE_H
#define GBTCP_BACKTRACE_H

#include <gbtcp/kernel/subr.h>

struct gt_bfd;

enum gt_bfd_filetype {
	GT_BFD_UNKNOWN,
	GT_BFD_EXECUTABLE,
	GT_BFD_SHARED_LIBRARY,
};

void gt_bfd_init(void);
void gt_bfd_deinit(void);

int gt_bfd_open(struct gt_bfd **pbfd, const char *path, u8 filetype);

int gt_bfd_close(struct gt_bfd *bfd);

void gt_print_backtrace(int fd);

#endif
