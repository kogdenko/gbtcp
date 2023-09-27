// SPDX-License-Identifier: BSD-4-Clause

#ifndef GBTCP_BSD44_IN_PCB_H
#define GBTCP_BSD44_IN_PCB_H

#include "tcp_var.h"

int in_pcbbind(struct socket *, be16_t);
int in_pcbconnect(struct socket *, uint32_t *);
int in_pcbattach(struct socket *, uint32_t *);
int in_pcbdetach(struct socket *);
void in_pcbdisconnect(struct socket *);
int in_pcblookup(struct socket **, int, be32_t, be32_t, be16_t, be16_t);
void in_pcbnotify(int, be32_t, be32_t, be16_t, be16_t, int err, 
                  void (*)(struct socket *, int));
void in_pcbforeach(void (*)(struct socket *));

#endif // GBTCP_BSD44_IN_PCB_H
