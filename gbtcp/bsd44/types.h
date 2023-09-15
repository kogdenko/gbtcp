/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef GBTCP_BSD44_TYPES_H
#define	GBTCP_BSD44_TYPES_H

#include <stdint.h>
#include "../global.h"
#include "../subr.h"
#include "../list.h"
#include "../service.h"

typedef unsigned char u_char;
typedef unsigned short u_short;

struct ip_socket {
	struct dlist ipso_list;
	union {
		struct ip_socket *ipso_cache;	// FIXME: ????
		uint32_t ipso_hash;		// FIXME: ????
	};
	be32_t ipso_laddr;
	be32_t ipso_faddr;
	be16_t ipso_lport;
	be16_t ipso_fport;
};

#define	M_BCAST                 0x0100 /* send/received as link-level broadcast */
#define	M_MCAST	                0x0200 /* send/received as link-level multicast */

#define	PRU_DETACH              1      /* detach protocol from up */
#define	PRU_BIND                2      /* bind socket to address */
#define	PRU_LISTEN              3      /* listen for connection */
#define	PRU_CONNECT             4      /* establish connection to peer */
#define	PRU_ACCEPT              5      /* accept connection from peer */
#define	PRU_DISCONNECT          6      /* disconnect from peer */
#define	PRU_SHUTDOWN            7      /* won't send any more data */
#define	PRU_SEND                9      /* send this data */
#define	PRU_ABORT               10     /* abort (fast DISCONNECT, DETATCH) */
/* begin for protocols internal use */
#define	PRU_FASTTIMO            18      /* 200ms timeout */
#define	PRU_SLOWTIMO            19      /* 500ms timeout */

#define	PRU_NREQ                21


#define	PRCO_GETOPT     0
#define	PRCO_SETOPT     1


#define PR_SLOWHZ       2               /* 2 slow timeouts per second */
#define PR_FASTHZ       5               /* 5 fast timeouts per second */
 
/*
 * Values for pr_flags.
 * PR_ADDR requires PR_ATOMIC;
 * PR_ADDR and PR_CONNREQUIRED are mutually exclusive.
 */
#define PR_ATOMIC       0x01            /* exchange atomic messages only */
#define PR_ADDR         0x02            /* addresses given with messages */
#define PR_CONNREQUIRED 0x04            /* connection required by protocol */
#define PR_WANTRCVD     0x08            /* want PRU_RCVD calls */
#define PR_RIGHTS       0x10            /* passes capabilities */

#define TCP_NSTATES     11

extern uint32_t tcp_now;
extern u_char etherbroadcastaddr[6];
extern const char *tcpstates[TCP_NSTATES];

#define tcpstat current->p_tcps

#endif // GBTCP_BSD44_TYPES_H
