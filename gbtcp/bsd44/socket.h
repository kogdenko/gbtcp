/*
 * Copyright (c) 1982, 1985, 1986, 1988, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
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

#ifndef GBTCP_BSD44_SOCKET_H_
#define	GBTCP_BSD44_SOCKET_H_

#include "types.h"
#include "in_pcb.h"
#include "../file.h"
#include "../list.h"

struct file;
struct socket;
struct sockbuf;

struct sockbuf {
	u_int sb_cc; /* actual chars in buffer */
	u_int sb_hiwat;	/* max actual char count */
	u_int sb_lowat;	/* low water mark */
	struct dlist sb_head;
};

#define	SB_MAX (256*1024) /* default for max chars in sockbuf */

/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
#define inp_list so_base.ipso_list
#define inp_laddr so_base.ipso_laddr
#define inp_faddr so_base.ipso_faddr
#define inp_lport so_base.ipso_lport
#define inp_fport so_base.ipso_fport

struct socket {
	struct file so_file;

	struct ip_socket so_base;

	uint32_t so_options;		/* from socket call, see socket.h */
	u_char	so_proto;
	short   so_events;
	u_short	so_error;		/* error affecting connection */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* internal state flags SS_*, below */

	struct	socket *so_head;	/* back pointer to accept socket */
	struct	dlist so_q[2];		/* queue of partial/incoming connections */
#define so_ql so_q[0]


	struct sockbuf so_snd;
	int so_rcv_hiwat;
	void (*so_userfn)(struct socket *, short, struct sockaddr_in *, void *, int);
	uint64_t so_user;
	struct dlist so_txlist;
	struct tcpcb inp_ppcb;
};

#define	sototcpcb(so) (&((so)->inp_ppcb))
#define tcpcbtoso(tp) container_of(tp, struct socket, inp_ppcb)

extern struct dlist so_txq;

#ifdef __linux__
#define SO_OPTION(optname) (1 << (optname))
#else
#define SO_OPTION(optname) (optname)
#endif

/*
 * Socket state bits.
 */
#define	SS_NOFDREF              0x001   /* no file table ref any more */
#define	SS_ISCONNECTED          0x002   /* socket connected to a peer */
#define	SS_ISCONNECTING         0x004   /* in process of connecting to peer */
#define	SS_ISDISCONNECTING      0x008   /* in process of disconnecting */
#define	SS_CANTSENDMORE         0x010   /* can't send more data to peer */
#define	SS_CANTRCVMORE          0x020   /* can't receive more data from peer */
#define	SS_ISTXPENDING          0x080
#define SS_ISPROCESSING         0x100
#define SS_ISATTACHED           0x200

/*
 * Macros for sockets and socket buffering.
 */

/*
 * How much space is there in a socket buffer (so->so_snd or so->so_rcv)?
 * This is problematical if the fields are unsigned, as the space might
 * still be negative (cc > hiwat or mbcnt > mbmax).  Should detect
 * overflow and return 0.  Should use "lmin" but it doesn't exist now.
 */
#define	sbspace(sb) ((long)(sb)->sb_hiwat - (sb)->sb_cc)

/* do we have to send all at once on a socket? */
#define	sosendallatonce(so) ((so)->so_proto == IPPROTO_UDP)


#define soisopt(so, optname) (((so)->so_options & SO_OPTION(optname)) ? 1 : 0)
#define sosetopt(so, optname) ((so)->so_options |= SO_OPTION(optname))
#define soclropt(so, optname) ((so)->so_options &= ~SO_OPTION(optname))

short soevents(struct socket *so);

/* can we read something from so? */
int soreadable(struct socket *so);

/* can we write something to so? */
int sowriteable(struct socket *so);

struct	socket *sonewconn(struct socket *head);

//int getsock(int fdes, struct file **fpp);
int soconnect(struct socket *so, const struct sockaddr_in *);
void soaccept(struct socket *so);

int sodisconnect(struct socket *so);
void sofree(struct socket *);
void soqremque(struct socket *so);
void sbrelease(struct sockbuf *sb);
void sorflush(struct socket *so);
void soisconnecting(struct socket *so);
void socantsendmore(struct socket *so);
int sbappend(struct sockbuf *, const u_char *, int);
void soisdisconnecting(struct socket *so);
void soisdisconnected(struct socket *so);
void soqinsque(struct socket *head, struct socket *so, int q);
void sowakeup(struct socket *, short, struct sockaddr_in *, void *, int);
#define sowakeup2(so, events) sowakeup(so, events, NULL, NULL, 0)
void sbinit(struct sockbuf *sb, u_long);
void sbreserve(struct sockbuf *sb, u_long);
void sbdrop(struct sockbuf *sb, int len);
void sbcopy(struct sockbuf *, int, int, u_char *);
void soabort(struct socket *so);
int sosend(struct socket *, const void *, int, const struct sockaddr_in *, int);
void sbdroprecord(struct sockbuf *sb);
void socantrcvmore(struct socket *so);
int sbappendaddr(struct sockbuf *, struct sockaddr *, const void *, int);
void soisconnected(struct socket *so);
void somodopt(struct socket *, int, int);

int bsd_socket(int, struct socket **);
int bsd_connect(struct socket *);
int bsd_sendto(struct socket *, const void *, int, int,
	const struct sockaddr_in *);
int bsd_bind(struct socket *so, be16_t port);
int bsd_listen(struct socket *so);
int bsd_accept(struct socket *, struct socket **);
int bsd_close(struct socket *);

#endif // GBTCP_BSD44_SOCKET_H_
