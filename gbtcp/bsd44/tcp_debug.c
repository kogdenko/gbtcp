/*
 * Copyright (c) 1982, 1986, 1993
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

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_var.h"
#include "tcp_timer.h"

char *prurequests[] = {
	[PRU_DETACH] = "DETACH",
	[PRU_BIND] = "BIND",
	[PRU_LISTEN] = "LISTEN",
	[PRU_CONNECT] = "CONNECT",
	[PRU_ACCEPT] = "ACCEPT",
	[PRU_DISCONNECT] = "DISCONNECT",
	[PRU_SHUTDOWN] = "SHUTDOWN",
	[PRU_SEND] =  "SEND",
	[PRU_ABORT] = "ABORT",
	[PRU_FASTTIMO] = "FASTTIMO",
	[PRU_SLOWTIMO] = "SLOWTIMO",
};

static const char* tanames[] = {
	[TA_INPUT] = "input",
	[TA_OUTPUT] = "output",
	[TA_USER] = "user",
	[TA_RESPOND] = "respond",
	[TA_DROP] = "drop"
};

static const char *tcptimers[] = {
	[TCPT_REXMT] = "REXMT",
	[TCPT_PERSIST] = "PERSIST",
	[TCPT_KEEP] = "KEEP",
	[TCPT_2MSL] = "2MSL"
};

/*
 * Tcp debug routines
 */
void
tcp_trace(int act, int ostate, struct tcpcb *tp, struct ip *ip,
		struct bsd_tcp_hdr *th, int req)
{
	char lb[INET_ADDRSTRLEN];
	char fb[INET_ADDRSTRLEN];
	tcp_seq seq, ack;
	int len, flags;
	struct socket *so;

	printf("%s ", tanames[act]);
	if (tp) {
		so = tcpcbtoso(tp);
		printf("[%s:%hu > %s:%hu %s] ",
			inet_ntop(AF_INET, &so->so_base.ipso_laddr, lb, sizeof(lb)),
			ntohs(so->so_base.ipso_lport),
			inet_ntop(AF_INET, &so->so_base.ipso_faddr, fb, sizeof(fb)),
			ntohs(so->so_base.ipso_fport),
			tcpstates[ostate]);
	} else {
		printf("[?] ");
	}
	switch (act) {
	case TA_INPUT:
	case TA_OUTPUT:
	case TA_DROP:
		if (ip == 0) {
			break;
		}
		seq = th->th_seq;
		ack = th->th_ack;
		len = ip->ip_len;
		if (act == TA_OUTPUT) {
			seq = ntohl(seq);
			ack = ntohl(ack);
			len -= (sizeof(*ip) + (th->th_off << 2));
		}
		if (len) {
			printf("[%u..%u)", seq, seq + len);
		} else {
			printf("[%u)", seq);
		}
		printf("@%u", ack);
		flags = th->th_flags;
		if (flags) {
			char *cp = "<";
#define pf(f) \
			if (th->th_flags & TH_##f) { \
				printf("%s%s", cp, #f); cp = ","; \
			}
			pf(SYN);
			pf(ACK);
			pf(FIN);
			pf(RST);
			pf(PUSH);
			pf(URG);
#undef pf
			printf(">");
		}
		break;

	case TA_USER:
		printf("%s", prurequests[req & 0xff]);
		if ((req & 0xff) == PRU_SLOWTIMO) {
			printf("<%s>", tcptimers[req >> 8]);
		}
		break;
	}
	if (tp) {
		printf(" -> %s", tcpstates[tp->t_state]);
	}
	/* print out internal state of tp !?! */
	printf("\n");
	if (tp == NULL) {
		return;
	}
	printf("\trcv_nxt=%u snd_(una,nxt,max)=(%u,%u,%u)\n",
		tp->rcv_nxt, tp->snd_una, tp->snd_nxt, tp->snd_max);
	printf("\tsnd_(wl1,wl2,wnd) (%u,%u,%lu)\n",
		tp->snd_wl1, tp->snd_wl2, tp->snd_wnd);
}
