// SPDX-License-Identifier: BSD-4-Clause

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
tcp_trace(int act, int ostate, struct tcpcb *tp, struct ip4_hdr *ip, struct tcp_hdr *th, int req)
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
			inet_ntop(AF_INET, &so->so_base.sobase_laddr, lb, sizeof(lb)),
			ntohs(so->so_base.sobase_lport),
			inet_ntop(AF_INET, &so->so_base.sobase_faddr, fb, sizeof(fb)),
			ntohs(so->so_base.sobase_fport),
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
		len = ip->ih_total_len;
		if (act == TA_OUTPUT) {
			seq = ntohl(seq);
			ack = ntohl(ack);
			len -= (sizeof(*ip) + (th->th_data_off << 2));
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
