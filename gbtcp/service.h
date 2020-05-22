#ifndef GBTCP_SERVICE_H
#define GBTCP_SERVICE_H

#include "subr.h"
#include "mod.h"
#include "mbuf.h"
#include "route.h"

#define IH_VERSION 2

#define PROC_COMM_MAX 32

#define MOD_COUNT_MAX 32

#define P_SERVICE 0
#define P_CONTROLLER 1

#define tcps (current->p_tcps)
#define udps (current->p_udps)
#define ips (current->p_ips)
#define icmps (current->p_icmps)
#define arps (current->p_arps)

#define SERVICE_LOCK do { \
	spinlock_lock(&current->p_lock); \
	rd_nanoseconds(); \
	if (current->p_dirty_rss_table) { \
		service_update_rss_table(NULL, current); \
	} \
} while (0)

#define SERVICE_UNLOCK \
	spinlock_unlock(&current->p_lock)

#define SERVICE_FOREACH(s) \
	for ((s) = ih->ih_services; \
	     (s) != ih->ih_services + ARRAY_SIZE(ih->ih_services); ++(s))

struct service {
	struct spinlock p_lock;
	int p_pid;
	u_char p_id;
	u_char p_dirty_rss_table;
	u_char p_rss_nq;
	int p_fd;
	uint32_t p_pps;
	struct tcp_stat p_tcps;
	struct udp_stat p_udps;
	struct ip_stat p_ips;
	struct icmp_stat p_icmps;
	struct arp_stat p_arps;
	struct mbuf_pool p_file_pool;
	struct mbuf_pool p_sockbuf_pool;
	struct mbuf_pool p_arp_entry_pool;
	struct mbuf_pool p_arp_incomplete_pool;
	char p_comm[PROC_COMM_MAX];
};

struct init_hdr {
	int ih_version;
	uint64_t ih_hz;
	void *ih_mods[MOD_COUNT_MAX];
	struct service ih_services[GT_SERVICE_COUNT_MAX];
	int ih_rss_nq;
	int ih_rss_table[GT_RSS_NQ_MAX];
};

void proc_init();

int service_mod_init(struct log *, void **);
int service_mod_attach(struct log *, void *);
void service_mod_deinit(struct log *, void *);
void service_mod_detach(struct log *);

int service_init();
void service_update_rss_table(struct log *, struct service *);
void service_clean(struct service *);
int service_is_appropriate_rss(struct route_if *, struct sock_tuple *); 
void service_rxtx(struct dev *, short);

int service_fork(struct log *);

#ifdef __linux__
int service_clone(int (*)(void *), void *, int, void *,
	void *, void *, void *);
#endif /* __linux__ */

extern struct init_hdr *ih;
extern struct service *current;
//extern int proc_type;
uint64_t nanoseconds;

#endif /* GBTCP_SERVICE_H */
