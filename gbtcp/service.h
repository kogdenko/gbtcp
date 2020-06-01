#ifndef GBTCP_SERVICE_H
#define GBTCP_SERVICE_H

#include "subr.h"
#include "mod.h"
#include "mbuf.h"
#include "route.h"

#define IH_VERSION 2

#define PROC_COMM_MAX 32

#define MODS_MAX 32

//#define P_SERVICE 0
//#define P_CONTROLLER 1

#define SERVICE_LOCK do { \
	spinlock_lock(&current->p_lock); \
	rd_nanoseconds(); \
	if (current->p_dirty) { \
		service_update(); \
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
	u_char p_dirty;
	u_char p_rss_nq;
	int p_fd;
	uint32_t p_kpps;
	uint64_t p_pkts;
	uint64_t p_pkts_time;
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
	void *ih_mods[MODS_MAX];
	struct service ih_services[GT_SERVICES_MAX];
	int ih_rss_nq;
	int ih_rss_table[GT_RSS_NQ_MAX];
};

int service_mod_init(void **);
int service_mod_attach(void *);
void service_mod_deinit();
void service_mod_detach();

int service_init(const char *);
void service_deinit();
int service_attach();
void service_update();
void service_inc_pkts();
int service_can_connect(struct route_if *, be32_t, be32_t, be16_t, be16_t);

int service_fork();

#ifdef __linux__
int service_clone(int (*)(void *), void *, int, void *,
	void *, void *, void *);
#endif /* __linux__ */

extern struct init_hdr *ih;
extern struct service *current;
uint64_t nanoseconds;

#endif // GBTCP_SERVICE_H
