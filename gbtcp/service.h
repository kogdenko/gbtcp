// gpl2 license
#ifndef GBTCP_SERVICE_H
#define GBTCP_SERVICE_H

#include "subr.h"
#include "mod.h"
#include "mbuf.h"
#include "route.h"
#include "timer.h"

#define IH_VERSION 2

#define SERVICE_COMM_MAX 32

#define SERVICE_LOCK do { \
	spinlock_lock(&current->p_lock); \
	rd_nanoseconds(); \
	if (current->p_dirty) { \
		service_update(); \
	} \
} while (0)

#define SERVICE_UNLOCK \
	service_unlock()

#define SERVICE_FOREACH(s) \
	for ((s) = shm_ih->ih_services; \
	     (s) != shm_ih->ih_services + ARRAY_SIZE(shm_ih->ih_services); \
	     (s)++)

struct service {
	struct spinlock p_lock;
	int p_pid;
	u_char p_id;
	u_char p_dirty;
	u_char p_rss_nq;
	int p_fd;
	u_int p_epoch;
	u_int p_tx_kpps;
	uint64_t p_tx_kpps_time;
	uint64_t p_tx_pkts;
	int p_timer_nrings;
	struct timer_ring *p_timer_rings[TIMER_NRINGS_MAX];
	struct mbuf_pool p_file_pool;
	struct mbuf_pool p_sockbuf_pool;
	struct mbuf_pool p_arp_entry_pool;
	struct mbuf_pool p_arp_incomplete_pool;
	struct tcp_stat p_tcps;
	struct udp_stat p_udps;
	struct ip_stat p_ips;
	struct icmp_stat p_icmps;
	struct arp_stat p_arps;
	int p_mbuf_free_indirect_n;
	struct dlist p_mbuf_free_indirect_head[GT_SERVICES_MAX];
	char p_comm[SERVICE_COMM_MAX];
};

struct shm_init_hdr {
	int ih_version;
	uint64_t ih_hz;
	void *ih_mods[MODS_NUM];
	struct service ih_services[GT_SERVICES_MAX];
	int ih_rss_nq;
	int ih_rss_table[GT_RSS_NQ_MAX];
};


int service_mod_init(void **);
void service_mod_deinit();

int service_init(const char *);
int service_attach();
void service_deinit();
void service_detach(int);
void service_clean(struct service *);
void service_unlock();
void service_account_tx_pkt();
void service_update();
int service_can_connect(struct route_if *, be32_t, be32_t, be16_t, be16_t);

int service_fork();

#ifdef __linux__
int service_clone(int (*)(void *), void *, int, void *,
	void *, void *, void *);
#endif /* __linux__ */

#endif // GBTCP_SERVICE_H
