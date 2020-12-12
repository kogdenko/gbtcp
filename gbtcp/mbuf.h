// GPL v2
#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "list.h"


struct mbuf_chunk {
	struct dlist mbc_list;
	struct dlist mbc_mbuf_head;
	struct mbuf_pool *mbc_pool;
	int mbc_n_mbufs;
	short mbc_id;
};

struct mbuf_pool {
	int mbp_mbuf_size;
	int mbp_mbufs_per_chunk;
	int mbp_n_allocated_chunks;
	u_char mbp_worker_id;
	u_char mbp_referenced;
	struct dlist mbp_avail_chunk_head;
	struct dlist mbp_not_avail_chunk_head;
};

#if 0
#define MBUF_FOREACH_SAFE(m, p, tmp_id) \
	for (m = mbuf_next(p, 0); \
	     m != NULL && ((tmp_id = mbuf_get_id(m) + 1), 1); \
	     m = mbuf_next(p, tmp_id))
#endif

int mbuf_mod_init(void **);
int mbuf_mod_service_init(struct service *);
void mbuf_mod_deinit();
void mbuf_mod_service_deinit(struct service *);

int mbuf_pool_alloc(struct mbuf_pool **, u_char, int);
void mbuf_pool_free(struct mbuf_pool *);

void *mbuf_alloc(struct mbuf_pool *);
void mbuf_free(void *);
void mbuf_free_rcu(void *);

void garbage_collector(struct service *);

void mem_worker_init();
void mem_reclaim_rcu();

//void *mem_alloc(size_t);
//void mem_free(void *);

#endif // GBTCP_MBUF_H
