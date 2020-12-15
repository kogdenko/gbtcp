// GPL v2
#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "list.h"

#define SLAB_ORDER_MIN 6 // 64b
#define BUDDY_ORDER_MIN 20 // ~1Mb
#define BUDDY_ORDER_MAX 27 // ~134Mb

struct mem_buf {
	struct dlist mb_list;
	struct mem_cache_block *mb_block;
	uint32_t mb_size;
	uint16_t mb_magic;
	int8_t mb_order;
	uint8_t mb_worker_id;
};

struct mem_cache_block {
	struct dlist mcb_list;
	struct dlist mcb_used_head;
	struct dlist mcb_free_head;
	struct mem_cache *mcb_cache;
	int mcb_used;
	int mcb_size;
};

struct mem_cache {
	struct dlist mc_block_head;
	int mc_buf_size;
	u_short mc_size;
	uint8_t mc_worker_id;
	char mc_name[25];
};

#if 0
#define MEM_BUF_FOREACH(m, cache) \
	UNIQV(
	DLIST_FOREACH(struct 
	     m != NULL && ((tmp_id = mbuf_get_id(m) + 1), 1); \
	     m = mbuf_next(p, tmp_id))
#endif

void mem_cache_init(struct mem_cache *, uint8_t, int);
void mem_cache_deinit(struct mem_cache *);
void *mem_cache_alloc(struct mem_cache *);

void *mem_alloc(u_int);
void *mem_realloc(void *, u_int);
void mem_free(void *);
void mem_free_rcu(void *);


void mem_worker_init();
void mem_reclaim_rcu();

#endif // GBTCP_MBUF_H
