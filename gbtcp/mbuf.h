// GPL v2
#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "list.h"

#define SLAB_ORDER_MIN 6 // 64b
#define BUDDY_ORDER_MIN 21 // ~2Mb
#define BUDDY_ORDER_MAX 27 // ~134Mb

#define MEM_HDRSZ sizeof(struct mem_buf)

#define PACKET_BUFSZ (2048 - MEM_HDRSZ)

struct mem_buf {
	struct dlist mb_list;
	struct mem_cache_block *mb_block;
	uint32_t mb_size;
	uint16_t mb_magic;
	int8_t mb_order;
	uint8_t mb_worker_id;
};

struct mem_cache {
	struct dlist mc_block_head;
	u_short mc_size;
	int8_t mc_order;
	uint8_t mc_worker_id;
};

void init_worker_mem();
void deinit_worker_mem();

void *mem_alloc(u_int);
void *mem_realloc(void *, u_int);
void mem_free(void *);
void mem_free_rcu(void *);

void rcu_update();

#endif // GBTCP_MBUF_H
