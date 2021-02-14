// GPL v2
#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "list.h"

#define MEM_BUF_ORDER 5 // 32 b

#define SLAB_ORDER_MIN 6 // 64b
#define GLOBAL_BUDDY_ORDER_MIN 21 // ~2Mb
#define GLOBAL_BUDDY_ORDER_MAX 27 // ~134Mb
#define GLOBAL_BUDDY_ORDER_NUM \
	(GLOBAL_BUDDY_ORDER_MAX - GLOBAL_BUDDY_ORDER_MIN + 1)

// Can allocate ~4Mb per cpu
#define PERCPU_BUF_ORDER_MIN 14
#define PERCPU_BUF_ORDER_MAX 21
#define PERCPU_BUDDY_ORDER_MIN MEM_BUF_ORDER
#define PERCPU_BUDDY_ORDER_MAX PERCPU_BUF_ORDER_MAX
#define PERCPU_BUDDY_ORDER_NUM \
	(PERCPU_BUDDY_ORDER_MAX - PERCPU_BUDDY_ORDER_MIN + 1)
#define PERCPU_BUF_NUM (PERCPU_BUF_ORDER_MAX - PERCPU_BUF_ORDER_MIN + 1)

#define MEM_HDRSZ sizeof(struct mem_buf)

#define PACKET_BUFSZ (2048 - MEM_HDRSZ)

struct mem_buf {
	struct dlist mb_list;
	struct mem_cache_block *mb_block;
	uint32_t mb_size;
	uint16_t mb_magic;
	int8_t mb_order;
	uint8_t mb_cpu_id;
};

struct mem_cache {
	struct dlist mc_block_head;
	u_short mc_size;
	int8_t mc_order;
	uint8_t mc_cpu_id;
};

#define MEM_BUDDY_HEAD_NUM MAX(GLOBAL_BUDDY_ORDER_NUM, PERCPU_BUDDY_ORDER_NUM)

struct mem_buddy {
	u_char *mbd_buf;
	int mbd_order_min;
	int mbd_order_max;
	uintptr_t mbd_beg;
	uintptr_t mbd_end;
	struct dlist mbd_head[MEM_BUDDY_HEAD_NUM];
};

void init_mem(int);
void fini_mem();

void *mem_alloc(u_int);
void *mem_realloc(void *, u_int);
void mem_free(void *);
void mem_free_rcu(void *);

struct percpu {
	uint8_t perc_buf_id;
	u_int perc_offset;
};

#define PERCPU_FOREACH(var, percpu) \
	for (int UNIQV(i) = 0; \
	     UNIQV(i) < CPU_NUM && (var = percpu_get(UNIQV(i), percpu)); \
	     ++UNIQV(i))

int percpu_alloc(struct percpu *, int);
void percpu_free(struct percpu *);
void *percpu_get(int, struct percpu *);

typedef struct percpu counter64_t;

int counter64_init(counter64_t *);
void counter64_fini(counter64_t *);
void counter64_add(counter64_t *, uint64_t);
#define counter64_inc(c) counter64_add(c, 1)
uint64_t counter64_get(counter64_t *);


void rcu_update();

#endif // GBTCP_MBUF_H
