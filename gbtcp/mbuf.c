// GPL v2
#include "internals.h"

#define CURMOD mm

#define MEM_BUF_MAGIC 0xcafe

#define super shared

struct mem_cache_block {
	struct dlist mcb_list;
	struct dlist mcb_free_head;
	struct mem_cache *mcb_cache;
	int mcb_used;
	int mcb_size;
};

static void rcu_reload();
void garbage_collector();

static void
mem_lock()
{
	spinlock_lock(&super->msb_lock);
}

static void
mem_unlock()
{
	if (current != NULL) {
		garbage_collector();
	}
	spinlock_unlock(&super->msb_lock);
}

static int
mem_is_buddy(uintptr_t ptr, size_t size)
{
	return ptr > super->msb_begin + sizeof(*super) &&
		ptr + size <= super->msb_end;
}

void
mem_buddy_init()
{
	int order, algn_order, size_order;
	uintptr_t addr, begin, size;
	struct dlist *area;
	struct mem_buf *m;

	begin = super->msb_begin + sizeof(*super);
	addr = ROUND_UP(begin, 1 << BUDDY_ORDER_MIN);
	while (1) {
		algn_order = ffsll(addr) - 1;
		assert(algn_order >= BUDDY_ORDER_MIN);
		size = lower_pow2_64(super->msb_end - addr);
		size_order = ffsll(size) - 1;
		order = MIN3(algn_order, size_order, BUDDY_ORDER_MAX);
		if (order < BUDDY_ORDER_MIN) {
			break;
		}
		m = (struct mem_buf *)addr;
		addr += (1 << order);
		m->mb_magic = MEM_BUF_MAGIC;
		m->mb_block = NULL;
		m->mb_order = -1;
		area = &super->msb_buddy_area[order - BUDDY_ORDER_MIN];
		DLIST_INSERT_HEAD(area, m, mb_list);
	}
}

static struct mem_buf *
mem_buddy_alloc(int order)
{
	int i;
	struct dlist *area;
	struct mem_buf *m, *buddy;

	area = &super->msb_buddy_area[order - BUDDY_ORDER_MIN];
	for (i = order; i <= BUDDY_ORDER_MAX; ++i, ++area) {
		if (!dlist_is_empty(area)) {
			m = DLIST_FIRST(area, struct mem_buf, mb_list);
			break;
		}
	}
	if (i > BUDDY_ORDER_MAX) {
		return NULL;
	}
	DLIST_REMOVE(m, mb_list);
	m->mb_order = order;
	while (i > order) {
		i--;
		area--;
		buddy = (struct mem_buf *)(((uintptr_t)m) + (1 << i));
		buddy->mb_magic = MEM_BUF_MAGIC;
		buddy->mb_block = NULL;
		buddy->mb_order = -1;
		DLIST_INSERT_HEAD(area, buddy, mb_list);
	}
	return m;
}

static void
mem_buddy_free(struct mem_buf *m)
{
	int order, size;
	uintptr_t addr, buddy_addr;
	struct dlist *area;
	struct mem_buf *buddy, *coalesced;

	order = m->mb_order;
	addr = (uintptr_t)m;
	assert(order >= BUDDY_ORDER_MIN);
	assert(order <= BUDDY_ORDER_MAX);
	area = &super->msb_buddy_area[order - BUDDY_ORDER_MIN];
	for (; order < BUDDY_ORDER_MAX; ++order, ++area) {
		size = 1 << order;
		buddy_addr = addr ^ size;
		if (mem_is_buddy(buddy_addr, size))  {
			break;
		}
		buddy = (struct mem_buf *)buddy_addr;
		if (buddy->mb_order != -1) {
			break;
		}
		DLIST_REMOVE(buddy, mb_list);
		addr &= buddy_addr;
	}
	coalesced = (struct mem_buf *)addr;
	coalesced->mb_order = -1;
	DLIST_INSERT_HEAD(area, coalesced, mb_list);
}

static struct mem_cache_block *
mem_cache_block_alloc(struct mem_cache *cache)
{
	int i, data_size;
	uintptr_t addr;
	struct mem_cache_block *b;
	struct mem_buf *m;

	// TODO: choose data size
	data_size = (1 << BUDDY_ORDER_MIN) - sizeof(struct mem_buf);
	b = mem_alloc(data_size);
	if (b == NULL) {
		return NULL;
	}
	dlist_init(&b->mcb_free_head);
	b->mcb_cache = cache;
	b->mcb_used = 0;
	b->mcb_size = data_size / (1 << cache->mc_order);
	for (i = 0; i < b->mcb_size; ++i) {
		addr = (uintptr_t)(b + 1) + (i << cache->mc_order);
		m = (struct mem_buf *)addr;
		m->mb_magic = MEM_BUF_MAGIC;
		m->mb_order = cache->mc_order;
		m->mb_block = b;
		m->mb_cpu_id = cache->mc_cpu_id;
		DLIST_INSERT_TAIL(&b->mcb_free_head, m, mb_list);
	}
	DLIST_INSERT_HEAD(&cache->mc_block_head, b, mcb_list);
	cache->mc_size++;
	return b;
}

static void
mem_cache_init(struct mem_cache *cache, uint8_t cpu_id, int order)
{
	cache->mc_order = order;
	cache->mc_size = 0;
	cache->mc_cpu_id = cpu_id;
	dlist_init(&cache->mc_block_head);
}

void
mem_cache_deinit(struct mem_cache *cache)
{
	struct mem_cache_block *b;

	DLIST_FOREACH(b, &cache->mc_block_head, mcb_list) {
		b->mcb_cache = NULL;
	}
}

struct mem_cache_block *
mem_cache_get_free_block(struct mem_cache *cache)
{
	struct mem_cache_block *b;

	if (dlist_is_empty(&cache->mc_block_head)) {
		return mem_cache_block_alloc(cache);
	}
	b = DLIST_FIRST(&cache->mc_block_head,
		struct mem_cache_block, mcb_list);
	if (b->mcb_used < b->mcb_size) {
		return b;
	} else {
		return mem_cache_block_alloc(cache);
	}
}

static struct mem_buf *
mem_cache_alloc(struct mem_cache *cache)
{
	struct mem_buf *m;
	struct mem_cache_block *b;

	assert(current_cpu_id == cache->mc_cpu_id);
	b = mem_cache_get_free_block(cache);
	if (b == NULL) {
		return NULL;
	}
	assert(b->mcb_size > b->mcb_used);
	assert(!dlist_is_empty(&b->mcb_free_head));
	m = DLIST_FIRST(&b->mcb_free_head, struct mem_buf, mb_list);
	DLIST_REMOVE(m, mb_list);
	b->mcb_used++;
	if (b->mcb_used == b->mcb_size) {
		DLIST_REMOVE(b, mcb_list);
		DLIST_INSERT_TAIL(&cache->mc_block_head, b, mcb_list);
	}
	return m;
}

static void
mem_cache_free_reclaim(struct mem_buf *m)
{
	struct mem_cache *cache;
	struct mem_cache_block *b;

	b = m->mb_block;
	assert(b != NULL);
	assert(b->mcb_used);
	cache = b->mcb_cache;
	DLIST_INSERT_HEAD(&b->mcb_free_head, m, mb_list);
	if (b->mcb_used == b->mcb_size && cache != NULL) {
		DLIST_REMOVE(b, mcb_list);
		DLIST_INSERT_HEAD(&cache->mc_block_head, b, mcb_list);
	}
	b->mcb_used--;
	if (b->mcb_used == 0) {
		if (cache != NULL) {
			if (cache->mc_size == 1) {
				return;
			}		
			DLIST_REMOVE(b, mcb_list);
			cache->mc_size--;
		}
		mem_free(b);
	}
}

void *
mem_realloc(void *ptr, u_int size)
{
	int order, order0;
	struct mem_buf *m, *m0;
	struct mem_cache *slab;

	assert(size <= (1 << BUDDY_ORDER_MAX) - sizeof(*m));
	order = ffs(upper_pow2_32(size + (sizeof(*m)))) - 1;
	if (ptr == NULL) {
		m0 = NULL;
	} else {
		m0 = ((struct mem_buf *)ptr) - 1;
		assert(m0->mb_magic == MEM_BUF_MAGIC);
		order0 = m0->mb_order;
		assert(order0 >= SLAB_ORDER_MIN);
		assert(order0 <= BUDDY_ORDER_MAX);
		assert(m0->mb_size <= (1 << order0) + sizeof(*m0));
		if (order0 == order) {
			m0->mb_size = size;
			return ptr; 
		}
	}
	if (order < SLAB_ORDER_MIN) {
		order = SLAB_ORDER_MIN;
	}
	if (order < BUDDY_ORDER_MIN) {
		slab = &current_cpu->mw_slab[order - SLAB_ORDER_MIN];
		m = mem_cache_alloc(slab);
	} else {
		mem_lock();
		m = mem_buddy_alloc(order);
		mem_unlock();
	}
	if (m != NULL) {
		if (m0 != NULL) {
			memcpy(m + 1, m0 + 1, MIN(size, m0->mb_size));
			mem_free(m0 + 1);
		}
		m->mb_size = size;
		return m + 1;
	} else {
		return NULL;
	}
}

void *
mem_alloc(u_int size)
{
	return mem_realloc(NULL, size);
}

void
mem_free(void *ptr)
{
	struct mem_buf *m;

	if (ptr == NULL) {
		return;
	}
	m = ((struct mem_buf *)ptr) - 1;
	assert(m->mb_magic == MEM_BUF_MAGIC);
	if (m->mb_block == NULL) {
		mem_lock();
		mem_buddy_free(m);
		mem_unlock();
	} else if (m->mb_cpu_id == current_cpu_id) {
		mem_cache_free_reclaim(m);
	} else {
		DLIST_INSERT_TAIL(&current_cpu->mw_garbage, m, mb_list);
	}
}

#define RCU_ACTIVE &(current_cpu->mw_rcu_head[current_cpu->mw_rcu_active])
#define RCU_SHADOW &(current_cpu->mw_rcu_head[1 - current_cpu->mw_rcu_active])

void
mem_free_rcu(void *ptr)
{
	struct mem_buf *m;

	m = ((struct mem_buf *)ptr) - 1;
	DLIST_INSERT_TAIL(RCU_SHADOW, m, mb_list);
	rcu_reload();
}

void
garbage_collector(struct service *s)
{
	struct mem_buf *m;
	struct dlist *head;

	while (!dlist_is_empty(&current_cpu->mw_garbage)) {
		m = DLIST_FIRST(&current_cpu->mw_garbage,
			struct mem_buf, mb_list);
		DLIST_REMOVE(m, mb_list);
		head = &super->msb_garbage[m->mb_cpu_id];
		DLIST_INSERT_TAIL(head, m, mb_list);
	}
	head = &super->msb_garbage[current_cpu_id];
	while (!dlist_is_empty(head)) {
		m = DLIST_FIRST(head, struct mem_buf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mem_cache_free_reclaim(m);
	}
}

// RCU (Read Copy Update)
//
// < - lock (acequire barrier)
// > - unlock (release barrier)
// ^ - read barrier
// e - cpu rcu epoch (mw_rcu_epoch)
// 
// Between lock and unlock cpu can touch already freed RCU objects.
// The purpose of the updater is realise when we can reclaim freed
// rcu objects (we can reclaim objects when nobody has reference to it).
//
// e: 0      1          2            3           4  
// Reader  < e++ >     < e++ >     < e++ >     < e++ >
// Memory-------------------------------------------
// Updater   ^      ^    ^      ^    ^
// e:        0/1    1    1/2    2    2/3

static void
rcu_free()
{
	struct mem_buf *m;

	while (!dlist_is_empty(RCU_ACTIVE)) {
		m = DLIST_FIRST(RCU_ACTIVE, struct mem_buf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mem_free(m + 1);
	}
}

static void
rcu_reload()
{
	int i;
	struct service *w;

	if (!dlist_is_empty(RCU_ACTIVE) || dlist_is_empty(RCU_SHADOW)) {
		return;
	}
	// swap shadow/active
	current_cpu->mw_rcu_active = 1 - current_cpu->mw_rcu_active;
	smp_rmb();
	for (i = 0; i < N_CPUS; ++i) {
		w = shared->shm_cpus + i;
		current_cpu->mw_rcu[i] = READ_ONCE(w->mw_rcu_epoch);
	}
}

void
rcu_update()
{
	u_int i, e;
	struct service *w;

	e = current_cpu->mw_rcu_epoch + 1;
	WRITE_ONCE(current_cpu->mw_rcu_epoch, e);
	smp_rmb();
	for (i = 0; i < N_CPUS; ++i) {
		w = shared->shm_cpus + i;
		e = READ_ONCE(w->mw_rcu_epoch);
		if (abs(e - current_cpu->mw_rcu[i]) < 2) {
			return;
		}
	}
	rcu_free();
	rcu_reload();
}

void
init_mem(int cpu_id)
{
	int i, order;
	struct service *w;
	
	w = shared->shm_cpus + cpu_id;
	dlist_init(&w->mw_garbage);
	for (i = 0; i < ARRAY_SIZE(w->mw_slab); ++i) {
		order = i + SLAB_ORDER_MIN;
		mem_cache_init(&w->mw_slab[i], cpu_id, order);
	}
	for (i = 0; i < ARRAY_SIZE(w->mw_rcu_head); ++i) {
		dlist_init(&w->mw_rcu_head[i]);	
	}
	w->mw_rcu_active = 0;
}

/*void
deinit_worker_mem(struct service *w)
{
	int i;

	assert(current != w);
	mem_lock();
	WRITE_ONCE(w->mw_rcu_epoch, 0);
	mem_unlock();
	for (i = 0; i < ARRAY_SIZE(w->mw_slab); ++i) {
		mem_cache_deinit(&w->mw_slab[i]);
	}
	for (i = 0; i < ARRAY_SIZE(w->mw_rcu_head); ++i) {
		dlist_splice_tail_init(RCU_SHADOW, &w->mw_rcu_head[i]);
	}
	rcu_reload();
}*/
