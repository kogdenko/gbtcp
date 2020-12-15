// GPL v2
#include "internals.h"

#define CURMOD mm

#define MEM_BUF_MAGIC 0xcafe

#define mem_sb shared

struct mem_cache_block {
	struct dlist mcb_list;
	struct dlist mcb_free_head;
	struct mem_cache *mcb_cache;
	int mcb_used;
	int mcb_size;
};


static void rcu_reload();
void garbage_collector(struct service *);

static void
mem_lock()
{
	spinlock_lock(&mem_sb->mmsb_lock);
}

static void
mem_unlock()
{
	if (current != NULL) {
		garbage_collector(current);
	}
	spinlock_unlock(&mem_sb->mmsb_lock);
}

static int
mem_is_buddy(uintptr_t ptr, size_t size)
{
	return ptr > mem_sb->mmsb_begin + sizeof(*mem_sb) &&
		ptr + size <= mem_sb->mmsb_end;
}

void
mem_buddy_init()
{
	int order, algn_order, size_order;
	uintptr_t addr, begin, size;
	struct dlist *area;
	struct mem_buf *m;

	begin = mem_sb->mmsb_begin + sizeof(*mem_sb);
	addr = ROUND_UP(begin, 1 << BUDDY_ORDER_MIN);
	while (1) {
		algn_order = ffsll(addr) - 1;
		assert(algn_order >= BUDDY_ORDER_MIN);
		size = lower_pow2_64(mem_sb->mmsb_end - addr);
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
		area = &mem_sb->mmsb_buddy_area[order - BUDDY_ORDER_MIN];
		DLIST_INSERT_HEAD(area, m, mb_list);
	}
}

static struct mem_buf *
mem_buddy_alloc(int order)
{
	int i;
	struct dlist *area;
	struct mem_buf *m, *buddy;

	area = &mem_sb->mmsb_buddy_area[order - BUDDY_ORDER_MIN];
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
	area = &mem_sb->mmsb_buddy_area[order - BUDDY_ORDER_MIN];
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
		m->mb_worker_id = cache->mc_worker_id;
		DLIST_INSERT_TAIL(&b->mcb_free_head, m, mb_list);
	}
	DLIST_INSERT_HEAD(&cache->mc_block_head, b, mcb_list);
	cache->mc_size++;
	return b;
}

static void
mem_cache_init(struct mem_cache *cache, uint8_t worker_id, int order)
{
	cache->mc_order = order;
	cache->mc_size = 0;
	cache->mc_worker_id = worker_id;
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

	assert(current->p_sid == cache->mc_worker_id);
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
		slab = &current->wmm_slab[order - SLAB_ORDER_MIN];
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
	} else if (m->mb_worker_id == current->p_sid) {
		mem_cache_free_reclaim(m);
	} else {
		DLIST_INSERT_TAIL(&current->wmm_garbage, m, mb_list);
	}
}

#define RCU_ACTIVE(w) &((w)->wmm_rcu_head[(w)->wmm_rcu_active])
#define RCU_SHADOW(w) &((w)->wmm_rcu_head[(1 - (w)->wmm_rcu_active)])

void
mem_free_rcu(void *ptr)
{
	struct mem_buf *m;

	m = ((struct mem_buf *)ptr) - 1;
	DLIST_INSERT_TAIL(RCU_SHADOW(current), m, mb_list);
	rcu_reload();
}

void
garbage_collector(struct service *s)
{
	struct mem_buf *m;
	struct dlist *head;

	while (!dlist_is_empty(&s->wmm_garbage)) {
		m = DLIST_FIRST(&s->wmm_garbage, struct mem_buf, mb_list);
		DLIST_REMOVE(m, mb_list);
		head = &mem_sb->mmsb_garbage[m->mb_worker_id];
		DLIST_INSERT_TAIL(head, m, mb_list);
	}
	head = &mem_sb->mmsb_garbage[s->p_sid];
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
// e - worker rcu epoch (wmm_rcu_epoch)
// 
// Between @< and @> worker can touch already freed RCU objects.
// The purpose of updater is realise when we can reclaim freed
// rcu object (we can reclaim object when nobody has reference to it).
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

	while (!dlist_is_empty(RCU_ACTIVE(current))) {
		m = DLIST_FIRST(RCU_ACTIVE(current), struct mem_buf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mem_free(m + 1);
	}
}

static void
rcu_reload()
{
	int i;
	struct service *w;

	if (current->wmm_rcu_max) {
		return;
	}
	assert(dlist_is_empty(RCU_ACTIVE(current)));
	if (dlist_is_empty(RCU_SHADOW(current))) {
		return;
	}
	// swap shadow/active
	current->wmm_rcu_active = 1 - current->wmm_rcu_active;
	smp_rmb();
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		w = shared->shm_services + i;
		if (w != current) {
			current->wmm_rcu[i] = READ_ONCE(w->wmm_rcu_epoch);
			if (current->wmm_rcu[i]) {
				current->wmm_rcu_max = i + 1;
			}
		}
	}
	if (current->wmm_rcu_max == 0) {
		rcu_free();
	}
}

void
rcu_update()
{
	u_int i, e, rcu_max;
	struct service *w;

	e = current->wmm_rcu_epoch + 1;
	if (e == 0) {
		e++;
	}
	WRITE_ONCE(current->wmm_rcu_epoch, e);
	if (current->wmm_rcu_max == 0) {
		return;
	}
	smp_rmb();
	rcu_max = 0;
	for (i = 0; i < current->wmm_rcu_max; ++i) {
		w = shared->shm_services + i;
		if (current->wmm_rcu[i]) {
			e = READ_ONCE(w->wmm_rcu_epoch);
			if (abs(e - current->wmm_rcu[i]) > 2) {
				current->wmm_rcu[i] = 0;
			} else {
				rcu_max = i + 1;
			}
		}
	}
	current->wmm_rcu_max = rcu_max;
	if (current->wmm_rcu_max == 0) {
		rcu_free();
		rcu_reload();
	}
}

void
init_worker_mem(struct service *w)
{
	int i, order;

	dlist_init(&w->wmm_garbage);
	for (i = 0; i < ARRAY_SIZE(w->wmm_slab); ++i) {
		order = i + SLAB_ORDER_MIN;
		mem_cache_init(&w->wmm_slab[i], w->p_sid, order);
	}
	for (i = 0; i < ARRAY_SIZE(w->wmm_rcu_head); ++i) {
		dlist_init(&w->wmm_rcu_head[i]);	
	}
	w->wmm_rcu_active = 0;
	w->wmm_rcu_max = 0;
	memset(w->wmm_rcu, 0, sizeof(w->wmm_rcu));
}

void
deinit_worker_mem(struct service *w)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(w->wmm_slab); ++i) {
		mem_cache_deinit(&w->wmm_slab[i]);
	}
	for (i = 0; i < ARRAY_SIZE(w->wmm_rcu_head); ++i) {
		dlist_splice_tail_init(RCU_SHADOW(current),
			&w->wmm_rcu_head[i]);
	}
	rcu_reload();
}
