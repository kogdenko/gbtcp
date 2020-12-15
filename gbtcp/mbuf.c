// GPL v2
#include "internals.h"

#define CURMOD mm

#define CHUNK_SIZE 1*1024*1024

#define MEM_BUF_MAGIC 0xcafe

#define mem_sb shared

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
init_memory()
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

void
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

void *
mem_realloc(void *ptr, u_int size)
{
	int order, order0;
	struct mem_buf *m, *m0;

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
			m = m0;
			goto ok;
		}
	}
	if (order < BUDDY_ORDER_MIN) {
		order = BUDDY_ORDER_MIN;
	}	
	mem_lock();
	m = mem_buddy_alloc(order);
	mem_unlock();
	if (m != NULL) {
		if (m0 != NULL) {
			memcpy(m + 1, m0 + 1, MIN(size, m0->mb_size));
			mem_free(m0 + 1);
		}
ok:
		m->mb_size = size;
		INFO(0, "ok; size=%d, ptr=%p", size, m + 1);
		return m + 1;
	} else {
		WARN(ENOMEM, "failed; size=%d", size);
		return NULL;
	}
}

void *
mem_alloc(u_int size)
{
	return mem_realloc(NULL, size);
}

static struct mem_cache_block *
mem_cache_block_alloc(struct mem_cache *cache)
{
	int i, order, data_size;
	uintptr_t addr;
	struct mem_cache_block *b;
	struct mem_buf *m;

	// TODO: choose data size
	data_size = CHUNK_SIZE - sizeof(struct mem_buf);
	b = mem_alloc(data_size);
	if (b == NULL) {
		return NULL;
	}
	order = ffs(cache->mc_buf_size) + 1;
	dlist_init(&b->mcb_used_head);
	dlist_init(&b->mcb_free_head);
	b->mcb_cache = cache;
	b->mcb_used = 0;
	b->mcb_size = data_size / cache->mc_buf_size;
	for (i = 0; i < b->mcb_size; ++i) {
		addr = (uintptr_t)(b + 1) + i * cache->mc_buf_size;
		m = (struct mem_buf *)addr;
		m->mb_magic = MEM_BUF_MAGIC;
		m->mb_order = order;
		m->mb_block = b;
		m->mb_worker_id = cache->mc_worker_id;
		DLIST_INSERT_TAIL(&b->mcb_free_head, m, mb_list);
	}
	DLIST_INSERT_HEAD(&cache->mc_block_head, b, mcb_list);
	cache->mc_size++;
	return b;
}

void
mem_cache_init(struct mem_cache *cache, uint8_t worker_id,
	int data_size)
{
	int buf_size;

	buf_size = ROUND_UP(sizeof(struct mem_buf) + data_size, ALIGN_PTR);
	cache->mc_buf_size = buf_size;
	cache->mc_size = 0;
	cache->mc_worker_id = worker_id;
	dlist_init(&cache->mc_block_head);
//	strzcpy(cache->mc_name, name, sizeof(cache->mc_name));
//	INFO(0, "ok; cache=%s", name);
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

void *
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
	DLIST_INSERT_HEAD(&b->mcb_used_head, m, mb_list);
	b->mcb_used++;
	if (b->mcb_used == b->mcb_size) {
		DLIST_REMOVE(b, mcb_list);
		DLIST_INSERT_TAIL(&cache->mc_block_head, b, mcb_list);
	}
	return m + 1;
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
	DLIST_REMOVE(m, mb_list);
	DLIST_INSERT_HEAD(&b->mcb_free_head, m, mb_list);
	if (b->mcb_used == b->mcb_size && cache != NULL) {
		DLIST_REMOVE(b, mcb_list);
		DLIST_INSERT_HEAD(&cache->mc_block_head, b, mcb_list);
	}
	assert(b->mcb_used);
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

void
mem_free(void *ptr)
{
	struct mem_buf *m;

	if (ptr == NULL) {
		return;
	}
	m = ((struct mem_buf *)ptr) - 1;
	if (m->mb_block == NULL) {
		mem_lock();
		mem_buddy_free(m);
		mem_unlock();
	} else if (m->mb_worker_id == current->p_sid) {
		mem_cache_free_reclaim(m);
	} else {
		DLIST_INSERT_TAIL(&current->p_mbuf_garbage_head, m, mb_list);
	}
}

void
garbage_collector(struct service *s)
{
	struct mem_buf *m;
	struct dlist *head;

	while (!dlist_is_empty(&s->p_mbuf_garbage_head)) {
		m = DLIST_FIRST(&s->p_mbuf_garbage_head, struct mem_buf, mb_list);
		DLIST_REMOVE(m, mb_list);
		head = &shared->shm_garbage_head[m->mb_worker_id];
		DLIST_INSERT_TAIL(head, m, mb_list);
	}
	head = &shared->shm_garbage_head[s->p_sid];
	while (!dlist_is_empty(head)) {
		m = DLIST_FIRST(head, struct mem_buf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mem_cache_free_reclaim(m);
	}
}

static int service_rcu_max;
static struct dlist service_rcu_active_head;
static struct dlist service_rcu_shadow_head;
static u_int service_rcu[GT_SERVICES_MAX];

void
mem_worker_init()
{
	dlist_init(&service_rcu_active_head);
	dlist_init(&service_rcu_shadow_head);
	service_rcu_max = 0;
	memset(service_rcu, 0, sizeof(service_rcu));
}

static void
service_rcu_reload()
{
	int i;
	struct service *s;

	dlist_replace_init(&service_rcu_active_head, &service_rcu_shadow_head);
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		s = shared->shm_services + i;
		if (s != current) {
			service_rcu[i] = service_load_epoch(s);
			if (service_rcu[i]) {
				service_rcu_max = i + 1;
			}
		}
	}
	//if (service_rcu_max == 0) {
	//	service_rcu_free();
	//}
}

void
mem_free_rcu(void *ptr)
{
	struct mem_buf *m;

	m = ((struct mem_buf *)ptr) - 1;
	DLIST_INSERT_TAIL(&service_rcu_shadow_head, m, mb_list);
	if (service_rcu_max == 0) {
		assert(dlist_is_empty(&service_rcu_active_head));
		service_rcu_reload();
	}
}

static void
service_rcu_free()
{
	struct dlist *head;
	struct mem_buf *m;

	head = &service_rcu_active_head;
	while (!dlist_is_empty(head)) {
		m = DLIST_FIRST(head, struct mem_buf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mem_free(m + 1);
	}
}

void
mem_reclaim_rcu()
{
	u_int i, epoch, rcu_max;
	struct service *s;

	rcu_max = 0;
	for (i = 0; i < service_rcu_max; ++i) {
		s = shared->shm_services + i;
		if (service_rcu[i]) {
			epoch = service_load_epoch(s);
			if (service_rcu[i] != epoch) {
				service_rcu[i] = 0;
			} else {
				rcu_max = i + 1;
			}
		}
	}
	service_rcu_max = rcu_max;
	if (service_rcu_max == 0) {
		service_rcu_free();
		if (!dlist_is_empty(&service_rcu_shadow_head)) {
			service_rcu_reload();
		}
	}
}

