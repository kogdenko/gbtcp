// GPL v2
#include "internals.h"

#define CURMOD mm

#define MEM_BUF_MAGIC 0xfeca


#define RCU_ACTIVE &(current_cpu->mw_rcu_head[current_cpu->mw_rcu_active])
#define RCU_SHADOW &(current_cpu->mw_rcu_head[1 - current_cpu->mw_rcu_active])

struct mem_cache_block {
	struct dlist mcb_list;
	struct dlist mcb_free_head;
	struct mem_cache *mcb_cache;
	int mcb_used;
	int mcb_size;
};

static void rcu_reload();
void garbage_collector();

static int
size_to_order(int size)
{
	int order;

	order = ffs(upper_pow2_32(size)) - 1;
	return order;
}

static int
order_to_size(int order)
{
	return 1 << order;
}

static void
mem_lock()
{
	spinlock_lock(&super->msb_global_lock);
}

static void
mem_unlock()
{
	if (current != NULL) {
		garbage_collector();
	}
	spinlock_unlock(&super->msb_global_lock);
}

static int
mem_buddy_is_buddy(struct mem_buddy *b, uintptr_t beg, size_t size)
{
	uintptr_t end;

	end = beg + size - 1;
	return beg >= b->mbd_beg && end <= b->mbd_end;
}

static int
mem_buddy_is_inited(struct mem_buddy *b)
{
	return b->mbd_buf != NULL;
}

void
mem_buddy_init(struct mem_buddy *b, int order_min, int order_max,
		void *buf, int hdr_size, int size)
{
	int i, order, algn_order, rem_order;
	uintptr_t addr, rem;
	struct mem_buf *m;

	assert(order_max - order_min + 1 <= ARRAY_SIZE(b->mbd_head));
	b->mbd_order_min = order_min;
	b->mbd_order_max = order_max;
	b->mbd_buf = buf;
	b->mbd_beg = (uintptr_t)buf + hdr_size;
	b->mbd_end = b->mbd_beg + size - hdr_size - 1;
	for (i = 0; i < ARRAY_SIZE(b->mbd_head); ++i) {
		dlist_init(&b->mbd_head[i]);
	}
	addr = ROUND_UP(b->mbd_beg, 1 << order_min);
	while (1) {
		algn_order = ffsll(addr) - 1;
		assert(algn_order >= b->mbd_order_min);
		rem = lower_pow2_64(b->mbd_end - addr);
		rem_order = ffsll(rem) - 1;
		order = MIN3(algn_order, rem_order, order_max);
		if (order < order_min) {
			break;
		}
		m = (struct mem_buf *)addr;
		addr += (1 << order);
		m->mb_magic = MEM_BUF_MAGIC;
		m->mb_block = NULL;
		m->mb_order = -1;
		DLIST_INSERT_HEAD(&b->mbd_head[order - order_min], m, mb_list);
	}
}

static struct mem_buf *
mem_buddy_alloc(struct mem_buddy *b, u_int order)
{
	int i;
	struct dlist *head;
	struct mem_buf *m, *buddy;

	if (order < b->mbd_order_min) {
		order = b->mbd_order_min;
	}
	assert(order <= b->mbd_order_max);
	head = &b->mbd_head[order - b->mbd_order_min];
	for (i = order; i <= b->mbd_order_max; ++i, ++head) {
		if (!dlist_is_empty(head)) {
			m = DLIST_FIRST(head, struct mem_buf, mb_list);
			break;
		}
	}
	if (i > b->mbd_order_max) {
		return NULL;
	}
	DLIST_REMOVE(m, mb_list);
	m->mb_order = order;
	while (i > order) {
		i--;
		head--;
		buddy = (struct mem_buf *)(((uintptr_t)m) + (1 << i));
		buddy->mb_magic = MEM_BUF_MAGIC;
		buddy->mb_block = NULL;
		buddy->mb_order = -1;
		DLIST_INSERT_HEAD(head, buddy, mb_list);
	}
	return m;
}

static void
mem_buddy_free(struct mem_buddy *b, struct mem_buf *m)
{
	int order;
	uintptr_t size, addr, buddy_addr;
	struct dlist *head;
	struct mem_buf *buddy, *coalesced;

	order = m->mb_order;
	addr = (uintptr_t)m;
	assert(order >= b->mbd_order_min);
	assert(order <= b->mbd_order_max);
	head = &b->mbd_head[order - b->mbd_order_min];
	for (; order < b->mbd_order_max; ++order, ++head) {
		size = 1 << order;
		buddy_addr = addr ^ size;
		if (mem_buddy_is_buddy(b, buddy_addr, size))  {
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
	DLIST_INSERT_HEAD(head, coalesced, mb_list);
}

static struct mem_cache_block *
mem_cache_block_alloc(struct mem_cache *cache)
{
	int i, data_size;
	uintptr_t addr;
	struct mem_cache_block *b;
	struct mem_buf *m;

	// TODO: choose data size
	data_size = (1 << GLOBAL_BUDDY_ORDER_MIN) - sizeof(struct mem_buf);
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
mem_buf_alloc(int cpu_id, u_int order)
{
	struct mem_buf *m;
	struct mem_cache *slab;
	struct cpu *cpu;

	assert(order <= GLOBAL_BUDDY_ORDER_MAX);
	if (order < SLAB_ORDER_MIN) {
		order = SLAB_ORDER_MIN;
	}
	if (order < GLOBAL_BUDDY_ORDER_MIN) {
		cpu = cpu_get(cpu_id);
	
		slab = &cpu->cpu_mem_cache[order - SLAB_ORDER_MIN];

		spinlock_lock(&cpu->cpu_mem_cache_lock);
		m = mem_cache_alloc(slab);
		spinlock_unlock(&cpu->cpu_mem_cache_lock);

	} else {
		mem_lock();
		m = mem_buddy_alloc(&super->msb_global_buddy, order);
		mem_unlock();
	}
	return m;
}

void
mem_buf_free(struct mem_buf *m)
{
	assert(m->mb_magic == MEM_BUF_MAGIC);
	if (m->mb_block == NULL) {
		mem_lock();
		mem_buddy_free(&super->msb_global_buddy, m);
		mem_unlock();
	} else if (m->mb_cpu_id == current_cpu_id) {
		spinlock_lock(&current_cpu->cpu_mem_cache_lock);
		mem_cache_free_reclaim(m);
		spinlock_unlock(&current_cpu->cpu_mem_cache_lock);
	} else {
		DLIST_INSERT_TAIL(&current_cpu->mw_garbage, m, mb_list);
	}
}

void
mem_buf_free_rcu(struct mem_buf *m)
{
	DLIST_INSERT_TAIL(RCU_SHADOW, m, mb_list);
	rcu_reload();
}

void *
mem_realloc(void *ptr, u_int size)
{
	u_int order, order0;
	struct mem_buf *m0, *m;

	order = size_to_order(size + sizeof(*m));
	if (ptr == NULL) {
		m0 = NULL;
	} else {
		m0 = (struct mem_buf *)ptr - 1;
		assert(m0->mb_magic == MEM_BUF_MAGIC);
		order0 = m0->mb_order;
		assert(order0 >= SLAB_ORDER_MIN);
		assert(order0 <= GLOBAL_BUDDY_ORDER_MAX);
		assert(m0->mb_size + sizeof(*m0) <= (1 << order0));
		if (order0 == order) {
			m0->mb_size = size;
			return ptr; 
		}
	}
	m = mem_buf_alloc(current_cpu_id, order);
	if (m == NULL) {
		return NULL;
	} else {
		if (m0 != NULL) {
			memcpy(m + 1, m0 + 1, MIN(size, m0->mb_size));
			mem_buf_free(m0);
		}
		m->mb_size = size;
		return m + 1;
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
	if (ptr != NULL) {
		mem_buf_free(((struct mem_buf *)ptr) - 1);
	}
}

void
mem_free_rcu(void *ptr)
{
	if (ptr != NULL) {
		mem_buf_free_rcu(((struct mem_buf *)ptr) - 1);
	}
}

#define PERCPU_LOCK spinlock_lock(&super->msb_percpu_lock)
#define PERCPU_UNLOCK spinlock_unlock(&super->msb_percpu_lock)

static int
percpu_buf_init(int buf_id)
{
	int i, j;
	u_int buf_order, buf_size;
	struct mem_buddy *b;
	struct mem_buf *m, *m2;
	struct cpu *cpu;

	b = &super->msb_percpu_buddy[buf_id];
	buf_order = PERCPU_BUF_ORDER_MIN + buf_id;
	buf_size = order_to_size(buf_order);
	m2 = mem_buf_alloc(AUX_CPU_ID, buf_order);
	if (m2 == NULL) {
		return -ENOMEM;
	}
	for (i = 0; i < CPU_NUM; ++i) {
		cpu = cpu_get(i);
		m = mem_buf_alloc(i, buf_order);
		cpu->cpu_percpu_buf[buf_id] = m;
		if (m == NULL) {
			mem_buf_free(m2);
			for (j = 0; j < i; ++j) {
				cpu = cpu_get(j);
				m = cpu->cpu_percpu_buf[buf_id];
				cpu->cpu_percpu_buf[buf_id] = NULL;
				mem_buf_free(m);
			}
			return -ENOMEM;
		}
	}
	mem_buddy_init(b, PERCPU_BUDDY_ORDER_MIN, PERCPU_BUDDY_ORDER_MAX,
		m, sizeof(m), buf_size);
	return 0;
}

static int
percpu_alloc_locked(struct percpu *pc, int size)
{
	int i, rc, order;
	struct mem_buddy *b;
	struct mem_buf *m;

	order = size_to_order(size);
	for (i = 0; i < PERCPU_BUF_NUM; ++i) {
		b = &super->msb_percpu_buddy[i];
		if (!mem_buddy_is_inited(b)) {
			rc = percpu_buf_init(i);
			if (rc) {
				return rc;
			}
		}
		m = mem_buddy_alloc(b, order);
		if (m != NULL) {
			pc->perc_buf_id = i;
			pc->perc_offset = (u_char *)m - b->mbd_buf;
			return 0;
		}
	}
	return -ENOMEM;
}

int
percpu_alloc(struct percpu *pc, int size)
{
	int rc;

	PERCPU_LOCK;
	rc = percpu_alloc_locked(pc, size);
	PERCPU_UNLOCK;
	return rc;
}

void
percpu_free(struct percpu *pc)
{
	assert(0);
}

void *
percpu_get(int cpu_id, struct percpu *pc)
{
	struct cpu *cpu;

	cpu = cpu_get(cpu_id);
	assert(pc->perc_buf_id < PERCPU_BUF_NUM);
	// TODO: checks
	return cpu->cpu_percpu_buf[pc->perc_buf_id] + pc->perc_offset;
}

int
counter64_init(counter64_t *c)
{
	return percpu_alloc(c, sizeof(uint64_t));
}

void
counter64_fini(counter64_t *c)
{
	percpu_free(c);
}

void
counter64_add(counter64_t *c, uint64_t a)
{
	*((uint64_t *)percpu_get(current_cpu_id, c)) += a;
}

uint64_t
counter64_get(counter64_t *c)
{
	uint64_t accum, *it;

	accum = 0;
	PERCPU_FOREACH(it, c) {
		accum += *it;
	}
	return accum;
}

void
garbage_collector()
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
	struct cpu *cpu;

	if (!dlist_is_empty(RCU_ACTIVE) || dlist_is_empty(RCU_SHADOW)) {
		return;
	}
	// swap shadow/active
	current_cpu->mw_rcu_active = 1 - current_cpu->mw_rcu_active;
	smp_rmb();
	for (i = 0; i < CPU_NUM; ++i) {
		cpu = shared->msb_cpus + i;
		current_cpu->mw_rcu[i] = READ_ONCE(cpu->mw_rcu_epoch);
	}
}

void
rcu_update()
{
	u_int i, e;
	struct cpu *cpu;

	e = current_cpu->mw_rcu_epoch + 1;
	WRITE_ONCE(current_cpu->mw_rcu_epoch, e);
	smp_rmb();
	for (i = 0; i < CPU_NUM; ++i) {
		cpu = cpu_get(i);
		e = READ_ONCE(cpu->mw_rcu_epoch);
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
	struct cpu *cpu;
	
	cpu = cpu_get(cpu_id);
	dlist_init(&cpu->mw_garbage);
	for (i = 0; i < ARRAY_SIZE(cpu->cpu_mem_cache); ++i) {
		order = i + SLAB_ORDER_MIN;
		mem_cache_init(&cpu->cpu_mem_cache[i], cpu_id, order);
	}
	for (i = 0; i < ARRAY_SIZE(cpu->mw_rcu_head); ++i) {
		dlist_init(&cpu->mw_rcu_head[i]);	
	}
	cpu->mw_rcu_active = 0;
}

/*void
deinit_worker_mem()
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
