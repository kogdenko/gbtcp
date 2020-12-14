// GPL v2
#include "internals.h"

#define CURMOD mm

#define CHUNK_SIZE 1*1024*1024

#define MEM_HDR_MAGIC 0xcafe


#define mem_sb shared

struct mm_mod {
	struct log_scope log_scope;
};

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
	uintptr_t mh_addr, begin, size;
	struct dlist *area;
	struct mem_hdr *mh;

	begin = mem_sb->mmsb_begin + sizeof(*mem_sb);
	mh_addr = ROUND_UP(begin, 1 << BUDDY_ORDER_MIN);
	while (1) {
		algn_order = ffsll(mh_addr) - 1;
		assert(algn_order >= BUDDY_ORDER_MIN);
		size = lower_pow2_64(mem_sb->mmsb_end - mh_addr);
		size_order = ffsll(size) - 1;
		order = MIN3(algn_order, size_order, BUDDY_ORDER_MAX);
		if (order < BUDDY_ORDER_MIN) {
			break;
		}
		mh = (struct mem_hdr *)mh_addr;
		mh_addr += (1 << order);
		mh->mmh_magic = MEM_HDR_MAGIC;
		mh->mmh_order = -1;
		area = &mem_sb->mmsb_buddy_area[order - BUDDY_ORDER_MIN];
		DLIST_INSERT_HEAD(area, mh, mmh_list);
	}
}

void
mem_buddy_free(struct mem_hdr *mh)
{
	int order, size;
	uintptr_t mh_addr, buddy_addr;
	struct dlist *area;
	struct mem_hdr *buddy, *coalesced;

	order = mh->mmh_order;
	mh_addr = (uintptr_t)mh;
	assert(order >= BUDDY_ORDER_MIN);
	assert(order <= BUDDY_ORDER_MAX);
	area = &mem_sb->mmsb_buddy_area[order - BUDDY_ORDER_MIN];
	for (; order < BUDDY_ORDER_MAX; ++order, ++area) {
		size = 1 << order;
		buddy_addr = mh_addr ^ size;
		if (mem_is_buddy(buddy_addr, size))  {
			break;
		}
		buddy = (struct mem_hdr *)buddy_addr;
		if (buddy->mmh_order != -1) {
			break;
		}
		DLIST_REMOVE(buddy, mmh_list);
		mh_addr &= buddy_addr;
	}
	coalesced = (struct mem_hdr *)mh_addr;
	coalesced->mmh_order = -1;
	DLIST_INSERT_HEAD(area, coalesced, mmh_list);
}

static struct mem_hdr *
mem_buddy_alloc(int order)
{
	int i;
	struct dlist *area;
	struct mem_hdr *mh, *buddy;

	area = &mem_sb->mmsb_buddy_area[order - BUDDY_ORDER_MIN];
	for (i = order; i <= BUDDY_ORDER_MAX; ++i, ++area) {
		if (!dlist_is_empty(area)) {
			mh = DLIST_FIRST(area, struct mem_hdr, mmh_list);
			break;
		}
	}
	if (i > BUDDY_ORDER_MAX) {
		return NULL;
	}
	DLIST_REMOVE(mh, mmh_list);
	mh->mmh_order = order;
	while (i > order) {
		i--;
		area--;
		buddy = (struct mem_hdr *)(((u_char *)mh) + (1 << i));
		buddy->mmh_order = -1;
		buddy->mmh_magic = MEM_HDR_MAGIC;
		DLIST_INSERT_HEAD(area, buddy, mmh_list);
	}
	return mh;
}

void *
mem_realloc(void *ptr, u_int size)
{
	int order, order0;
	struct mem_hdr *mh, *mh0;

	assert(size <= (1 << BUDDY_ORDER_MAX) - sizeof(*mh));
	order = ffs(upper_pow2_32(size + (sizeof(*mh)))) - 1;
	if (ptr == NULL) {
		mh0 = NULL;
	} else {
		mh0 = ((struct mem_hdr *)ptr) - 1;
		assert(mh0->mmh_magic == MEM_HDR_MAGIC);
		order0 = mh0->mmh_order;
		assert(order0 >= SLAB_ORDER_MIN);
		assert(order0 <= BUDDY_ORDER_MAX);
		assert(mh0->mmh_size <= (1 << order0) + sizeof(*mh0));
		if (order0 == order) {
			mh = mh0;
			goto ok;
		}
	}
	if (order < BUDDY_ORDER_MIN) {
		order = BUDDY_ORDER_MIN;
	}	
	mem_lock();
	mh = mem_buddy_alloc(order);
	mem_unlock();
	if (mh != NULL) {
		if (mh0 != NULL) {
			memcpy(mh + 1, mh0 + 1, MIN(size, mh0->mmh_size));
			mem_free(mh0 + 1);
		}
ok:
		mh->mmh_size = size;
		INFO(0, "ok; size=%d, ptr=%p", size, mh + 1);
		return mh + 1;
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

void
mem_free(void *ptr)
{
}

static struct mbuf_chunk *
mem_block_alloc(struct mbuf_pool *p)
{
	int i;
	struct mbuf_chunk *chunk;
	struct mem_hdr *m;

	chunk = mem_alloc(CHUNK_SIZE - sizeof(struct mem_hdr));
	if (chunk == NULL) {
		return NULL;
	}
	p->mbp_n_allocated_chunks++;
	chunk->mbc_pool = p;
	chunk->mbc_id = -1;
	dlist_init(&chunk->mbc_mbuf_head);
	chunk->mbc_n_mbufs = p->mbp_mbufs_per_chunk;
	for (i = 0; i < chunk->mbc_n_mbufs; ++i) {
		m = (struct mem_hdr *)((u_char *)(chunk + 1) + i * p->mbp_mbuf_size);
		m->mmh_magic = MEM_HDR_MAGIC;
		m->mmh_block = chunk;
		m->mmh_worker_id = p->mbp_worker_id;
		
		DLIST_INSERT_TAIL(&chunk->mbc_mbuf_head, m, mmh_list);
	}
	DLIST_INSERT_TAIL(&p->mbp_avail_chunk_head, chunk, mbc_list);
	return chunk;
}

static int
mbuf_chunk_free(struct mbuf_pool *p, struct mbuf_chunk *chunk)
{
	assert(chunk->mbc_n_mbufs == p->mbp_mbufs_per_chunk);
	if (p->mbp_referenced == 0) {
		DLIST_REMOVE(chunk, mbc_list);
		mem_free(chunk);
		p->mbp_n_allocated_chunks--;
		if (p->mbp_n_allocated_chunks == 0) {
			mbuf_pool_free(p);
			return -EINVAL;
		}
	}
	return 0;
}

int
mbuf_pool_alloc(struct mbuf_pool **pp, u_char sid, int obj_size)
{
	int size, mbuf_size, mbufs_per_chunk/*, chunk_map_size*/;
	struct mbuf_pool *p;

	mbuf_size = ROUND_UP(obj_size + sizeof(struct mem_hdr), ALIGNMENT_PTR);
	mbufs_per_chunk = (CHUNK_SIZE - sizeof(struct mbuf_chunk)) /
		mbuf_size;
	size = sizeof(*p);
	p = mem_alloc(size);
	if (p == NULL) {
		return -ENOMEM;
	}
	*pp = p;
	memset(p, 0, size);
	p->mbp_worker_id = sid;
	p->mbp_referenced = 1;
	p->mbp_mbuf_size = mbuf_size;
	p->mbp_mbufs_per_chunk = mbufs_per_chunk;
	dlist_init(&p->mbp_avail_chunk_head);
	dlist_init(&p->mbp_not_avail_chunk_head);
	INFO(0, "ok; pool=%p", p);
	return 0;
}

void
mbuf_pool_free(struct mbuf_pool *p)
{
	int rc;
	struct mbuf_chunk *chunk, *tmp;

	if (p == NULL) {
		return;
	}
	p->mbp_referenced = 0;
	if (p->mbp_n_allocated_chunks == 0) {
		INFO(0, "ok; pool=%p", p);
		mem_free(p);
		return;
	}
	DLIST_FOREACH_SAFE(chunk, &p->mbp_avail_chunk_head, mbc_list, tmp) {
		if (chunk->mbc_n_mbufs == p->mbp_mbufs_per_chunk) {
			rc = mbuf_chunk_free(p, chunk);
			if (rc) {
				break;
			}
		}
	}
}

static void
mbuf_alloc2(struct mem_hdr *m, struct mbuf_chunk *chunk)
{
	struct mbuf_pool *p;

	assert(chunk->mbc_n_mbufs > 0);
	DLIST_REMOVE(m, mmh_list);
	p = chunk->mbc_pool;
	chunk->mbc_n_mbufs--;
	if (chunk->mbc_n_mbufs == 0) {
		DLIST_REMOVE(chunk, mbc_list);
		DLIST_INSERT_HEAD(&p->mbp_not_avail_chunk_head,
			chunk, mbc_list);
	}
	DBG(0, "ok; m=%p, c=%p, pool=%p, n=%d",
		m, chunk, p, chunk->mbc_n_mbufs);
}

void *
mbuf_alloc(struct mbuf_pool *p)
{
	struct mem_hdr *m;
	struct mbuf_chunk *chunk;

	assert(current->p_sid == p->mbp_worker_id);
	if (dlist_is_empty(&p->mbp_avail_chunk_head)) {
		chunk = mem_block_alloc(p);
		if (chunk == NULL) {
			return NULL;
		}
	}
	assert(!dlist_is_empty(&p->mbp_avail_chunk_head));
	chunk = DLIST_FIRST(&p->mbp_avail_chunk_head,
		struct mbuf_chunk, mbc_list);
	assert(chunk->mbc_n_mbufs);
	assert(!dlist_is_empty(&chunk->mbc_mbuf_head));
	m = DLIST_FIRST(&chunk->mbc_mbuf_head, struct mem_hdr, mmh_list);
	mbuf_alloc2(m, chunk);
	return m + 1;
}

static void
mem_free_reclaim(struct mem_hdr *mh)
{
	struct mbuf_chunk *chunk;
	struct mbuf_pool *p;

	chunk = mh->mmh_block;
	p = chunk->mbc_pool;
	DBG(0, "hit; m=%p, c=%p, pool=%p, n=%d",
		mh, chunk, p, chunk->mbc_n_mbufs);
	assert(chunk->mbc_n_mbufs < p->mbp_mbufs_per_chunk);
	DLIST_INSERT_HEAD(&chunk->mbc_mbuf_head, mh, mmh_list);
	if (chunk->mbc_n_mbufs == 0) {
		DLIST_REMOVE(chunk, mbc_list);
		DLIST_INSERT_TAIL(&p->mbp_avail_chunk_head, chunk, mbc_list);
	}
	chunk->mbc_n_mbufs++;
	if (chunk->mbc_n_mbufs == p->mbp_mbufs_per_chunk) {
		mbuf_chunk_free(p, chunk);
	}
}

void
mbuf_free(void *ptr)
{
	struct mem_hdr *mh;

	if (ptr == NULL) {
		return;
	}
	mh = ((struct mem_hdr *)ptr) - 1;
	DBG(0, "hit; m=%p", mh);
	if (mh->mmh_worker_id == current->p_sid) {
		mem_free_reclaim(mh);
	} else {
		DLIST_INSERT_TAIL(&current->p_mbuf_garbage_head, mh, mmh_list);
	}
}

void
garbage_collector(struct service *s)
{
	struct mem_hdr *mh;
	struct dlist *head;

	while (!dlist_is_empty(&s->p_mbuf_garbage_head)) {
		mh = DLIST_FIRST(&s->p_mbuf_garbage_head, struct mem_hdr, mmh_list);
		DLIST_REMOVE(mh, mmh_list);
		head = &shared->shm_garbage_head[mh->mmh_worker_id];
		DLIST_INSERT_TAIL(head, mh, mmh_list);
	}
	head = &shared->shm_garbage_head[s->p_sid];
	while (!dlist_is_empty(head)) {
		mh = DLIST_FIRST(head, struct mem_hdr, mmh_list);
		DLIST_REMOVE(mh, mmh_list);
		mem_free_reclaim(mh);
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
mbuf_free_rcu(void *ptr)
{
	struct mem_hdr *mh;

	mh = ((struct mem_hdr *)ptr) - 1;
	DLIST_INSERT_TAIL(&service_rcu_shadow_head, mh, mmh_list);
	if (service_rcu_max == 0) {
		assert(dlist_is_empty(&service_rcu_active_head));
		service_rcu_reload();
	}
}

static void
service_rcu_free()
{
	struct dlist *head;
	struct mem_hdr *mh;

	head = &service_rcu_active_head;
	while (!dlist_is_empty(head)) {
		mh = DLIST_FIRST(head, struct mem_hdr, mmh_list);
		DLIST_REMOVE(mh, mmh_list);
		mbuf_free(mh + 1);
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

