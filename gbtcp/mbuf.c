// gpl2
#include "internals.h"

#define CURMOD mbuf

#define CHUNK_SIZE 1*1024*1024

#define MBUF_MAGIC 0xcafe

#define MBUF_GET(p, chunk, i) \
	(struct mbuf *)(((u_char *)(chunk + 1)) + (i) * (p)->mbp_mbuf_size)

struct mbuf {
	struct dlist mb_list;
	struct mbuf_chunk *mb_chunk;
	uint16_t mb_magic;
	u_char mb_worker_id;
	u_char mb_freed;
};


void
mbuf_init(struct mbuf *m)
{
	m->mb_chunk = NULL;
	m->mb_magic = MBUF_MAGIC;
	m->mb_freed = 0;
}

static int
mbuf_chunk_alloc(struct mbuf_pool *p, struct mbuf_chunk **pchunk)
{
	int i, rc;
	struct mbuf_chunk *chunk;
	struct mbuf *m;

//	if (p->mbp_chunk_map_size != 0 &&
//	    p->mbp_n_allocated_chunks == p->mbp_chunk_map_size) {
//		return -ENOMEM;
//	}
	rc = shm_alloc_pages((void **)pchunk, CHUNK_SIZE);
	if (rc) {
		return rc;
	}
	p->mbp_n_allocated_chunks++;
	chunk = *pchunk;
	chunk->mbc_pool = p;
	chunk->mbc_id = -1;
	dlist_init(&chunk->mbc_mbuf_head);
	chunk->mbc_n_mbufs = p->mbp_mbufs_per_chunk;
	for (i = 0; i < chunk->mbc_n_mbufs; ++i) {
		m = MBUF_GET(p, chunk, i);
		mbuf_init(m);
		m->mb_freed = 1;
		m->mb_worker_id = p->mbp_worker_id;
		m->mb_chunk = chunk;
		DLIST_INSERT_TAIL(&chunk->mbc_mbuf_head, m, mb_list);
	}
	DLIST_INSERT_TAIL(&p->mbp_avail_chunk_head, chunk, mbc_list);
	return 0;
}

static int
mbuf_chunk_free(struct mbuf_pool *p, struct mbuf_chunk *chunk)
{
	assert(chunk->mbc_n_mbufs == p->mbp_mbufs_per_chunk);
	if (p->mbp_referenced == 0) {
//		if (chunk->mbc_id >= 0) {
//			assert(p->mbp_chunk_map[chunk->mbc_id] == chunk);
//			p->mbp_chunk_map[chunk->mbc_id] = NULL;
//		}
		DLIST_REMOVE(chunk, mbc_list);
		shm_free_pages(chunk, CHUNK_SIZE);
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

	mbuf_size = ALIGN_UP(obj_size + sizeof(struct mbuf), ALIGNMENT_PTR);
	mbufs_per_chunk = (CHUNK_SIZE - sizeof(struct mbuf_chunk)) /
		mbuf_size;
	//chunk_map_size = n_mbufs_max / mbufs_per_chunk;
	//if (n_mbufs_max % mbufs_per_chunk) {
	//	chunk_map_size++;
	//}
	size = sizeof(*p) /*+ chunk_map_size * sizeof(struct mbuf_chunk *)*/;
	p = shm_malloc(size);
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
//	p->mbp_chunk_map_size = chunk_map_size;
//	if (p->mbp_chunk_map_size) {
//		p->mbp_chunk_map = (struct mbuf_chunk **)(p + 1);
//	}
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
		shm_free(p);
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
mbuf_alloc2(struct mbuf *m, struct mbuf_chunk *chunk)
{
	struct mbuf_pool *p;

	assert(m->mb_freed == 1);
	assert(chunk->mbc_n_mbufs > 0);
	DLIST_REMOVE(m, mb_list);
	p = chunk->mbc_pool;
	chunk->mbc_n_mbufs--;
	if (chunk->mbc_n_mbufs == 0) {
		DLIST_REMOVE(chunk, mbc_list);
		DLIST_INSERT_HEAD(&p->mbp_not_avail_chunk_head,
			chunk, mbc_list);
	}
	WRITE_ONCE(m->mb_freed, 0);
	DBG(0, "ok; m=%p, c=%p, pool=%p, n=%d",
		m, chunk, p, chunk->mbc_n_mbufs);
}

void *
mbuf_alloc(struct mbuf_pool *p)
{
	int /*i,*/ rc;
	struct mbuf *m;
	struct mbuf_chunk *chunk;

	assert(current->p_sid == p->mbp_worker_id);
	if (dlist_is_empty(&p->mbp_avail_chunk_head)) {
		rc = mbuf_chunk_alloc(p, &chunk);
		if (rc) {
			return NULL;
		}
//		for (i = 0; i < p->mbp_chunk_map_size; ++i) {
//			if (p->mbp_chunk_map[i] == NULL) {
//				chunk->mbc_id = i;
//				p->mbp_chunk_map[i] = chunk;
//			}
//		}
//		assert(i == 0 || i < p->mbp_chunk_map_size);
//		assert(i == 0 || i < p->mbp_chunk_map_size);
	}
	assert(!dlist_is_empty(&p->mbp_avail_chunk_head));
	chunk = DLIST_FIRST(&p->mbp_avail_chunk_head,
		struct mbuf_chunk, mbc_list);
	assert(chunk->mbc_n_mbufs);
	assert(!dlist_is_empty(&chunk->mbc_mbuf_head));
	m = DLIST_FIRST(&chunk->mbc_mbuf_head, struct mbuf, mb_list);
	mbuf_alloc2(m, chunk);
	return m + 1;
}

/*int
mbuf_alloc3(struct mbuf_pool *p, uint32_t m_id, struct mbuf **mp)
{
	int i, rc, chunk_id;
	struct mbuf *m;
	struct mbuf_chunk *chunk;

	assert(current->p_sid == p->mbp_sid);
	*mp = NULL;
	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	if (chunk_id >= p->mbp_chunk_map_size) {
		return -ENFILE;
	}
	chunk = p->mbp_chunk_map[chunk_id];
	if (chunk == NULL) {
		rc = mbuf_chunk_alloc(p, &chunk);
		if (rc) {
			return rc;
		}
		p->mbp_chunk_map[chunk_id] = chunk;
		chunk->mbc_id = chunk_id;
	}
	i = m_id % p->mbp_mbufs_per_chunk;
	m = MBUF_GET(p, chunk, i);
	if (READ_ONCE(m->mb_freed)) {
		mbuf_alloc2(m, chunk);
		*mp = m;
		return 0;
	} else {
		return -EBUSY;
	}
}*/

void
mbuf_free_reclaim(struct mbuf *m)
{
	struct mbuf_chunk *chunk;
	struct mbuf_pool *p;

	chunk = m->mb_chunk;
	p = chunk->mbc_pool;
	DBG(0, "hit; m=%p, c=%p, pool=%p, n=%d",
		m, chunk, p, chunk->mbc_n_mbufs);
	assert(chunk->mbc_n_mbufs < p->mbp_mbufs_per_chunk);
	DLIST_INSERT_HEAD(&chunk->mbc_mbuf_head, m, mb_list);
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
	struct mbuf *m;

	if (ptr == NULL) {
		return;
	}
	m = ((struct mbuf *)ptr) - 1;
	DBG(0, "hit; m=%p", m);
	assert(m->mb_freed == 0);
	WRITE_ONCE(m->mb_freed, 1);
	if (m->mb_worker_id == current->p_sid) {
		mbuf_free_reclaim(m);
	} else {
		DLIST_INSERT_TAIL(&current->p_mbuf_garbage_head, m, mb_list);
	}
}

void
garbage_collector(struct service *s)
{
	struct mbuf *m;
	struct dlist *head;

	while (!dlist_is_empty(&s->p_mbuf_garbage_head)) {
		m = DLIST_FIRST(&s->p_mbuf_garbage_head, struct mbuf, mb_list);
		DLIST_REMOVE(m, mb_list);
		head = &shared->shm_garbage_head[m->mb_worker_id];
		DLIST_INSERT_TAIL(head, m, mb_list);
	}
	head = &shared->shm_garbage_head[s->p_sid];
	while (!dlist_is_empty(head)) {
		m = DLIST_FIRST(head, struct mbuf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mbuf_free_reclaim(m);
	}
}



// struct page;
//
// mbuf_cache
//
// mbuf sizes:
// << slab >>
// 64
// 128
// 256
// 512
// 1024 = 1k
// 2k
// 4k
// 8k
// 16k
// 32k
// 64k
// 128k
// 256k
// 512k
// 1024k = 1m
// << buddy >>
// 2m
// 4m
// 8m
// 16m
// 32m
// 64m
// 128m
//
// mm_malloc(int mm_alloc_id)
// {
// 	
//MM_ALLOC_64
//MM_ALLOC_128M
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
	struct mbuf *m;

	m = ((struct mbuf *)ptr) - 1;
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
	struct mbuf *m;

	head = &service_rcu_active_head;
	while (!dlist_is_empty(head)) {
		m = DLIST_FIRST(head, struct mbuf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mbuf_free(m);
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

