#include "internals.h"

#define CURMOD timer

#define TIMER_RING_POISON TIMER_RINGS_MAX

struct timer_mod {
	struct log_scope log_scope;
};

#define SEG_LOCK(seg) spinlock_lock(&seg->htb_lock)
#define SEG_UNLOCK(seg) spinlock_unlock(&seg->htb_lock)

static void
free_timer_rings(struct service *s)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(s->p_timer_rings); ++i) {
		shm_free(s->p_timer_rings[i]);
		s->p_timer_rings[i] = NULL;
	}
}

static int
alloc_timer_rings(struct service *s)
{
	int i, rc;

	for (i = 0; i < s->p_timer_n_rings; ++i) {
		rc = shm_malloc((void **)&(s->p_timer_rings[i]),
		                sizeof(struct timer_ring));
		if (rc) {
			free_timer_rings(s);
			return rc;
		}
	}
	return 0;
}

static void
timer_ring_init(struct timer_ring *ring, uint64_t seg_size)
{
	int i;

	if (seg_size) {
		ring->tmr_seg_shift = ffsll(seg_size) - 1;
		assert(seg_size == (1llu << ring->tmr_seg_shift));
		ring->tmr_cur = nanoseconds >> ring->tmr_seg_shift;
	}
	for (i = 0; i < TIMER_RING_SIZE; ++i) {
		htable_bucket_init(ring->tmr_segs + i);
	}
}

int
timer_mod_init()
{
	int rc;

	rc = curmod_init();
	return rc;
}

int
timer_mod_service_init(struct service *s)
{
	int i, rc, n_rings;
	uint64_t seg_size;
	uint64_t ring_seg_size[TIMER_RINGS_MAX];
	struct timer_ring *ring;

	seg_size = lower_pow2_64(TIMER_TIMEOUT);
	n_rings = 0;
	while (seg_size < TIMER_EXPIRE_MAX) {
		ring_seg_size[n_rings] = seg_size;
		n_rings++;
		if (seg_size * TIMER_RING_SIZE > TIMER_EXPIRE_MAX) {
			break;
		} else {
			seg_size = ((seg_size * TIMER_RING_SIZE) >> 2llu);
			assert(n_rings < TIMER_RINGS_MAX);
		}
	}
	assert(n_rings);
	s->p_timer_n_rings = n_rings;
	rc = alloc_timer_rings(s);
	if (rc) {
		return rc;
	}
	for (i = 0; i < n_rings; ++i) {
		ring = s->p_timer_rings[i];
		timer_ring_init(ring, ring_seg_size[i]);
		INFO(0, "hit; ring=%d, seg=%llu",
		     i, 1llu << ring->tmr_seg_shift);
	}
	return 0;
}

void
timer_mod_deinit()
{
	curmod_deinit();
}

void
timer_mod_service_deinit(struct service *s)
{
	free_timer_rings(s);
}

static void
call_timers(struct dlist *queue)
{
	struct timer *timer;

	while (!dlist_is_empty(queue)) {
		timer = DLIST_FIRST(queue, struct timer, tm_list);
		DLIST_REMOVE(timer, tm_list);
		timer->tm_ring_id = TIMER_RING_POISON;
		mod_timer_handler(timer, timer->tm_mod_id, timer->tm_fn_id);
	}
}

static void
timer_ring_check(struct timer_ring *ring, struct dlist *queue)
{
	int i;
	uint64_t pos;
	struct timer *timer;
	struct htable_bucket *seg;

	pos = ring->tmr_cur;
	ring->tmr_cur = (nanoseconds >> ring->tmr_seg_shift);
	assert(pos <= ring->tmr_cur);
	for (i = 0; pos <= ring->tmr_cur && i < TIMER_RING_SIZE; ++pos, ++i) {
		seg = ring->tmr_segs + (pos & TIMER_RING_MASK);
		SEG_LOCK(seg);
		while (!dlist_is_empty(&seg->htb_head)) {
			timer = DLIST_FIRST(&seg->htb_head,
			                    struct timer, tm_list);
			DLIST_REMOVE(timer, tm_list);
			DLIST_INSERT_HEAD(queue, timer, tm_list);
		}
		SEG_UNLOCK(seg);
	}
}

void
check_timers()
{
	int i;
	static uint64_t last_check_time;
	struct dlist queue;
	struct timer_ring *ring;

	if (nanoseconds - last_check_time < TIMER_TIMEOUT) {
		return;
	}
	last_check_time = nanoseconds;
	dlist_init(&queue);
	for (i = 0; i < current->p_timer_n_rings; ++i) {
		ring = current->p_timer_rings[i];
		timer_ring_check(ring, &queue);
	}
	call_timers(&queue);
}

void
timer_init(struct timer *timer)
{
	timer->tm_ring_id = TIMER_RING_POISON;
}

int
timer_is_running(struct timer *timer)
{
	return timer->tm_ring_id != TIMER_RING_POISON;
}

#if 0
uint64_t
timer_timeout(struct timer *timer)
{
	uint64_t e, b, dist;
	struct dlist *list;
	struct timer_ring *ring;

	if (!timer_is_running(timer)) {
		return 0;
	}
	assert(timer->tm_ring_id <= current->p_timer_n_rings);
	ring = current->p_timer_rings[timer->tm_ring_id];
	for (list = timer->tm_list.dls_next;
	     list != &timer->tm_list; // never occured
	     list = list->dls_next) {
		e = list - ring->tmr_segs;
		if (e < TIMER_RING_SIZE) {
			b = ring->tmr_cur & TIMER_RING_MASK;
			if (e >= b) {
				dist = e - b;
			} else {
				dist = e + TIMER_RING_SIZE - b;
			}
			return dist >> ring->tmr_seg_shift;
		}
	}
	assert(!"bad ring");
	return 0;
}
#endif

void
timer_set4(struct timer *timer, uint64_t expire, u_char mod_id, u_char fn_id)
{
	int ring_id;
	u_short seg_id;
	uint64_t dist, pos;
	struct htable_bucket *seg;
	struct timer_ring *ring;

	assert(expire <= TIMER_EXPIRE_MAX);
	assert(mod_id > 0 && mod_id < MODS_NUM);
	timer_del(timer);
	dist = 0;
	for (ring_id = 0; ring_id < current->p_timer_n_rings; ++ring_id) {
		ring = current->p_timer_rings[ring_id];
		dist = expire >> ring->tmr_seg_shift;
		assert(dist >= 2);
		if (dist < TIMER_RING_SIZE) {
			break;
		}
	}
	if (ring_id == current->p_timer_n_rings) {
		ERR(0, "too big expire=%"PRIu64, expire);
		ring_id = current->p_timer_n_rings - 1;
		ring = current->p_timer_rings[ring_id];
		dist = TIMER_RING_SIZE - 1;
	}
	ring = current->p_timer_rings[ring_id];
	pos = ring->tmr_cur + dist;
	seg_id = (pos & TIMER_RING_MASK);
	seg = ring->tmr_segs + seg_id;
	timer->tm_sid = current->p_sid;
	timer->tm_ring_id = ring_id;
	timer->tm_seg_id = seg_id;
	timer->tm_mod_id = mod_id;
	timer->tm_fn_id = fn_id;
	SEG_LOCK(seg);
	DLIST_INSERT_HEAD(&seg->htb_head, timer, tm_list);
	SEG_UNLOCK(seg);
	DBG(0, "ok; timer=%p, mod_id=%d, fn_id=%d, ring=%d, seg_id=%hu",
	    timer, mod_id, fn_id, ring_id, seg_id);
}

void
timer_del(struct timer *timer)
{
	struct service *s;
	struct timer_ring *ring;
	struct htable_bucket *seg;

	if (timer_is_running(timer)) {
		s = service_get_by_sid(timer->tm_sid);
		ring = s->p_timer_rings[timer->tm_ring_id];
		seg = ring->tmr_segs + timer->tm_seg_id;
		DBG(0, "ok; timer=%p", timer);
		SEG_LOCK(seg);
		DLIST_REMOVE(timer, tm_list);
		SEG_UNLOCK(seg);
		timer->tm_ring_id = TIMER_RING_POISON;
	}
}
