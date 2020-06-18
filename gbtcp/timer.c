// gpl2
#include "internals.h"

#define CURMOD timer

#define TIMER_RING_POISON TIMER_N_RINGS

#define SEG_LOCK(seg) spinlock_lock(&seg->htb_lock)
#define SEG_UNLOCK(seg) spinlock_unlock(&seg->htb_lock)

static int
timer_ring_init(struct service *s, uint64_t t, int ring_id, uint64_t seg_shift)
{
	int i, rc;
	void *ptr;
	struct timer_ring *ring;

	assert(ring_id < TIMER_N_RINGS);
	rc = shm_malloc("timer.ring", &ptr, sizeof(struct timer_ring));
	if (rc) {
		deinit_timers(s);
		return rc;
	}
	s->p_timer_rings[ring_id] = ring = ptr;
	ring->tmr_seg_shift = seg_shift;
	ring->tmr_cur = t >> ring->tmr_seg_shift;
	for (i = 0; i < TIMER_RING_SIZE; ++i) {
		htable_bucket_init(ring->tmr_segs + i);
	}
	INFO(0, "ok; ring=%d, seg=%llu", ring_id, 1llu << ring->tmr_seg_shift);
	return 0;
}

int
init_timers(struct service *s)
{
	int i, rc;
	uint64_t t;
	int seg_shift[2] = {
		TIMER_RING0_SEG_SHIFT,
		TIMER_RING1_SEG_SHIFT
	};

	t = shm_get_nanoseconds();
	for (i = 0; i < ARRAY_SIZE(seg_shift); ++i) {
		rc = timer_ring_init(s, t, i, seg_shift[i]);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

void
deinit_timers(struct service *s)
{
	int i;

	for (i = 0; i < TIMER_N_RINGS; ++i) {
		shm_free(s->p_timer_rings[i]);
		s->p_timer_rings[i] = NULL;
	}
}

static void
call_timers(struct dlist *queue)
{
	struct timer *timer;
	void (*fn)(struct timer *, u_char);

	while (!dlist_is_empty(queue)) {
		timer = DLIST_FIRST(queue, struct timer, tm_list);
		DLIST_REMOVE(timer, tm_list);
		timer->tm_ring_id = TIMER_RING_POISON;
		assert(timer->tm_mod_id < MODS_MAX);
		fn = mods[timer->tm_mod_id].mod_timer;
		assert(fn != NULL);
		(*fn)(timer, timer->tm_fn_id);
	}
}

static void
run_ring_timers(struct timer_ring *ring, uint64_t t, struct dlist *queue)
{
	int i;
	uint64_t pos;
	struct timer *timer;
	timer_seg_t *seg;

	pos = ring->tmr_cur;
	ring->tmr_cur = t >> ring->tmr_seg_shift;
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
run_timers()
{
	int i;
	uint64_t t;
	static uint64_t t_saved;
	struct dlist queue;
	struct timer_ring *ring;

	t = shm_get_nanoseconds();
	if (t - t_saved < TIMER_TIMEOUT) {
		return;
	}
	t_saved = t;
	dlist_init(&queue);
	for (i = 0; i < TIMER_N_RINGS; ++i) {
		ring = current->p_timer_rings[i];
		run_ring_timers(ring, t, &queue);
	}
	call_timers(&queue);
}

static void
migrate_timers_in_seg(u_char sid, timer_seg_t *dst_seg, timer_seg_t *src_seg)
{
	struct timer *timer;

	while (!dlist_is_empty(&src_seg->htb_head)) {
		timer = DLIST_FIRST(&src_seg->htb_head, struct timer, tm_list);
		DLIST_REMOVE(timer, tm_list);
		// timer_del executed while migrate_timers
		WRITE_ONCE(timer->tm_sid, sid);
		DLIST_INSERT_TAIL(&dst_seg->htb_head, timer, tm_list);
	}
}

void
migrate_timers(struct service *dst, struct service *src)
{
	int i, j;
	struct timer_ring *src_ring, *dst_ring;
	timer_seg_t *src_seg, *dst_seg;

	for (i = 0; i < TIMER_N_RINGS; ++i) {
		src_ring = src->p_timer_rings[i];
		dst_ring = dst->p_timer_rings[i];
		for (j = 0; j < TIMER_RING_SIZE; ++j) {
			src_seg = src_ring->tmr_segs + j;
			dst_seg = dst_ring->tmr_segs + j;
			SEG_LOCK(src_seg);
			SEG_LOCK(dst_seg);
			migrate_timers_in_seg(src->p_sid, dst_seg, src_seg);
			SEG_UNLOCK(dst_seg);
			SEG_UNLOCK(src_seg);
		}
	}
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
	timer_seg_t *seg;
	struct timer_ring *ring;

	assert(expire >= TIMER_EXPIRE_MIN);
	assert(expire <= TIMER_EXPIRE_MAX);
	assert(mod_id > 0 && mod_id < MODS_MAX);
	timer_del(timer);
	if (expire < 2*TIMER_RING1_SEG) {
		ring_id = 0;
	} else {
		ring_id = 1;
	}
	ring = current->p_timer_rings[ring_id];
	dist = expire >> ring->tmr_seg_shift;
	assert(dist < TIMER_RING_SIZE);
	assert(dist > 1);
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
	u_char sid;
	struct service *s;
	struct timer_ring *ring;
	timer_seg_t *seg;

	if (timer_is_running(timer)) {
restart:
		// timer_del executed while migrate_timers
		sid = READ_ONCE(timer->tm_sid);
		s = service_get_by_sid(sid);
		ring = s->p_timer_rings[timer->tm_ring_id];
		assert(ring != NULL);
		seg = ring->tmr_segs + timer->tm_seg_id;
		SEG_LOCK(seg);
		if (sid != READ_ONCE(timer->tm_sid)) {
			SEG_UNLOCK(seg);
			goto restart;
		}
		DLIST_REMOVE(timer, tm_list);
		SEG_UNLOCK(seg);
		timer->tm_ring_id = TIMER_RING_POISON;
		DBG(0, "ok; timer=%p", timer);
	}
}
