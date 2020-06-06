#include "internals.h"

#define CURMOD timer

#define TIMER_RING_ID_MASK (((uintptr_t)1 << TIMER_RING_ID_SHIFT) - 1)

struct timer_mod {
	struct log_scope log_scope;
};

static int
timer_ring_get_id(struct timer *timer)
{
	return timer->tm_data & TIMER_RING_ID_MASK;
}

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

	for (i = 0; i < s->p_timer_nrings; ++i) {
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
		ring->r_seg_shift = ffsll(seg_size) - 1;
		assert(seg_size == (1llu << ring->r_seg_shift));
		ring->r_cur = nanoseconds >> ring->r_seg_shift;
	}
	ring->r_ntimers = 0;
	for (i = 0; i < TIMER_RING_SIZE; ++i) {
		dlist_init(ring->r_segs + i);
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
	int i, rc, nrings;
	uint64_t seg_size;
	uint64_t ring_seg_size[TIMER_NRINGS_MAX];
	struct timer_ring *ring;

	seg_size = lower_pow2_64(TIMER_TIMEOUT);
	nrings = 0;
	while (seg_size < TIMER_EXPIRE_MAX) {
		ring_seg_size[nrings] = seg_size;
		nrings++;
		if (seg_size * TIMER_RING_SIZE > TIMER_EXPIRE_MAX) {
			break;
		} else {
			seg_size = ((seg_size * TIMER_RING_SIZE) >> 2llu);
			assert(nrings < TIMER_NRINGS_MAX);
		}
	}
	assert(nrings);
	s->p_timer_nrings = nrings;
	rc = alloc_timer_rings(s);
	if (rc) {
		return rc;
	}
	for (i = 0; i < nrings; ++i) {
		ring = s->p_timer_rings[i];
		timer_ring_init(ring, ring_seg_size[i]);
		INFO(0, "hit; ring=%d, seg=%llu",
		     i, 1llu << ring->r_seg_shift);
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
	timer_f fn;

	while (!dlist_is_empty(queue)) {
		timer = DLIST_FIRST(queue, struct timer, tm_list);
		DLIST_REMOVE(timer, tm_list);
		fn = (timer_f)(timer->tm_data & ~TIMER_RING_ID_MASK);
		timer->tm_data = 0;
		(*fn)(timer);
	}
}

static void
timer_ring_check(struct timer_ring *ring, struct dlist *queue)
{
	int i;
	uint64_t pos;
	struct timer *timer;
	struct dlist *head;

	pos = ring->r_cur;
	ring->r_cur = (nanoseconds >> ring->r_seg_shift);
	assert(pos <= ring->r_cur);
	if (ring->r_ntimers == 0) {
		return;
	}
	for (i = 0; pos <= ring->r_cur && i < TIMER_RING_SIZE; ++pos, ++i) {
		head = ring->r_segs + (pos & TIMER_RING_MASK);
		while (!dlist_is_empty(head)) {
			ring->r_ntimers--;
			assert(ring->r_ntimers >= 0);
			timer = DLIST_FIRST(head, struct timer, tm_list);
			DLIST_REMOVE(timer, tm_list);
			DLIST_INSERT_HEAD(queue, timer, tm_list);
		}
		if (ring->r_ntimers == 0) {
			break;
		}
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
	for (i = 0; i < current->p_timer_nrings; ++i) {
		ring = current->p_timer_rings[i];
		timer_ring_check(ring, &queue);
	}
	call_timers(&queue);
}

void
timer_init(struct timer *timer)
{
	timer->tm_data = 0;
}

int
timer_is_running(struct timer *timer)
{
	return timer->tm_data != 0;
}

uint64_t
timer_timeout(struct timer *timer)
{
	int ring_id;
	uint64_t e, b, dist;
	struct dlist *list;
	struct timer_ring *ring;

	if (!timer_is_running(timer)) {
		return 0;
	}
	ring_id = timer_ring_get_id(timer);
	assert(ring_id <= current->p_timer_nrings);
	if (ring_id == current->p_timer_nrings) {
		return 0;
	}
	ring = current->p_timer_rings[ring_id];
	for (list = timer->tm_list.dls_next;
	     list != &timer->tm_list; // Never occured
	     list = list->dls_next) {
		e = list - ring->r_segs;
		if (e < TIMER_RING_SIZE) {
			b = ring->r_cur & TIMER_RING_MASK;
			if (e >= b) {
				dist = e - b;
			} else {
				dist = e + TIMER_RING_SIZE - b;
			}
			return dist >> ring->r_seg_shift;
		}
	}
	assert(!"bad ring");
	return 0;
}

void
timer_set(struct timer *timer, uint64_t expire, timer_f fn)
{
	int ring_id;
	uintptr_t uint_fn;
	uint64_t dist, pos;
	struct dlist *head;
	struct timer_ring *ring;

	uint_fn = (uintptr_t)fn;
	assert(uint_fn != 0);
	assert((uint_fn & TIMER_RING_ID_MASK) == 0);
	assert(expire <= TIMER_EXPIRE_MAX);
	timer_del(timer);
	dist = 0;
	for (ring_id = 0; ring_id < current->p_timer_nrings; ++ring_id) {
		ring = current->p_timer_rings[ring_id];
		dist = expire >> ring->r_seg_shift;
		assert(dist >= 2);
		if (dist < TIMER_RING_SIZE) {
			break;
		}
	}
	if (ring_id == current->p_timer_nrings) {
		ERR(0, "too big expire=%"PRIu64, expire);
		ring_id = current->p_timer_nrings - 1;
		ring = current->p_timer_rings[ring_id];
		dist = TIMER_RING_SIZE - 1;
	}
	assert((ring_id & ~TIMER_RING_ID_MASK) == 0);
	ring = current->p_timer_rings[ring_id];
	pos = ring->r_cur + dist;
	head = ring->r_segs + (pos & TIMER_RING_MASK);
	ring->r_ntimers++;
	timer->tm_data = uint_fn|ring_id;
	DLIST_INSERT_HEAD(head, timer, tm_list);
	DBG(0, "ok; timer=%p, fn=%p, ring=%d, cur=%"PRIu64", head=%p, dist=%d",
	    timer, fn, ring_id, ring->r_cur, head, (int)dist);
}

void
timer_del(struct timer *timer)
{
	int ring_id;
	struct timer_ring *ring;

	if (timer_is_running(timer)) {
		ring_id = timer_ring_get_id(timer);
		ring = current->p_timer_rings[ring_id];
		ring->r_ntimers--;
		DBG(0, "ok; timer=%p, ring=%d", timer, ring_id);
		assert(ring->r_ntimers >= 0);
		DLIST_REMOVE(timer, tm_list);
		timer->tm_data = 0;
	}
}
