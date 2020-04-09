#include "timer.h"
#include "sys.h"
#include "log.h"

//#define TIMER_MOD_DISABLED
#define TIMER_RING_ID_MASK (((uintptr_t)1 << TIMER_RING_ID_SHIFT) - 1)
#define TIMER_NRINGS_MAX (1 << TIMER_RING_ID_SHIFT) 

#define TIMER_LOG_MSG_FOREACH(x) \
	x(mod_init) \
	x(set) \
	x(del)

struct timer_mod {
	struct log_scope log_scope;
	TIMER_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
};

struct timer_ring {
	gt_time_t r_seg_shift;
	gt_time_t r_cur;
	int r_ntimers;
	struct dllist r_segs[TIMER_RING_SIZE];
};

static struct timer_mod this_mod;
static int timer_nrings;
static gt_time_t timer_last_time;
static struct timer_ring *timer_rings[TIMER_NRINGS_MAX];

static int gt_timer_ring_get_id(struct gt_timer *timer);

static int gt_timer_mod_alloc_rings(struct gt_log *log);

#ifndef TIMER_MOD_DISABLED
static void gt_timer_mod_call(struct dllist *);

static void gt_timer_ring_check(struct timer_ring *ring, struct dllist *);
#endif /* TIMER_MOD_DISABLED */

static int
gt_timer_ring_get_id(struct gt_timer *timer)
{
	return timer->tm_data & TIMER_RING_ID_MASK;
}

static void
timer_free_rings()
{
	int i;

	for (i = 0; i < GT_ARRAY_SIZE(timer_rings); ++i) {
		free(timer_rings[i]);
		timer_rings[i] = NULL;
	}
}

static int
gt_timer_mod_alloc_rings(struct gt_log *log)
{
	int i, rc;

	for (i = 0; i < timer_nrings; ++i) {
		rc = gt_sys_malloc(log, (void **)&(timer_rings[i]),
		                   sizeof(struct timer_ring));
		if (rc) {
			timer_free_rings();
			return rc;
		}
	}
	return 0;
}

static void
timer_ring_init(struct timer_ring *ring, gt_time_t seg_size)
{
	int i;

	if (seg_size) {
		ring->r_seg_shift = ffsll(seg_size) - 1;
		ASSERT(seg_size == (1llu << ring->r_seg_shift));
		ring->r_cur = gt_nsec >> ring->r_seg_shift;
	}
	ring->r_ntimers = 0;
	for (i = 0; i < TIMER_RING_SIZE; ++i) {
		dllist_init(ring->r_segs + i);
	}
}

int
gt_timer_mod_init()
{
	int i, rc;
	gt_time_t seg_size;
	gt_time_t ring_seg_size[TIMER_NRINGS_MAX];
	struct gt_log *log;
	struct timer_ring *ring;

	log_scope_init(&this_mod.log_scope, "timer");
	log = log_trace0();
	seg_size = gt_lower_pow_of_2_64(TIMER_TIMO);
	timer_nrings = 0;
	while (seg_size < TIMER_EXPIRE_MAX) {
		ring_seg_size[timer_nrings] = seg_size;
		timer_nrings++;
		if (seg_size * TIMER_RING_SIZE > TIMER_EXPIRE_MAX) {
			break;
		} else {
			seg_size = ((seg_size * TIMER_RING_SIZE) >> 2llu);
			ASSERT(timer_nrings < TIMER_NRINGS_MAX);
		}
	}
	ASSERT(timer_nrings);
	rc = gt_timer_mod_alloc_rings(log);
	if (rc) {
		log_scope_deinit(log, &this_mod.log_scope);
		return rc;
	}
	for (i = 0; i < timer_nrings; ++i) {
		ring = timer_rings[i];
		timer_ring_init(ring, ring_seg_size[i]);
		LOGF(log, mod_init, LOG_INFO, 0, "hit; ring=%d, seg=%llu",
		     i, 1llu << ring->r_seg_shift);
	}
	return 0;
}

void
gt_timer_mod_deinit(struct gt_log *log)
{
	timer_free_rings();
	LOG_TRACE(log);
	log_scope_deinit(log, &this_mod.log_scope);
}

#ifdef TIMER_MOD_DISABLED
void
gt_timer_mod_check()
{
	timer_last_time = gt_nsec;
}
#else /* TIMER_MOD_DISABLED */
static void
gt_timer_mod_call(struct dllist *queue)
{
	struct gt_timer *timer;
	gt_timer_f fn;

	while (!dllist_isempty(queue)) {
		timer = DLLIST_FIRST(queue, struct gt_timer, tm_list);
		DLLIST_REMOVE(timer, tm_list);
		fn = (gt_timer_f)(timer->tm_data & ~TIMER_RING_ID_MASK);
		timer->tm_data = 0;
		(*fn)(timer);
	}
}

void
gt_timer_mod_check()
{
	int i;
	struct dllist queue;
	struct timer_ring *ring;

	if (gt_nsec - timer_last_time < TIMER_TIMO) {
		return;
	}
	timer_last_time = gt_nsec;
	dllist_init(&queue);
	for (i = 0; i < timer_nrings; ++i) {
		ring = timer_rings[i];
		gt_timer_ring_check(ring, &queue);
	}
	gt_timer_mod_call(&queue);
}
#endif /* TIMER_MOD_DISABLED */

void
gt_timer_init(struct gt_timer *timer)
{
	timer->tm_data = 0;
}

int
gt_timer_is_running(struct gt_timer *timer)
{
	return timer->tm_data != 0;
}

gt_time_t
gt_timer_timeout(struct gt_timer *timer)
{
	int ring_id;
	gt_time_t e, b, dist;
	struct dllist *list;
	struct timer_ring *ring;

	if (!gt_timer_is_running(timer)) {
		return 0;
	}
	ring_id = gt_timer_ring_get_id(timer);
	ASSERT(ring_id <= timer_nrings);
	if (ring_id == timer_nrings) {
		return 0;
	}
	ring = timer_rings[ring_id];
	for (list = timer->tm_list.dls_next;
	     list != &timer->tm_list; /* Never occured */
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
	BUG1("invalid ring; ring_id=%d; timer=%p", ring_id, timer);
	return 0;
}

#ifdef TIMER_MOD_DISABLED
void
gt_timer_set(struct gt_timer *timer, gt_time_t expire, gt_timer_f fn)
{
}
#else /* TIMER_MOD_DISABLED */
void
gt_timer_set(struct gt_timer *timer, gt_time_t expire, gt_timer_f fn)
{
	int ring_id;
	uintptr_t uint_fn;
	gt_time_t dist, pos;
	struct gt_log *log;
	struct dllist *head;
	struct timer_ring *ring;

	uint_fn = (uintptr_t)fn;
	ASSERT(uint_fn != 0);
	ASSERT((uint_fn & TIMER_RING_ID_MASK) == 0);
	ASSERT(expire <= TIMER_EXPIRE_MAX);
	gt_timer_del(timer);
	dist = 0;
	for (ring_id = 0; ring_id < timer_nrings; ++ring_id) {
		ring = timer_rings[ring_id];
		dist = expire >> ring->r_seg_shift;
		ASSERT3(0, dist >= 2, "expire=%"PRIu64", ring=%d",
		        expire, ring_id);
		if (dist < TIMER_RING_SIZE) {
			break;
		}
	}
	log = log_trace0();
	if (ring_id == timer_nrings) {
		LOGF(log, set, LOG_ERR, 0, "too big expire=%"PRIu64, expire);
		ring_id = timer_nrings - 1;
		ring = timer_rings[ring_id];
		dist = TIMER_RING_SIZE - 1;
	}
	ASSERT((ring_id & ~TIMER_RING_ID_MASK) == 0);
	ring = timer_rings[ring_id];
	pos = ring->r_cur + dist;
	head = ring->r_segs + (pos & TIMER_RING_MASK);
	ring->r_ntimers++;
	timer->tm_data = uint_fn|ring_id;
	DLLIST_INSERT_HEAD(head, timer, tm_list);
	DBG(log, set, 0,
	    "ok; timer=%p, fn=%p, ring=%d, cur=%"PRIu64", head=%p, dist=%d",
	    timer, fn, ring_id, ring->r_cur, head, (int)dist);
}
#endif /* TIMER_MOD_DISABLED */

#ifdef TIMER_MOD_DISABLED
void
gt_timer_del(struct gt_timer *timer)
{
}

#else /* TIMER_MOD_DISABLED */
void
gt_timer_del(struct gt_timer *timer)
{
	int ring_id;
	struct gt_log *log;
	struct timer_ring *ring;

	if (gt_timer_is_running(timer)) {
		ring_id = gt_timer_ring_get_id(timer);
		ring = timer_rings[ring_id];
		ring->r_ntimers--;
		log = log_trace0();
		DBG(log, del, 0, "ok; timer=%p, ring=%d", timer, ring_id);
		ASSERT(ring->r_ntimers >= 0);
		DLLIST_REMOVE(timer, tm_list);
		timer->tm_data = 0;
	}
}
#endif /* TIMER_MOD_DISABLED */

#ifndef TIMER_MOD_DISABLED
static void
gt_timer_ring_check(struct timer_ring *ring, struct dllist *queue)
{
	int i;
	gt_time_t pos;
	struct gt_timer *timer;
	struct dllist *head;

	pos = ring->r_cur;
	ring->r_cur = (gt_nsec >> ring->r_seg_shift);
	ASSERT(pos <= ring->r_cur);
	if (ring->r_ntimers == 0) {
		return;
	}
	for (i = 0; pos <= ring->r_cur && i < TIMER_RING_SIZE; ++pos, ++i) {
		head = ring->r_segs + (pos & TIMER_RING_MASK);
		while (!dllist_isempty(head)) {
			ring->r_ntimers--;
			ASSERT(ring->r_ntimers >= 0);
			timer = DLLIST_FIRST(head, struct gt_timer, tm_list);
			DLLIST_REMOVE(timer, tm_list);
			DLLIST_INSERT_HEAD(queue, timer, tm_list);
		}
		if (ring->r_ntimers == 0) {
			break;
		}
	}
}
#endif /* TIMER_MOD_DISABLED */
