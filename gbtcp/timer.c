#include "internals.h"

#define TIMER_RING_ID_MASK (((uintptr_t)1 << TIMER_RING_ID_SHIFT) - 1)
#define TIMER_NRINGS_MAX (1 << TIMER_RING_ID_SHIFT) 

struct timer_mod {
	struct log_scope log_scope;
};

struct timer_ring {
	uint64_t r_seg_shift;
	uint64_t r_cur;
	int r_ntimers;
	struct dlist r_segs[TIMER_RING_SIZE];
};

static struct timer_mod *curmod;
static int timer_nrings;
static struct timer_ring *timer_rings[TIMER_NRINGS_MAX];

static int
timer_ring_get_id(struct timer *timer)
{
	return timer->tm_data & TIMER_RING_ID_MASK;
}

static void
timer_free_rings()
{
	int i;

	for (i = 0; i < ARRAY_SIZE(timer_rings); ++i) {
		free(timer_rings[i]);
		timer_rings[i] = NULL;
	}
}

static int
timer_alloc_rings(struct log *log)
{
	int i, rc;

	for (i = 0; i < timer_nrings; ++i) {
		rc = sys_malloc(log, (void **)&(timer_rings[i]),
		                sizeof(struct timer_ring));
		if (rc) {
			timer_free_rings();
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
		ASSERT(seg_size == (1llu << ring->r_seg_shift));
		ring->r_cur = nanoseconds >> ring->r_seg_shift;
	}
	ring->r_ntimers = 0;
	for (i = 0; i < TIMER_RING_SIZE; ++i) {
		dlist_init(ring->r_segs + i);
	}
}

int
timer_mod_init(struct log *log, void **pp)
{
	int rc;
	struct timer_mod *mod;

	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "timer");
	}
	return rc;
}

int
timer_mod_attach(struct log *log, void *raw_mod)
{
	int i, rc;
	uint64_t seg_size;
	uint64_t ring_seg_size[TIMER_NRINGS_MAX];
	struct timer_ring *ring;

	LOG_TRACE(log);
	curmod = raw_mod;
	seg_size = lower_pow2_64(TIMER_TIMO);
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
	rc = timer_alloc_rings(log);
	if (rc) {
		return rc;
	}
	for (i = 0; i < timer_nrings; ++i) {
		ring = timer_rings[i];
		timer_ring_init(ring, ring_seg_size[i]);
		LOGF(log, LOG_INFO, 0, "hit; ring=%d, seg=%llu",
		     i, 1llu << ring->r_seg_shift);
	}
	return 0;
}

int
timer_proc_init(struct log *log, struct proc *p)
{
	return 0;
}

void
timer_mod_deinit(struct log *log, void *raw_mod)
{
	struct timer_mod *mod;

	mod = raw_mod;
	LOG_TRACE(log);
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
timer_mod_detach(struct log *log)
{
	timer_free_rings();
	curmod = NULL;
}

static void
timer_mod_call(struct dlist *queue)
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
	ASSERT(pos <= ring->r_cur);
	if (ring->r_ntimers == 0) {
		return;
	}
	for (i = 0; pos <= ring->r_cur && i < TIMER_RING_SIZE; ++pos, ++i) {
		head = ring->r_segs + (pos & TIMER_RING_MASK);
		while (!dlist_is_empty(head)) {
			ring->r_ntimers--;
			ASSERT(ring->r_ntimers >= 0);
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
timer_mod_check()
{
	int i;
	static uint64_t last_time;
	struct dlist queue;
	struct timer_ring *ring;

	if (nanoseconds - last_time < TIMER_TIMO) {
		return;
	}
	last_time = nanoseconds;
	dlist_init(&queue);
	for (i = 0; i < timer_nrings; ++i) {
		ring = timer_rings[i];
		timer_ring_check(ring, &queue);
	}
	timer_mod_call(&queue);
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
	ASSERT(ring_id <= timer_nrings);
	if (ring_id == timer_nrings) {
		return 0;
	}
	ring = timer_rings[ring_id];
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
	BUG1("invalid ring; ring_id=%d; timer=%p", ring_id, timer);
	return 0;
}

void
timer_set(struct timer *timer, uint64_t expire, timer_f fn)
{
	int ring_id;
	uintptr_t uint_fn;
	uint64_t dist, pos;
	struct log *log;
	struct dlist *head;
	struct timer_ring *ring;

	uint_fn = (uintptr_t)fn;
	ASSERT(uint_fn != 0);
	ASSERT((uint_fn & TIMER_RING_ID_MASK) == 0);
	ASSERT(expire <= TIMER_EXPIRE_MAX);
	timer_del(timer);
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
		LOGF(log, LOG_ERR, 0, "too big expire=%"PRIu64, expire);
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
	DLIST_INSERT_HEAD(head, timer, tm_list);
	DBG(log, 0,
	    "ok; timer=%p, fn=%p, ring=%d, cur=%"PRIu64", head=%p, dist=%d",
	    timer, fn, ring_id, ring->r_cur, head, (int)dist);
}

void
timer_del(struct timer *timer)
{
	int ring_id;
	struct log *log;
	struct timer_ring *ring;

	if (timer_is_running(timer)) {
		ring_id = timer_ring_get_id(timer);
		ring = timer_rings[ring_id];
		ring->r_ntimers--;
		log = log_trace0();
		DBG(log, 0, "ok; timer=%p, ring=%d", timer, ring_id);
		ASSERT(ring->r_ntimers >= 0);
		DLIST_REMOVE(timer, tm_list);
		timer->tm_data = 0;
	}
}
