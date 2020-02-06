#include "timer.h"
#include "sys.h"
#include "log.h"

//#define GT_TIMER_MOD_DISABLED
#define GT_TIMER_RING_ID_MASK (((uintptr_t)1 << GT_TIMER_RING_ID_SHIFT) - 1)
#define GT_TIMER_NR_RINGS_MAX (1 << GT_TIMER_RING_ID_SHIFT) 

#define GT_TIMER_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(mod_deinit) \
	x(set) \
	x(del)

struct gt_timer_ring {
	gt_time_t r_cell_shift;
	gt_time_t r_cur;
	int r_nr_timers;
	struct dllist r_cells[GT_TIMER_RING_SIZE];
};

static int gt_timer_nr_rings;
static gt_time_t gt_timer_last_time;
static struct gt_timer_ring *gt_timer_rings[GT_TIMER_NR_RINGS_MAX];
static struct gt_log_scope this_log;
GT_TIMER_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static int gt_timer_ring_get_id(struct gt_timer *timer);

static int gt_timer_mod_alloc_rings(struct gt_log *log);

static void gt_timer_mod_free_rings();

static void gt_timer_ring_init(struct gt_timer_ring *, gt_time_t);

#ifndef GT_TIMER_MOD_DISABLED
static void gt_timer_mod_call(struct dllist *);

static void gt_timer_ring_check(struct gt_timer_ring *ring, struct dllist *);
#endif /* GT_TIMER_MOD_DISABLED */

static int
gt_timer_ring_get_id(struct gt_timer *timer)
{
	return timer->tm_data & GT_TIMER_RING_ID_MASK;
}

static int
gt_timer_mod_alloc_rings(struct gt_log *log)
{
	int i, rc;

	for (i = 0; i < gt_timer_nr_rings; ++i) {
		rc = gt_sys_malloc(log, (void **)&(gt_timer_rings[i]),
		                   sizeof(struct gt_timer_ring));
		if (rc) {
			gt_timer_mod_free_rings();
			return rc;
		}
	}
	return 0;
}

static void
gt_timer_mod_free_rings()
{
	int i;

	for (i = 0; i < GT_ARRAY_SIZE(gt_timer_rings); ++i) {
		free(gt_timer_rings[i]);
		gt_timer_rings[i] = NULL;
	}
}

static void
gt_timer_ring_init(struct gt_timer_ring *ring, gt_time_t cell_size)
{
	int i;

	if (cell_size) {
		ring->r_cell_shift = ffsll(cell_size) - 1;
		GT_ASSERT(cell_size == (1llu << ring->r_cell_shift));
		ring->r_cur = gt_nsec >> ring->r_cell_shift;
	}
	ring->r_nr_timers = 0;
	for (i = 0; i < GT_TIMER_RING_SIZE; ++i) {
		dllist_init(ring->r_cells + i);
	}
}

int
gt_timer_mod_init()
{
	int i, rc;
	gt_time_t cell_size;
	gt_time_t ring_cell_size[GT_TIMER_NR_RINGS_MAX];
	struct gt_log *log;
	struct gt_timer_ring *ring;

	gt_log_scope_init(&this_log, "timer");
	GT_TIMER_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	cell_size = gt_lower_pow_of_2_64(GT_TIMER_TIMEOUT);
	gt_timer_nr_rings = 0;
	while (cell_size < GT_TIMER_EXPIRE_MAX) {
		ring_cell_size[gt_timer_nr_rings] = cell_size;
		gt_timer_nr_rings++;
		if (cell_size * GT_TIMER_RING_SIZE > GT_TIMER_EXPIRE_MAX) {
			break;
		} else {
			cell_size = ((cell_size * GT_TIMER_RING_SIZE) >> 2llu);
			GT_ASSERT(gt_timer_nr_rings < GT_TIMER_NR_RINGS_MAX);
		}
	}
	GT_ASSERT(gt_timer_nr_rings);
	rc = gt_timer_mod_alloc_rings(log);
	if (rc) {
		gt_log_scope_deinit(log, &this_log);
		return rc;
	}
	for (i = 0; i < gt_timer_nr_rings; ++i) {
		ring = gt_timer_rings[i];
		gt_timer_ring_init(ring, ring_cell_size[i]);
		GT_LOGF(log, LOG_INFO, 0, "hit; ring=%d, cell=%llu",
		       i, 1llu << ring->r_cell_shift);
	}
	return 0;
}

void
gt_timer_mod_deinit(struct gt_log *log)
{
	gt_timer_mod_free_rings();
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_log_scope_deinit(log, &this_log);
}

#ifdef GT_TIMER_MOD_DISABLED
void
gt_timer_mod_check()
{
	gt_timer_last_time = gt_nsec;
}
#else /* GT_TIMER_MOD_DISABLED */
static void
gt_timer_mod_call(struct dllist *queue)
{
	struct gt_timer *timer;
	gt_timer_f fn;

	while (!dllist_isempty(queue)) {
		timer = DLLIST_FIRST(queue, struct gt_timer, tm_list);
		DLLIST_REMOVE(timer, tm_list);
		fn = (gt_timer_f)(timer->tm_data & ~GT_TIMER_RING_ID_MASK);
		timer->tm_data = 0;
		(*fn)(timer);
	}
}

void
gt_timer_mod_check()
{
	int i;
	struct dllist queue;
	struct gt_timer_ring *ring;

	if (gt_nsec - gt_timer_last_time < GT_TIMER_TIMEOUT) {
		return;
	}
	gt_timer_last_time = gt_nsec;
	dllist_init(&queue);
	for (i = 0; i < gt_timer_nr_rings; ++i) {
		ring = gt_timer_rings[i];
		gt_timer_ring_check(ring, &queue);
	}
	gt_timer_mod_call(&queue);
}
#endif /* GT_TIMER_MOD_DISABLED */

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
	struct gt_timer_ring *ring;

	if (!gt_timer_is_running(timer)) {
		return 0;
	}
	ring_id = gt_timer_ring_get_id(timer);
	GT_ASSERT(ring_id <= gt_timer_nr_rings);
	if (ring_id == gt_timer_nr_rings) {
		return 0;
	}
	ring = gt_timer_rings[ring_id];
	for (list = timer->tm_list.dls_next;
	     list != &timer->tm_list; /* Never occured */
	     list = list->dls_next) {
		e = list - ring->r_cells;
		if (e < GT_TIMER_RING_SIZE) {
			b = ring->r_cur & GT_TIMER_RING_MASK;
			if (e >= b) {
				dist = e - b;
			} else {
				dist = e + GT_TIMER_RING_SIZE - b;
			}
			return dist >> ring->r_cell_shift;
		}
	}
	GT_BUG1("invalid ring; ring_id=%d; timer=%p", ring_id, timer);
	return 0;
}

#ifdef GT_TIMER_iMOD_DISABLED
void
gt_timer_set(struct gt_timer *timer, gt_time_t expire, gt_timer_f fn)
{
}
#else /* GT_TIMER_MOD_DISABLED */
void
gt_timer_set(struct gt_timer *timer, gt_time_t expire, gt_timer_f fn)
{
	int ring_id;
	uintptr_t uint_fn;
	gt_time_t dist, pos;
	struct gt_log *log;
	struct dllist *head;
	struct gt_timer_ring *ring;

	uint_fn = (uintptr_t)fn;
	GT_ASSERT(uint_fn != 0);
	GT_ASSERT((uint_fn & GT_TIMER_RING_ID_MASK) == 0);
	GT_ASSERT(expire <= GT_TIMER_EXPIRE_MAX);
	gt_timer_del(timer);
	dist = 0;
	for (ring_id = 0; ring_id < gt_timer_nr_rings; ++ring_id) {
		ring = gt_timer_rings[ring_id];
		dist = expire >> ring->r_cell_shift;
		GT_ASSERT3(0, dist >= 2, "expire=%"PRIu64", ring=%d",
		        expire, ring_id);
		if (dist < GT_TIMER_RING_SIZE) {
			break;
		}
	}
	if (ring_id == gt_timer_nr_rings) {
		log = GT_LOG_TRACE1(set);
		GT_LOGF(log, LOG_ERR, 0, "too big expire=%"PRIu64, expire);
		ring_id = gt_timer_nr_rings - 1;
		ring = gt_timer_rings[ring_id];
		dist = GT_TIMER_RING_SIZE - 1;
	}
	GT_ASSERT((ring_id & ~GT_TIMER_RING_ID_MASK) == 0);
	ring = gt_timer_rings[ring_id];
	pos = ring->r_cur + dist;
	head = ring->r_cells + (pos & GT_TIMER_RING_MASK);
	ring->r_nr_timers++;
	timer->tm_data = uint_fn|ring_id;
	DLLIST_INSERT_HEAD(head, timer, tm_list);
	GT_DBG(set, 0,
	       "ok; timer=%p, fn=%p, ring=%d, cur=%"PRIu64", head=%p, dist=%d",
	       timer, fn, ring_id, ring->r_cur, head, (int)dist);
}
#endif /* GT_TIMER_MOD_DISABLED */

#ifdef GT_TIMER_MOD_DISABLED
void
gt_timer_del(struct gt_timer *timer)
{
}

#else /* GT_TIMER_MOD_DISABLED */
void
gt_timer_del(struct gt_timer *timer)
{
	int ring_id;
	struct gt_timer_ring *ring;

	if (gt_timer_is_running(timer)) {
		ring_id = gt_timer_ring_get_id(timer);
		ring = gt_timer_rings[ring_id];
		ring->r_nr_timers--;
		GT_DBG(del, 0, "ok; timer=%p, ring=%d", timer, ring_id);
		GT_ASSERT(ring->r_nr_timers >= 0);
		DLLIST_REMOVE(timer, tm_list);
		timer->tm_data = 0;
	}
}
#endif /* GT_TIMER_MOD_DISABLED */

#ifndef GT_TIMER_MOD_DISABLED
static void
gt_timer_ring_check(struct gt_timer_ring *ring, struct dllist *queue)
{
	int i;
	gt_time_t pos;
	struct gt_timer *timer;
	struct dllist *head;

	pos = ring->r_cur;
	ring->r_cur = (gt_nsec >> ring->r_cell_shift);
	GT_ASSERT(pos <= ring->r_cur);
	if (ring->r_nr_timers == 0) {
		return;
	}
	for (i = 0; pos <= ring->r_cur && i < GT_TIMER_RING_SIZE; ++pos, ++i) {
		head = ring->r_cells + (pos & GT_TIMER_RING_MASK);
		while (!dllist_isempty(head)) {
			ring->r_nr_timers--;
			GT_ASSERT(ring->r_nr_timers >= 0);
			timer = DLLIST_FIRST(head, struct gt_timer, tm_list);
			DLLIST_REMOVE(timer, tm_list);
			DLLIST_INSERT_HEAD(queue, timer, tm_list);
		}
		if (ring->r_nr_timers == 0) {
			break;
		}
	}
}
#endif /* GT_TIMER_MOD_DISABLED */
