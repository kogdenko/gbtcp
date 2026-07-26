// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/timer.h>

#define GT_TIMER_RING_ZERO (GT_TIMER_RING_MAX + 1)
#define GT_TIMER_RING_CALL (GT_TIMER_RING_MAX + 2)
#define GT_TIMER_RING_NONE (GT_TIMER_RING_MAX + 3)

static void
gt_timer_ring_init(struct gt_timer_ring *ring, u64 now, u64 seg_size)
{
	int i;

	ring->tmr_seg_shift = __builtin_ctzll(seg_size);
	ring->tmr_pos = now >> ring->tmr_seg_shift;
	ring->tmr_n_timers = 0;
	for (i = 0; i < GT_TIMER_RING_SIZE; ++i) {
		gt_dlist_init(ring->tmr_seg + i);
	}
}

int
gt_timer_wheel_init(struct gt_timer_wheel *tmw)
{
	int i;
	u64 now, seg_size, ring_seg_size[GT_TIMER_RING_MAX];

	seg_size = GT_TIMER_SEG_SIZE_MIN;
	tmw->tmw_n_rings = 0;
	while (seg_size < GT_TIMER_EXPIRE_MAX) {
		assert(tmw->tmw_n_rings < GT_TIMER_RING_MAX);
		ring_seg_size[tmw->tmw_n_rings] = seg_size;
		tmw->tmw_n_rings++;
		if (seg_size * GT_TIMER_RING_SIZE > GT_TIMER_EXPIRE_MAX) {
			break;
		}
		seg_size = (seg_size * GT_TIMER_RING_SIZE) >> 2;
	}

	tmw->tmw_last_time = 0;
	tmw->tmw_ring =
		gt_malloc(shm_cache(),
			  tmw->tmw_n_rings * sizeof(struct gt_timer_ring), 0);
	if (tmw->tmw_ring == NULL) {
		tmw->tmw_n_rings = 0;
		return -ENOMEM;
	}

	now = shared_ns();
	for (i = 0; i < tmw->tmw_n_rings; ++i) {
		gt_timer_ring_init(tmw->tmw_ring + i, now, ring_seg_size[i]);
	}

	gt_dlist_init(&tmw->tmw_zero_timer_head);

	return 0;
}

void
gt_timer_wheel_deinit(struct gt_timer_wheel *tmw)
{
	assert(gt_timer_wheel_is_empty(tmw));
	gt_free_internal(shm_cache(), tmw->tmw_ring);
	tmw->tmw_ring = NULL;
}

int
gt_timer_wheel_is_empty(struct gt_timer_wheel *tmw)
{
	int i;

	if (!gt_dlist_is_empty(&tmw->tmw_zero_timer_head)) {
		return 0;
	}
	for (i = 0; i < tmw->tmw_n_rings; ++i) {
		if (tmw->tmw_ring[i].tmr_n_timers) {
			return 0;
		}
	}
	return 1;
}

static void
gt_timer_call(struct gt_dlist *cq)
{
	struct gt_timer *timer;

	while (!gt_dlist_is_empty(cq)) {
		timer = GT_DLIST_FIRST(cq, struct gt_timer, tm_link);
		GT_DLIST_REMOVE(timer, tm_link);
		timer->tm_ring_id = GT_TIMER_RING_NONE;
		GT_WORKER_FUNC_EXEC(&timer->tm_fn, timer, timer);
	}
}

static void
gt_timer_ring_run(struct gt_timer_ring *ring, u64 now, struct gt_dlist *cq)
{
	int i;
	u64 pos;
	struct gt_dlist *seg;
	struct gt_timer *timer;

	pos = ring->tmr_pos;
	ring->tmr_pos = now >> ring->tmr_seg_shift;
	assert(pos <= ring->tmr_pos);
	if (ring->tmr_n_timers == 0) {
		return;
	}

	for (i = 0; pos <= ring->tmr_pos && i < GT_TIMER_RING_SIZE;
	     ++pos, ++i) {
		seg = ring->tmr_seg + (pos & GT_TIMER_RING_MASK);
		while (!gt_dlist_is_empty(seg)) {
			assert(ring->tmr_n_timers > 0);
			ring->tmr_n_timers--;

			timer = GT_DLIST_FIRST(seg, struct gt_timer, tm_link);
			timer->tm_ring_id = GT_TIMER_RING_CALL;
			GT_DLIST_REMOVE(timer, tm_link);
			GT_DLIST_INSERT_HEAD(cq, timer, tm_link);
		}

		if (ring->tmr_n_timers == 0) {
			break;
		}
	}
}

void
gt_timer_wheel_run(struct gt_timer_wheel *tmw)
{
	int i;
	u64 now;
	struct gt_dlist cq;

	now = shared_ns();
	if (now - tmw->tmw_last_time < GT_TIMER_EXPIRE_MIN) {
		return;
	}

	tmw->tmw_last_time = now;
	gt_dlist_init(&cq);
	for (i = 0; i < tmw->tmw_n_rings; ++i) {
		gt_timer_ring_run(tmw->tmw_ring + i, now, &cq);
	}
	gt_timer_call(&cq);
}

void
gt_timer_wheel_call_zero_timers(struct gt_timer_wheel *tmw)
{
	struct gt_dlist cq;
	struct gt_timer *timer;

	gt_dlist_init(&cq);
	while (!gt_dlist_is_empty(&tmw->tmw_zero_timer_head)) {
		timer = GT_DLIST_FIRST(&tmw->tmw_zero_timer_head,
				       struct gt_timer, tm_link);
		GT_DLIST_REMOVE(timer, tm_link);
		GT_DLIST_INSERT_TAIL(&cq, timer, tm_link);
	}
	gt_timer_call(&cq);
}

static int
gt_timer_seg_migrate(struct gt_dlist *dst_seg, struct gt_dlist *src_seg)
{
	int n = 0;
	struct gt_timer *timer;

	while (!gt_dlist_is_empty(src_seg)) {
		timer = GT_DLIST_FIRST(src_seg, struct gt_timer, tm_link);
		GT_DLIST_REMOVE(timer, tm_link);
		GT_DLIST_INSERT_TAIL(dst_seg, timer, tm_link);
		n++;
	}
	return n;
}

void
gt_timer_wheel_migrate(struct gt_timer_wheel *dst, struct gt_timer_wheel *src,
		       u8 sid)
{
	int i, j, n;
	struct gt_timer_ring *src_ring, *dst_ring;

	(void)sid;
	assert(dst->tmw_n_rings == src->tmw_n_rings);
	for (i = 0; i < src->tmw_n_rings; ++i) {
		src_ring = src->tmw_ring + i;
		dst_ring = dst->tmw_ring + i;
		n = 0;
		for (j = 0; j < GT_TIMER_RING_SIZE; ++j) {
			n += gt_timer_seg_migrate(dst_ring->tmr_seg + j,
						  src_ring->tmr_seg + j);
		}
		assert(n == src_ring->tmr_n_timers);
		dst_ring->tmr_n_timers += n;
		src_ring->tmr_n_timers = 0;
	}
}

void
gt_timer_init(struct gt_timer *timer)
{
	timer->tm_ring_id = GT_TIMER_RING_NONE;
}

int
gt_timer_is_running(struct gt_timer *timer)
{
	return timer->tm_ring_id != GT_TIMER_RING_NONE;
}

static void
gt__timer_arm(struct gt_timer_wheel *tmw, struct gt_timer *timer, u64 expire)
{
	int ring_id;
	u16 seg_id;
	u64 dist, pos;
	struct gt_dlist *seg;
	struct gt_timer_ring *ring;

	if (expire > GT_TIMER_EXPIRE_MAX) {
		expire = GT_TIMER_EXPIRE_MAX;
	}

	if (gt_timer_is_running(timer)) {
		gt__timer_cancel(tmw, timer);
	}

	if (expire == 0) {
		timer->tm_ring_id = GT_TIMER_RING_ZERO;
		GT_DLIST_INSERT_TAIL(&tmw->tmw_zero_timer_head, timer, tm_link);
		return;
	}

	for (ring_id = 0; ring_id < tmw->tmw_n_rings; ++ring_id) {
		ring = tmw->tmw_ring + ring_id;
		dist = expire >> ring->tmr_seg_shift;
		if (dist < GT_TIMER_RING_SIZE) {
			break;
		}
	}
	assert(ring_id < tmw->tmw_n_rings);
	assert(dist >= 1);

	pos = ring->tmr_pos + dist;
	seg_id = (pos & GT_TIMER_RING_MASK);
	seg = ring->tmr_seg + seg_id;
	timer->tm_ring_id = ring_id;
	GT_DLIST_INSERT_HEAD(seg, timer, tm_link);
	ring->tmr_n_timers++;
}

void
gt__timer_set_fn(struct gt_timer_wheel *tmw, struct gt_timer *timer, u64 expire,
		 struct gt_worker_func fn)
{
	timer->tm_fn = fn;
	gt__timer_arm(tmw, timer, expire);
}

void
gt__timer_cancel(struct gt_timer_wheel *tw, struct gt_timer *timer)
{
	struct gt_timer_ring *ring;

	if (!gt_timer_is_running(timer)) {
		return;
	}

	if (timer->tm_ring_id < GT_TIMER_RING_MAX) {
		ring = tw->tmw_ring + timer->tm_ring_id;
		assert(ring->tmr_n_timers > 0);
		ring->tmr_n_timers--;
	}

	GT_DLIST_REMOVE(timer, tm_link);
	timer->tm_ring_id = GT_TIMER_RING_NONE;
}
