// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/htable.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/sys.h>

struct htable_id {
	uint32_t lo;
	uint32_t hi;
};

void
htable_bucket_init(struct htable_bucket *b)
{
	gt_dlist_init(&b->htb_head);
	spinlock_init(&b->htb_lock);
}

static void
htable_free_array(struct htable *t)
{
	gt_free_internal(t->ht_mm_cache, t->ht_array);
	t->ht_array = NULL;
}

static int
htable_resize(struct htable *t, int size)
{
	int i;
	void *ptr;
	int new_size, new_mask;

	if (t->ht_flags & HTABLE_POWOF2) {
		new_size = gt_roundup_pow2_32(size);
		new_mask = new_size - 1;
	} else {
		new_size = size;
		new_mask = 0;
	}
	ptr = gt_malloc(t->ht_mm_cache, new_size * sizeof(struct htable_bucket),
			0);
	if (ptr == NULL) {
		return -ENOMEM;
	}
	htable_free_array(t);
	t->ht_array = ptr;
	t->ht_size = new_size;
	t->ht_mask = new_mask;
	for (i = 0; i < t->ht_size; ++i) {
		htable_bucket_init(t->ht_array + i);
	}
	return 0;
}

int
htable_init(struct htable *t, struct gt_mcache *mm_cache, int size, htable_f fn,
	    int flags)
{
	int rc;

	t->ht_flags = flags;
	t->ht_fn = fn;
	t->ht_array = NULL;
	t->ht_mm_cache = mm_cache;
	rc = htable_resize(t, size);
	return rc;
}

void
htable_deinit(struct htable *t)
{
	htable_free_array(t);
}

struct htable_bucket *
htable_bucket_get(struct htable *t, uint32_t h)
{
	int i;

	if (t->ht_flags & HTABLE_POWOF2) {
		i = h & t->ht_mask;
	} else {
		i = h % t->ht_size;
	}
	return t->ht_array + i;
}

int
gt_htable_iterate(struct htable *t, struct gt_htable_iterator *it,
		  gt_htable_handler_f handler, void *udata)
{
	int rc;
	uint slot_index;
	struct gt_dlist *slot;
	struct htable_bucket *b;

	for (; it->bucket_index < t->ht_size; ++it->bucket_index) {
		b = t->ht_array + it->bucket_index;
		slot_index = 0;
		gt_dlist_foreach(slot, &b->htb_head) {
			if (it->slot_index == slot_index) {
				it->slot_index++;
				rc = (*handler)(t, slot, udata);
				return rc;
			}
			slot_index = 0;
		}
	}
	return -EAGAIN;
}
