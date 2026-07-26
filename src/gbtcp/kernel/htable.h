// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_HTABLE_H
#define GBTCP_HTABLE_H

#include <gbtcp/kernel/list.h>

#define HTABLE_POWOF2 (1 << 0)

struct htable;
struct gt_mcache;

typedef struct gt_dlist htable_entry_t;

typedef uint32_t (*htable_f)(void *);

typedef int (*gt_htable_handler_f)(struct htable *t, struct gt_dlist *slot,
				   void *udata);

struct htable_bucket {
	struct spinlock htb_lock;
	struct gt_dlist htb_head;
};

struct htable {
	int ht_size;
	int ht_mask;
	int ht_flags;
	htable_f ht_fn;
	struct htable_bucket *ht_array;
	struct gt_mcache *ht_mm_cache; // backing allocator for ht_array
};

struct gt_htable_iterator {
	uint bucket_index;
	uint slot_index;
};

#if 0
#define HTABLE_BUCKET_LOCK(b) UNUSED(b)
#define HTABLE_BUCKET_UNLOCK(b) UNUSED(b)
#else // 1
#define HTABLE_BUCKET_LOCK(b) spinlock_lock(&(b)->htb_lock)
#define HTABLE_BUCKET_UNLOCK(b) spinlock_unlock(&(b)->htb_lock)
#endif //

void htable_bucket_init(struct htable_bucket *);
int htable_init(struct htable *, struct gt_mcache *, int, htable_f, int);
void htable_deinit(struct htable *);
struct htable_bucket *htable_bucket_get(struct htable *, uint32_t);

int gt_htable_iterate(struct htable *t, struct gt_htable_iterator *it,
		      gt_htable_handler_f handler, void *udata);

#endif // GBTCP_HTABLE_H
