// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_HTABLE_H
#define GBTCP_HTABLE_H

#include "sysctl.h"

#define HTABLE_SHARED (1 << 0)
#define HTABLE_POWOF2 (1 << 1)

typedef struct gt_dlist htable_entry_t;

typedef uint32_t (*htable_f)(void *);
typedef void (*htable_sysctl_f)(void *, const char *, struct strbuf *);

struct htable_bucket {
	struct spinlock htb_lock;
	struct gt_dlist htb_head;
};

struct htable {
	int ht_size;
	int ht_mask;
	int ht_flags;
	htable_f ht_fn;
	htable_sysctl_f ht_sysctl_fn;
	struct htable_bucket *ht_array;
};

#if 0
#define HTABLE_BUCKET_LOCK(b) UNUSED(b)
#define HTABLE_BUCKET_UNLOCK(b) UNUSED(b)
#else // 1
#define HTABLE_BUCKET_LOCK(b) spinlock_lock(&(b)->htb_lock)
#define HTABLE_BUCKET_UNLOCK(b) spinlock_unlock(&(b)->htb_lock)
#endif //

void htable_bucket_init(struct htable_bucket *);
int htable_init(struct htable *, int, htable_f, int);
void htable_deinit(struct htable *);
struct htable_bucket *htable_bucket_get(struct htable *, uint32_t);

void sysctl_add_htable_list(const char *, int, struct htable *, htable_sysctl_f);
void sysctl_add_htable_size(const char *, struct htable *);

#endif // GBTCP_HTABLE_H
