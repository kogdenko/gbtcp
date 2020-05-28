// gpl2 license
#ifndef GBTCP_HTABLE_H
#define GBTCP_HTABLE_H

#include "sysctl.h"

#define HTABLE_SHARED (1 << 0)

typedef struct dlist htable_entry_t;

typedef uint32_t (*htable_f)(void *);
typedef void (*htable_sysctl_f)(void *, const char *, struct strbuf *);

struct htable_bucket {
	struct spinlock htb_lock;
	struct dlist htb_head;
};

struct htable {
	int ht_size;
	int ht_mask;
	int ht_flags;
	htable_f ht_fn;
	htable_sysctl_f ht_sysctl_fn;
	struct htable_bucket *ht_array;
};

int htable_mod_init(void **);
int htable_mod_attach(void *);
void htable_mod_deinit(void *);
void htable_mod_detach();

void htable_bucket_init(struct htable_bucket *);
int htable_init(struct htable *, int, htable_f, int);
void htable_deinit(struct htable *);
struct htable_bucket *htable_bucket_get(struct htable *, uint32_t);

void sysctl_add_htable(const char *, int, struct htable *, htable_sysctl_f);

#endif // GBTCP_HTABLE_H
