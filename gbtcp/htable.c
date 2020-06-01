#include "internals.h"

struct htable_mod {
	struct log_scope log_scope;
};

struct htable_id {
	uint32_t lo;
	uint32_t hi;
};

static struct htable_mod *curmod;

int
htable_mod_init(void **pp)
{
	int rc;

	rc = shm_malloc(pp, sizeof(*curmod));
	if (!rc) {
		curmod = *pp;
		log_scope_init(&curmod->log_scope, "htable");
	}
	return rc;
}

int
htable_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
htable_mod_deinit(void *raw_mod)
{
	struct htable_mod *mod;

	mod = raw_mod;
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
htable_mod_detach()
{
	curmod = NULL;
}

void
htable_bucket_init(struct htable_bucket *b)
{
	dlist_init(&b->htb_head);
	spinlock_init(&b->htb_lock);
}

int
htable_init(struct htable *t, int size, htable_f fn, int flags)
{
	int i, rc;
	malloc_f malloc_fn;

	t->ht_size = upper_pow2_32(size);
	t->ht_mask = t->ht_size - 1;
	t->ht_flags = flags;
	t->ht_fn = fn;
	if (flags & HTABLE_SHARED) {
		malloc_fn = shm_malloc;
	} else {
		malloc_fn = sys_malloc;
	}
	rc = (*malloc_fn)((void **)&t->ht_array,
	                  size * sizeof(struct htable_bucket));
	if (rc) {
		return rc;
	}
	for (i = 0; i < t->ht_size; ++i) {
		htable_bucket_init(t->ht_array + i);
	}
	return 0;
}

void
htable_deinit(struct htable *t)
{
	free_f free_fn;

	if (t->ht_flags & HTABLE_SHARED) {
		free_fn = shm_free;
	} else {
		free_fn = sys_free;
	}
	(*free_fn)(t->ht_array);
	t->ht_array = NULL;
}

struct htable_bucket *
htable_bucket_get(struct htable *t, uint32_t h) 
{
	return t->ht_array + ((h) & (t)->ht_mask);
}

static int
sysctl_htable_size(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *out)
{
	int rc, new_size;
	char *endptr;
	struct htable *t, new_t;

	t = udata;
	strbuf_addf(out, "%d", t->ht_size);
	if (new == NULL) {
		return 0;
	}
	new_size = strtoul(new, &endptr, 10);
	if (new_size == 0 || *endptr != '\0') {
		return -EINVAL;
	}
	if (new_size == t->ht_size) {
		return 0;
	}
	rc = htable_init(&new_t, new_size, t->ht_fn, t->ht_flags);
	if (rc) {
		return rc;
	}
	htable_deinit(t);
	*t = new_t;
	return 0;
}


static int
sysctl_htable_list_next(void *udata, const char *ident, struct strbuf *out)
{
	int rc, lo;
	struct dlist *e;
	struct htable *t;
	struct htable_id id;
	struct htable_bucket *b;

	id.hi = id.lo = 0;
	if (ident != NULL) {
		rc = sscanf(ident, "%d.%d", &id.hi, &id.lo);
		if (rc == 2) {
			id.lo++;
		}
	}
	t = (struct htable *)udata;
	for (; id.hi < t->ht_size; ++id.hi) {
		b = t->ht_array + id.hi;
		lo = 0;
		spinlock_lock(&b->htb_lock);
		dlist_foreach(e, &b->htb_head) {
			if (lo == id.lo) {
				spinlock_unlock(&b->htb_lock);
				strbuf_addf(out, "%d.%d", id.hi, id.lo);
				return 0;
			}
			lo++;
		}
		spinlock_unlock(&b->htb_lock);
		id.lo = 0;
	}
	return -ENOENT;
}

static int
sysctl_htable_list(void *udata, const char *ident,
	const char *new, struct strbuf *out)
{
	int rc, lo;
	struct dlist *e;
	struct htable *t;
	struct htable_id id;
	struct htable_bucket *b;

	rc = sscanf(ident, "%d.%d", &id.hi, &id.lo);
	if (rc != 2) {
		return -EPROTO;
	}
	t = (struct htable *)udata;
	if (id.hi >= t->ht_size) {
		return -ENOENT;
	}
	b = t->ht_array + id.hi;
	lo = 0;
	spinlock_lock(&b->htb_lock);
	dlist_foreach(e, &b->htb_head) {
		if (lo == id.lo) {
			(*t->ht_sysctl_fn)(e, new, out);
			break;
		}
		lo++;
	}
	spinlock_unlock(&b->htb_lock);
	if (lo == id.lo) {
		return 0;
	} else {
		return -ENOENT;
	}
}

void
sysctl_add_htable(const char *path0, int mode, struct htable *t,
	htable_sysctl_f fn)
{
	char path[PATH_MAX];

	ASSERT(t->ht_sysctl_fn == NULL);
	ASSERT(fn != NULL);
	t->ht_sysctl_fn = fn;
	snprintf(path, sizeof(path), "%s.size", path0);
	sysctl_add(path, SYSCTL_LD, t, NULL, sysctl_htable_size);
	snprintf(path, sizeof(path), "%s.list", path0);
	sysctl_add_list(path, mode, t,
	                sysctl_htable_list_next,
	                sysctl_htable_list);
}
