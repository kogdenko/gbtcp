// GPL v2
#include "internals.h"

#define ITABLE_SLOT_BUSY -2

struct itable_slot {
	int its_next;
} __attribute__((aligned(ALIGNMENT_PTR)));

static void
itable_reset(struct itable *t)
{
	t->it_free_slot_head = -1;
	t->it_size = t->it_cap = 0;
	t->it_buf = NULL;
}

struct itable_slot *
itable_get_slot(struct itable *t, int id)
{
	assert(id < t->it_size);
	return (struct itable_slot *)(t->it_buf + id * t->it_slot_size);
}

static int
itable_grow(struct itable *t)
{
	size_t cap;
	void *buf;

	if (t->it_cap == 0) {
		cap = 128;
	} else if (t->it_cap == INT_MAX) {
		return -ENOMEM;
	} else {
		cap = t->it_cap * 2;
	}
	if (cap <= t->it_cap) {
		cap = INT_MAX;
	}
	assert(cap > t->it_cap);
	buf = shm_realloc(t->it_buf, cap * t->it_slot_size);
	if (buf == NULL) {
		return -ENOMEM;
	}
	t->it_buf = buf;
	t->it_cap = cap;
	return 0;
}

int
itable_init(struct itable *t, int obj_size)
{
	assert(obj_size >= sizeof(int));
	t->it_slot_size = sizeof(struct itable_slot) + obj_size;
	itable_reset(t);
	return 0;
}

void
itable_deinit(struct itable *t)
{
	shm_free(t->it_buf);
	itable_reset(t);
}

void *
itable_get(struct itable *t, int id)
{
	struct itable_slot *slot;

	if (id >= t->it_size) {
		return NULL;
	}
	slot = itable_get_slot(t, id);
	if (slot->its_next == ITABLE_SLOT_BUSY) {
		return slot + 1;
	} else {
		return NULL;
	}
}

int
itable_alloc(struct itable *t, const void *obj)
{
	int rc, id;
	struct itable_slot *slot;

	if (t->it_free_slot_head == -1) {
		if (t->it_size == t->it_cap) {
			rc = itable_grow(t);
			if (rc < 0) {
				return rc;
			}
		}
		id = t->it_size;
		t->it_size++;
		slot = itable_get_slot(t, id);
	} else {
		id = t->it_free_slot_head;
		slot = itable_get_slot(t, id);
		assert(slot->its_next != ITABLE_SLOT_BUSY);
		t->it_free_slot_head = slot->its_next;
	}
	slot->its_next = ITABLE_SLOT_BUSY;
	memcpy(slot + 1, obj, t->it_slot_size - sizeof(slot));
	return id;
}

int
itable_alloc2(struct itable *t, const void *obj, int id)
{
	return -ENOTSUP;
}

void
itable_free(struct itable *t, int id)
{
	struct itable_slot *slot;

	assert(id < t->it_size);
	if (t->it_size == id + 1) {
		t->it_size--;
	} else {
		slot = itable_get_slot(t, id);
		assert(slot->its_next == ITABLE_SLOT_BUSY);
		slot->its_next = t->it_free_slot_head;
		t->it_free_slot_head = id;
	}
}
