// gpl2 license
#include "internals.h"

void
dlist_init(struct  dlist *head)
{
	head->dls_next = head->dls_prev = head;
}

int
dlist_size(struct dlist *head)
{
	int size;
	struct dlist *cur;

	size = 0;
	dlist_foreach(cur, head) {
		size++;
	}
	return size;
}

int
dlist_is_empty(struct dlist *head)
{
	return head->dls_next == head;
}

struct dlist *
dlist_first(struct dlist *head)
{
	return head->dls_next;
}

struct dlist *
dlist_last(struct dlist *head)
{
	return head->dls_prev;
}

void
dlist_insert_head(struct dlist *head, struct dlist *l)
{
	l->dls_next = head->dls_next;
	l->dls_prev = head;
	head->dls_next->dls_prev = l;
	head->dls_next = l;
}

void
dlist_insert_tail(struct dlist *head, struct dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	head->dls_prev->dls_next = l;
	head->dls_prev = l;
}

void
dlist_insert_tail_rcu(struct dlist *head, struct dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	rcu_assign_pointer(head->dls_prev->dls_next, l);
	head->dls_prev = l;
}

void
dlist_insert_before(struct dlist *l, struct dlist *b)
{
	l->dls_next = b;
	l->dls_prev = b->dls_prev;
	b->dls_prev = l;
}

void
dlist_insert_after(struct dlist *a, struct dlist *l)
{
	l->dls_next = a->dls_next;
	l->dls_prev = a;
	a->dls_next = l;
}

void
dlist_remove(struct dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	list->dls_prev->dls_next = list->dls_next;
}

void
dlist_remove_rcu(struct dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	WRITE_ONCE(list->dls_prev->dls_next, list->dls_next);
}

void
dlist_replace(struct dlist *new, struct dlist *old)
{
	new->dls_next = old->dls_next;
	new->dls_next->dls_prev = new;
	new->dls_prev = old->dls_prev;
	new->dls_prev->dls_next = new;
}

void
dlist_replace_init(struct dlist *new, struct dlist *old)
{
	dlist_replace(new, old);
	dlist_init(old);	
}

void
dlist_splice_tail(struct dlist *dst, struct dlist *src)
{
	dst->dls_prev->dls_next = src->dls_next;
	src->dls_next->dls_prev = dst->dls_prev;
	src->dls_prev->dls_next = dst->dls_next;
	dst->dls_next->dls_prev = src->dls_prev;
}

void
dlist_splice_tail_init(struct dlist *dst, struct dlist *src)
{
	ASSERT(!dlist_is_empty(src));
	dlist_splice_tail(dst, src);
	dlist_init(src);
}
