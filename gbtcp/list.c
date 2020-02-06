/* GPL2 license */
#include "list.h"

void
dllist_init(struct  dllist *head)
{
	head->dls_next = head->dls_prev = head;
}

int
dllist_size(struct dllist *head)
{
	int size;
	struct dllist *cur;

	size = 0;
	dllist_foreach(cur, head) {
		size++;
	}
	return size;
}

int
dllist_isempty(struct dllist *head)
{
	return head->dls_next == head;
}

struct dllist *
dllist_first(struct dllist *head)
{
	return head->dls_next;
}

struct dllist *
dllist_last(struct dllist *head)
{
	return head->dls_prev;
}

void
dllist_insert_head(struct dllist *head, struct dllist *l)
{
	l->dls_next = head->dls_next;
	l->dls_prev = head;
	head->dls_next->dls_prev = l;
	head->dls_next = l;
}

void
dllist_insert_tail(struct dllist *head, struct dllist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	head->dls_prev->dls_next = l;
	head->dls_prev = l;
}

void
dllist_insert_before(struct dllist *b, struct dllist *l)
{
	l->dls_next = b;
	l->dls_prev = b->dls_prev;
	b->dls_prev = l;
}

void
dllist_insert_after(struct dllist *a, struct dllist *l)
{
	l->dls_next = a->dls_next;
	l->dls_prev = a;
	a->dls_next = l;
}

void
dllist_remove(struct dllist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	list->dls_prev->dls_next = list->dls_next;
}

void
dllist_replace(struct dllist *old, struct dllist *new)
{
	new->dls_next = old->dls_next;
	new->dls_next->dls_prev = new;
	new->dls_prev = old->dls_prev;
	new->dls_prev->dls_next = new;
}

void
dllist_replace_init(struct dllist *old, struct dllist *new)
{
	dllist_replace(old, new);
	dllist_init(old);	
}
