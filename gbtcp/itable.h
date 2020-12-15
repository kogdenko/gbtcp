// GPL v2
#ifndef GBTCP_ITABLE_H
#define GBTCP_ITABLE_H

struct itable {
	int it_size;
	int it_cap;
	int it_slot_size;
	int it_free_slot_head;
	u_char *it_buf;
};

void itable_init(struct itable *, int);
void itable_deinit(struct itable *);
void *itable_get(struct itable *, int);
int itable_alloc(struct itable *, const void *);
int itable_alloc2(struct itable *, const void *, int);
void itable_free(struct itable *, int);

#endif // GBTCP_ITABLE_H
