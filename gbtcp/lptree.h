// GPL2 license
#ifndef GBTCP_LPTREE_H
#define GBTCP_LPTREE_H

#include "subr.h"
#include "list.h"
#include "mbuf.h"

struct lptree_node;

struct lptree_rule {
	struct mbuf lpr_mbuf;
#define lpr_list lpr_mbuf.mb_list
	struct lptree_node *lpr_parent;
	uint32_t lpr_key;
	uint8_t lpr_key_rem;
	uint8_t lpr_depth;
	uint8_t lpr_depth_rem;
};

struct lptree {
	struct lptree_node *lpt_root;
	struct mbuf_pool *lpt_node_pool;
};

int lptree_mod_init(void **);
int lptree_mod_attach(void *);
void lptree_mod_deinit(void *);
void lptree_mod_detach();

int lptree_init(struct lptree *);
void lptree_deinit(struct lptree *);
struct lptree_rule *lptree_search(struct lptree *, uint32_t);
void lptree_del(struct lptree *, struct lptree_rule *);
struct lptree_rule *lptree_get(struct lptree *, uint32_t, int);
int lptree_set(struct lptree *, struct lptree_rule *, uint32_t, int);

#endif // GBTCP_LPTREE_H
