// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_LPTREE_H
#define GBTCP_LPTREE_H

#include <gbtcp/kernel/list.h>
#include <gbtcp/kernel/subr.h>

struct lptree_node;
struct gt_mcache;

// A child slot in a node holds either a struct lptree_node * or a struct
// lptree_rule *. Both start with a u8 type tag so they can be told apart.
#define LPTREE_NODE 1
#define LPTREE_RULE 2

struct lptree_rule {
	u8 lpr_type;
	struct gt_dlist lpr_list;
	struct lptree_node *lpr_parent;
	uint32_t lpr_key;
	uint8_t lpr_key_rem;
	uint8_t lpr_depth;
	uint8_t lpr_depth_rem;
};

struct lptree {
	struct lptree_node *lpt_root;
	struct gt_mcache *lpt_mm_cache;
};

int lptree_init(struct lptree *);
void lptree_deinit(struct lptree *);
struct lptree_rule *lptree_search(struct lptree *, uint32_t);
void lptree_del(struct lptree *, struct lptree_rule *);
struct lptree_rule *lptree_get(struct lptree *, uint32_t, int);
int lptree_add(struct lptree *, struct lptree_rule *, uint32_t, int);

#endif // GBTCP_LPTREE_H
