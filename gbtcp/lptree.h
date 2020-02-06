/* GPL2 license */
#ifndef GBTCP_LPTREE_H
#define GBTCP_LPTREE_H

#include "subr.h"
#include "list.h"
#include "mbuf.h"

struct lpnode {
	struct gt_mbuf lpn_mbuf;
	struct dllist lpn_rules;
	struct lprule *lpn_hidden;
	struct lpnode *lpn_parent;
	void *lpn_children[256];
};

struct lprule {
	struct gt_mbuf lpr_mbuf;
#define lpr_list lpr_mbuf.mb_list

	struct lpnode *lpr_parent;
	uint32_t lpr_key;
	uint8_t lpr_key_rem;
	uint8_t lpr_depth;
	uint8_t lpr_depth_rem;
};

int lptree_mod_init();
#define gt_lptree_mod_init lptree_mod_init

void lptree_mod_deinit(struct gt_log *log);
#define gt_lptree_mod_deinit lptree_mod_deinit

int lptree_init(struct gt_log *, struct lpnode *);

void lptree_deinit(struct lpnode *);

struct lprule *lptree_search(struct lpnode *, uint32_t);

void lptree_del(struct lprule *);

struct lprule *lptree_get(struct lpnode *, uint32_t, int);

int lptree_set(struct gt_log *, struct lpnode *, struct lprule *, uint32_t, int);

#endif /* GBTCP_LPTREE_H */
