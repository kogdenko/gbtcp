/* GPL2 license */
#ifndef GBTCP_LPTREE_H
#define GBTCP_LPTREE_H

#include "subr.h"
#include "list.h"
#include "mbuf.h"

struct lpnode {
	struct mbuf lpn_mbuf;
	struct dlist lpn_rules;
	struct lprule *lpn_hidden;
	struct lpnode *lpn_parent;
	void *lpn_children[256];
};

struct lprule {
	struct mbuf lpr_mbuf;
#define lpr_list lpr_mbuf.mb_list
	struct lpnode *lpr_parent;
	uint32_t lpr_key;
	uint8_t lpr_key_rem;
	uint8_t lpr_depth;
	uint8_t lpr_depth_rem;
};

struct lptree {
	struct lpnode *lpt_root;
	struct mbuf_pool lpt_pool;
};

int lptree_mod_init(struct log *, void **);
int lptree_mod_attach(struct log *, void *);
int lptree_proc_init(struct log *, struct proc *);
void lptree_mod_deinit(struct log *, void *);
void lptree_mod_detach(struct log *);

int lptree_init(struct log *, struct lptree *);
void lptree_deinit(struct lptree *);
struct lprule *lptree_search(struct lptree *, uint32_t);
void lptree_del(struct lptree *, struct lprule *);
struct lprule *lptree_get(struct log *, struct lptree *, uint32_t, int);
int lptree_set(struct log *, struct lptree *, struct lprule *, uint32_t, int);

#endif /* GBTCP_LPTREE_H */
