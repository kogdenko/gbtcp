/* GPL2 license */
#include "lptree.h"
#include "mm.h"
#include "log.h"
#include "mbuf.h"

struct lptree_mod {
	struct log_scope log_scope;
	struct mbuf_pool *lpnode_pool;
};

static struct lptree_mod *current_mod;

#define lpnode_dynamic_cast(m) \
	((m)->mb_pool_id == current_mod->lpnode_pool->mbp_id)

static void
lpnode_init(struct lpnode *node, struct lpnode *parent)
{
	memset(node->lpn_children, 0, sizeof(node->lpn_children));
	dlist_init(&node->lpn_rules);
	node->lpn_hidden = NULL;
	node->lpn_parent = parent;
}
static int
lpnode_alloc(struct log *log, struct lpnode *parent, struct lpnode **pnode)
{
	int rc;
	LOG_TRACE(log);
	rc = mbuf_alloc(log, current_mod->lpnode_pool, (struct mbuf **)pnode);
	if (!rc) {
		lpnode_init(*pnode, parent);
	}
	return rc;
}
static int
lpnode_is_empty(struct lpnode *node)
{
	int i;
	if (!dlist_is_empty(&node->lpn_rules)) {
		return 0;
	}
	for (i = 0; i < UINT8_MAX; ++i) {
		if (node->lpn_children[i] != NULL) {
			return 0;
		}
	}
	return 1;
}
static void
lpnode_free(struct lpnode *node)
{
	ASSERT(lpnode_is_empty(node));
	mbuf_free(&node->lpn_mbuf);
}
int
lptree_mod_init(struct log *log, void **pp)
{
	int rc;
	struct lptree_mod *mod;
	LOG_TRACE(log);
	rc = mm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "lptree");
	rc = mbuf_pool_alloc(log, &mod->lpnode_pool,
	                     sizeof(struct lpnode));
	return rc;
}
int
lptree_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
	return 0;
}
void
lptree_mod_deinit(struct log *log, void *raw_mod)
{
	struct lptree_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	mbuf_pool_free(mod->lpnode_pool);
	mod->lpnode_pool = NULL;
	log_scope_deinit(log, &mod->log_scope);
}
void
lptree_mod_detach(struct log *log)
{
	current_mod = NULL;
}
int
lptree_init(struct log *log, struct lpnode *root)
{
	lpnode_init(root, NULL);
	return 0;
}
void
lptree_deinit(struct lpnode *root)
{
	ASSERT(lpnode_is_empty(root));
}
struct lprule *
lptree_search(struct lpnode *root, uint32_t key)
{
	int i;
	uint32_t idx;
	struct mbuf *m;
	struct lpnode *node;
	struct lprule *rule;
	node = root;
	for (i = 0; i < 4; ++i) {
		idx = (key >> ((3 - i) << 3)) & 0x000000FF;
		m = node->lpn_children[idx];
		if (m == NULL) {
			break;
		} else if (lpnode_dynamic_cast(m)) {
			node = (struct lpnode *)m;
		} else {
			rule = (struct lprule *)m;
			return rule;
		}
	}
	if (node->lpn_hidden != NULL) {
		return node->lpn_hidden;
	}
	return NULL;
}
static int
lpnode_set(struct log *log,struct lpnode *parent,
	int idx, struct lpnode **pnode)
{
	int rc;
	struct mbuf *m;
	struct lprule *rule;
	m = parent->lpn_children[idx];
	if (m == NULL) {
		rc = lpnode_alloc(log, parent, pnode);
		if (rc) {
			return rc;
		}
	} else if (lpnode_dynamic_cast(m))  {
		*pnode = (struct lpnode *)m;
		return 0;
	} else {
		rule = (struct lprule *)m;
		rc = lpnode_alloc(log, parent, pnode);
		if (rc) {
			return rc;
		}
		(*pnode)->lpn_hidden = rule;
	}
	parent->lpn_children[idx] = (struct mbuf *)(*pnode);
	return 0;
}
static void
lpnode_unset(struct lpnode *node)
{
	int i;
	struct mbuf *m;
	struct lpnode *parent;
	parent = node->lpn_parent;
	for (i = 0; i < UINT8_MAX; ++i) {
		if (parent->lpn_children[i] == node) {
			if (node->lpn_hidden != NULL) {
				m = (struct mbuf *)node->lpn_hidden;
			} else {
				m = NULL;
			}
			parent->lpn_children[i] = m;
			break;
		}
	}
}
static void
lprule_set(struct lprule *rule)
{
	int i, n;
	uint32_t idx;
	void **slot;
	struct mbuf *m;
	struct lpnode *node;
	struct lprule *tmp;
	n = 1 << (8 - rule->lpr_depth_rem);
	ASSERT(rule->lpr_key_rem + n <= UINT8_MAX);
	for (i = 0; i < n; ++i) {
		idx = rule->lpr_key_rem + i;
		slot = rule->lpr_parent->lpn_children + idx;
		m = (struct mbuf *)(*slot);
		if (m == NULL) {
			*slot = rule;
		} else if (lpnode_dynamic_cast(m)) {
			node = (struct lpnode *)m;
			tmp = node->lpn_hidden;
			if (tmp == NULL || rule->lpr_depth > tmp->lpr_depth) {
				node->lpn_hidden = rule;
			}
		} else {
			tmp = (struct lprule *)m;
			if (rule->lpr_depth > tmp->lpr_depth) {
				*slot = rule;
			}
		}
	}
}
static void
lprule_unset(struct lprule *rule)
{
	int i;
	struct mbuf *m;
	struct lpnode *node;
	for (i = 0; i < UINT8_MAX; ++i) {
		m = rule->lpr_parent->lpn_children[i];
		if (m == NULL) {
			continue;
		}
		if (m == (struct mbuf *)rule) {
			rule->lpr_parent->lpn_children[i] = NULL;
		} else if (lpnode_dynamic_cast(m)) {
			node = (struct lpnode *)m;
			if (node->lpn_hidden == rule) {
				node->lpn_hidden = NULL;
			}
		}
	}
}
void
lptree_del(struct lprule *rule)
{
	struct lpnode *node, *parent;
	struct lprule *cur;
	DLIST_REMOVE(rule, lpr_list);
	node = rule->lpr_parent;
	lprule_unset(rule);
	DLIST_FOREACH(cur, &node->lpn_rules, lpr_list) {
		if (cur->lpr_depth < rule->lpr_depth) {
			lprule_set(cur);
		} else {
			break;
		}
	}
	mbuf_free(&rule->lpr_mbuf);
	while (1) {
		parent = node->lpn_parent;
		if (parent != NULL && lpnode_is_empty(node)) {
			lpnode_unset(node);
			lpnode_free(node);
			node = parent;
		} else {
			break;
		}
	}
}
static int
lptree_operate(struct log *log, struct lpnode *root,
	struct lprule **prule, uint32_t key, int depth)
{
	int i, d, rc;
	uint32_t k, m;
	struct lpnode *node, *parent;
	struct lprule *rule, *after;
	ASSERT(depth > 0);
	ASSERT(depth <= 32);
	parent = root;
	for (i = 0; i < 4; ++i) {
		k = (key >> ((3 - i) << 3)) & 0x000000FF;
		d = depth - (i << 3);
		ASSERT(d);
		ASSERT(k < UINT8_MAX);
		if (d > 8) {
			if (*prule == NULL) {
				node = parent->lpn_children[k];
				if (node == NULL) {
					return -ESRCH;
				}
			} else {
				rc = lpnode_set(log, parent, k, &node);
				if (rc) {
					return rc;
				}
			}
			parent = node;
		} else {
			m = (0xff << (8 - d));
			k &= m;
			break;
		}
	}
	after = NULL;
	rc = 0;
	DLIST_FOREACH(rule, &parent->lpn_rules, lpr_list) {
		if (rule->lpr_depth == depth && rule->lpr_key == key) {
			if (*prule == NULL) {
				*prule = rule;
			}
			return -EEXIST;
		} else if (depth < rule->lpr_depth) {
			break;
		} else {
			after = rule;
		}
	}
	rule = *prule;
	if (rule == NULL) {
		return -ESRCH;
	}
	rule->lpr_key = key;
	rule->lpr_depth = depth;
	rule->lpr_key_rem = k;
	rule->lpr_depth_rem = d;
	rule->lpr_parent = parent;
	lprule_set(rule);
	if (after == NULL) {
		DLIST_INSERT_HEAD(&parent->lpn_rules, rule, lpr_list);
	} else {
		DLIST_INSERT_AFTER(after, rule, lpr_list);
	}
	return 0;
}
struct lprule *
lptree_get(struct lpnode *root, uint32_t key, int depth)
{
	int rc;
	struct lprule *rule;
	rule = NULL;
	rc = lptree_operate(NULL, root, &rule, key, depth);
	ASSERT(rc);
	if (rc == -EEXIST) {
		return rule;
	} else {
		return NULL;
	}
}
int
lptree_set(struct log *log, struct lpnode *root,
	struct lprule *rule, uint32_t key, int depth)
{
	int rc;
	LOG_TRACE(log);
	rc = lptree_operate(log, root, &rule, key, depth);
	return rc;
}
