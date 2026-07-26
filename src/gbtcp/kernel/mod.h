// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include <assert.h>

#include <gbtcp/kernel/global.h>

#define GT_WORKER_FUNC_NAME_MAX 48

#define GT_WORKER_FUNC_REGISTER_TYPE(type, rettype, ...) \
	typedef rettype (*gt_module_##type##_f)(__VA_ARGS__);

#define GT_WORKER_FUNC_NAME(type, fn) \
	({ \
		gt_module_##type##_f gt_checked_ = (fn); \
		(void)gt_checked_; \
		#fn; \
	})

#define GT_WORKER_FUNC_REGISTER(module_id, type, fn, out) \
	gt__worker_func_register(module_id, GT_WORKER_FUNC_NAME(type, fn), out)

#define GT_WORKER_FUNC_EXEC(fn, type, ...) \
	((gt_module_##type##_f)gt_worker_func_get(fn))(__VA_ARGS__)

struct gt_timer;
struct service;
struct gt_api_conn;
struct route_if;

GT_WORKER_FUNC_REGISTER_TYPE(rx, int, struct route_if *, void *, int)
GT_WORKER_FUNC_REGISTER_TYPE(tx, void, void)
GT_WORKER_FUNC_REGISTER_TYPE(timer, void, struct gt_timer *);

struct gt_main_module {
	char mmod_name[GT_MODULE_NAME_MAX];

	struct gt_dlist mmod_list;

	void *mmod_user;
	void *mmod_object;

	int (*module_init)(u8 module_id, void **puser);
	int (*module_postinit)(void *mod);
	void (*module_deinit)(void *user);
	int (*module_worker_init)(struct service *s, int pid, int tid,
				  struct gt_api_conn *cp);
	void (*module_worker_deinit)(u8 worker_index);

	char (*worker_func_name_table)[GT_WORKER_FUNC_NAME_MAX];
};

struct gt_worker_module {
	struct gt_dlist wmod_list;

	void *wmod_object;

	struct gt_bfd *wmod_bfd;

	void (*module_worker_start)(void *m);
	void (*module_worker_stop)(void);

	void **module_function;
};

void gt_set_module_directory(void);

int gt_main_module_load(const char *name);

int gt_main_module_postinit(const char *name);

void gt_main_module_unload(const char *name);
void gt_main_modules_unload(void);

int gt_main_module_worker_init(const char *name, struct service *w);
int gt_main_modules_worker_init(struct service *s, int pid, int tid,
				struct gt_api_conn *cp);

void gt_main_modules_worker_deinit(struct service *s);

int gt_worker_module_load(const char *name);
int gt_worker_modules_load(void);

void gt_worker_modules_unload(void);

void *gt_worker_func_get(const struct gt_worker_func *fn);

int gt__worker_func_register(u8 module_id, const char *name,
			     struct gt_worker_func *fn);

#endif // GBTCP_MOD_H
