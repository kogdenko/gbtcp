// SPDX-License-Identifier: LGPL-2.1-only

#include <dlfcn.h>

#include <gbtcp/kernel/backtrace.h>
#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/inet.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/timer.h>
#include <gbtcp/kernel/vector.h>
#include <gbtcp/kernel/worker.h>

#define gt_module_is_inited(m) (m->mmod_name[0] != '\0')

#define GT_MODULE_FOREACH(i, m) \
	for (i = 0; i < GT_MODULE_MAX; ++i) \
		if ((m = &shared->shm_mods[i]) && gt_module_is_inited(m))

static u8
gt_main_module_get_id(struct gt_main_module *m)
{
	return m - shared->shm_mods;
}

static struct gt_main_module *
gt_main_module_get(const char *name)
{
	int i;
	struct gt_main_module *mmod;

	GT_MODULE_FOREACH(i, mmod) {
		if (!strcmp(mmod->mmod_name, name)) {
			return mmod;
		}
	}

	return NULL;
}

static struct gt_worker_module *
gt_worker_module_get(const char *name)
{
	struct gt_main_module *mod;

	mod = gt_main_module_get(name);
	if (mod == NULL) {
		return NULL;
	}

	return current->worker_modules_buf + gt_main_module_get_id(mod);
}

static void
gt_module_get_path(char *path, const char *name)
{
	snprintf(path, PATH_MAX, "%s/libgbtcp-%s.so", shared->module_directory,
		 name);
}

static void *
gt_module_dlopen(const char *path)
{
	void *object;

	object = dlopen(path, RTLD_NOW);
	if (object == NULL) {
		gt_dbg("dlopen('%s') failed (%s)", path, dlerror());
	}
	return object;
}

static void *
gt_module_dlsym(void *object, const char *func)
{
	void *ptr;

	ptr = dlsym(object, func);
	if (ptr == NULL) {
		//gt_dbg("Failed to load module function `%s` (%s)", func,
		//       dlerror());
	}

	return ptr;
}

static void
gt__worker_module_unload(struct gt_worker_module *wrk_mod)
{
	if (wrk_mod->wmod_object == NULL) {
		return;
	}

	if (wrk_mod->module_worker_stop) {
		(*wrk_mod->module_worker_stop)();
	}

	gt_bfd_close(wrk_mod->wmod_bfd);

	gt_vec_free(wrk_mod->module_function, gt_get_kallocator());

	dlclose(wrk_mod->wmod_object);
	wrk_mod->wmod_object = NULL;

	GT_DLIST_REMOVE(wrk_mod, wmod_list);
	current->n_worker_modules--;
}

void
gt_set_module_directory(void)
{
	size_t len;
	char *tmp, *dir;
	char path[PATH_MAX];

	dir = gt_get_executable_path(path, sizeof(path));
	assert(dir != NULL);
	tmp = (char *)gt_basename(dir);

	*(tmp - 1) = '\0';

	len = strlen(dir);
	shared->module_directory = gt_malloc(shm_cache(), len + 1, 0);
	memcpy(shared->module_directory, dir, len + 1);
}

int
gt_main_module_load(const char *name)
{
	int i, rc, slot;
	char func[GT_MODULE_NAME_MAX + 128];
	char path[PATH_MAX];
	struct gt_main_module *mmod;

	slot = -1;
	for (i = 0; i < GT_MODULE_MAX; ++i) {
		mmod = shared->shm_mods + i;
		if (!gt_module_is_inited(mmod)) {
			if (slot < 0) {
				slot = i;
			}
		} else if (!strcmp(mmod->mmod_name, name)) {
			return -EEXIST;
		}
	}

	if (slot < 0) {
		return -ENOMEM;
	}

	mmod = shared->shm_mods + slot;

	// The slot may be recycled from an unloaded module, so the function
	// table must start empty rather than inheriting stale names. Shrinks
	// in place (keeping whatever capacity is already there) rather than
	// freeing: gt_vec_resize() down to 0 never fails.
	gt_vec_resize(mmod->worker_func_name_table, gt_get_kallocator(), 0, 0);

	gt_module_get_path(path, name);
	mmod->mmod_object = gt_module_dlopen(path);
	if (mmod->mmod_object == NULL) {
		return -EINVAL;
	}

	snprintf(func, sizeof(func), "gt_%s_module_init", name);
	mmod->module_init = gt_module_dlsym(mmod->mmod_object, func);
	if (mmod->module_init == NULL) {
		return -ESRCH;
	}

	snprintf(func, sizeof(func), "gt_%s_module_postinit", name);
	mmod->module_postinit = gt_module_dlsym(mmod->mmod_object, func);

	snprintf(func, sizeof(func), "gt_%s_module_deinit", name);
	mmod->module_deinit = gt_module_dlsym(mmod->mmod_object, func);

	snprintf(func, sizeof(func), "gt_%s_module_worker_init", name);
	mmod->module_worker_init = gt_module_dlsym(mmod->mmod_object, func);

	snprintf(func, sizeof(func), "gt_%s_module_worker_deinit", name);
	mmod->module_worker_deinit = gt_module_dlsym(mmod->mmod_object, func);

	rc = (*mmod->module_init)(slot, &mmod->mmod_user);

	if (rc) {
		return rc;
	}

	gt_strzcpy(mmod->mmod_name, name, sizeof(mmod->mmod_name));
	GT_DLIST_INSERT_TAIL(&shared->module_head, mmod, mmod_list);

	return 0;
}

int
gt_main_module_postinit(const char *name)
{
	struct gt_main_module *mod;

	mod = gt_main_module_get(name);
	if (mod == NULL) {
		return -ESRCH;
	}
	if (mod->module_postinit == NULL) {
		return 0;
	}
	return (*mod->module_postinit)(mod);
}

void
gt_main_modules_unload(void)
{
	struct gt_main_module *m;

	GT_DLIST_FOREACH_REVERSE(m, &shared->module_head, mmod_list) {
		if (m->module_deinit != NULL) {
			(*m->module_deinit)(m->mmod_user);
		}
	}
}

// Controller-side per-service init of `name` for `w`, an already-attached worker that missed it in gt_main_modules_worker_init().
int
gt_main_module_worker_init(const char *name, struct service *w)
{
	struct gt_main_module *mmod;

	mmod = gt_main_module_get(name);
	if (mmod == NULL) {
		return -ESRCH;
	}
	if (mmod->module_worker_init == NULL) {
		return 0;
	}
	return (*mmod->module_worker_init)(w, w->p_pid, w->p_tid, w->wrk_conn);
}

int
gt_main_modules_worker_init(struct service *s, int pid, int tid,
			    struct gt_api_conn *cp)
{
	int rc;
	struct gt_main_module *m, *prev;

	GT_DLIST_FOREACH(m, &shared->module_head, mmod_list) {
		if (m->module_worker_init == NULL) {
			continue;
		}
		rc = (*m->module_worker_init)(s, pid, tid, cp);
		if (rc) {
			for (prev = GT_DLIST_PREV(m, mmod_list);
			     &prev->mmod_list != &shared->module_head;
			     prev = GT_DLIST_PREV(prev, mmod_list)) {
				if (prev->module_worker_deinit != NULL) {
					(*prev->module_worker_deinit)(s->p_sid);
				}
			}
			return rc;
		}
	}

	return 0;
}

void
gt_main_modules_worker_deinit(struct service *s)
{
	struct gt_main_module *m;

	GT_DLIST_FOREACH_REVERSE(m, &shared->module_head, mmod_list) {
		if (m->module_worker_deinit != NULL) {
			(*m->module_worker_deinit)(s->p_sid);
		}
	}
}

int
gt_worker_module_load(const char *name)
{
	int i, n, rc, module_id;
	char buf[1024];
	char path[PATH_MAX];
	void *obj;
	struct gt_main_module *mod;
	struct gt_worker_module *wrk_mod;

	mod = gt_main_module_get(name);
	if (mod == NULL) {
		return -ESRCH;
	}

	module_id = gt_main_module_get_id(mod);
	wrk_mod = current->worker_modules_buf + module_id;
	memset(wrk_mod, 0, sizeof(*wrk_mod));
	if (wrk_mod->wmod_object != NULL) {
		return -EBUSY;
	}

	gt_module_get_path(path, name);
	obj = gt_module_dlopen(path);
	if (obj == NULL) {
		return -ESRCH;
	}
	wrk_mod->wmod_object = obj;

	gt_bfd_open(&wrk_mod->wmod_bfd, path, GT_BFD_SHARED_LIBRARY);

	snprintf(buf, sizeof(buf), "gt_%s_module_worker_start", name);
	wrk_mod->module_worker_start = gt_module_dlsym(obj, buf);

	snprintf(buf, sizeof(buf), "gt_%s_module_worker_stop", name);
	wrk_mod->module_worker_stop = gt_module_dlsym(obj, buf);

	// Resolve the function table the controller registered. It is frozen
	// before the module was published, so it cannot grow under us here.
	n = gt_vec_size(mod->worker_func_name_table);
	if (n > 0) {
		rc = gt_vec_resize(wrk_mod->module_function,
				   gt_get_kallocator(), n, 0);
		if (rc) {
			return rc;
		}
		for (i = 0; i < n; ++i) {
			wrk_mod->module_function[i] = gt_module_dlsym(
				obj, mod->worker_func_name_table[i]);
		}
	}

	(*wrk_mod->module_worker_start)(shared->shm_mods[module_id].mmod_user);

	GT_DLIST_INSERT_TAIL(&current->worker_module_head, wrk_mod, wmod_list);
	current->n_worker_modules++;

	return 0;
}

// Load every main module this worker does not have yet (in module order).
// Used at attach: nothing is loaded yet, so this loads everything. Later
// loads reach the worker over the worker_module_load API fanout.
int
gt_worker_modules_load(void)
{
	int rc;
	struct gt_main_module *m;

	rc = 0;
	GT_DLIST_FOREACH(m, &shared->module_head, mmod_list) {
		rc = gt_worker_module_load(m->mmod_name);
		if (rc) {
			break;
		}
	}

	return rc;
}

void
gt_worker_module_unload(const char *name)
{
	struct gt_worker_module *wmod;

	wmod = gt_worker_module_get(name);
	if (wmod == NULL) {
		return;
	}

	gt__worker_module_unload(wmod);
}

void
gt_worker_modules_unload(void)
{
	struct gt_worker_module *wmod, *tmp;

	GT_DLIST_FOREACH_REVERSE_SAFE(wmod, &current->worker_module_head,
				      wmod_list, tmp) {
		gt__worker_module_unload(wmod);
	}
}

void *
gt_worker_func_get(const struct gt_worker_func *fn)
{
	struct gt_worker_module *wmod;

	assert(gt_worker_func_is_set(fn));
	assert(fn->fn_module_id < GT_MODULE_MAX);

	wmod = current->worker_modules_buf + fn->fn_module_id;
	assert(fn->fn_id < gt_vec_size(wmod->module_function));

	return wmod->module_function[fn->fn_id];
}

// Give `name` a stable id inside this module's function table, so it can be
// stored as a (module_id, fn_id) pair and called later from a worker in
// another process. Call from module_init only: the table must be complete
// before the module is published to workers.
int
gt__worker_func_register(u8 module_id, const char *name,
			 struct gt_worker_func *fn)
{
	int i, n, rc;
	struct gt_main_module *mod;

	if (module_id >= GT_MODULE_MAX) {
		return -EINVAL;
	}
	if (strlen(name) >= GT_WORKER_FUNC_NAME_MAX) {
		return -ENAMETOOLONG;
	}

	mod = shared->shm_mods + module_id;

	// The controller resolves it too, so a typo fails at registration
	// rather than in every worker at load time.
	if (gt_module_dlsym(mod->mmod_object, name) == NULL) {
		return -ESRCH;
	}

	n = gt_vec_size(mod->worker_func_name_table);
	for (i = 0; i < n; ++i) {
		if (!strcmp(mod->worker_func_name_table[i], name)) {
			goto out;
		}
	}

	// fn_id is a u8; GT_FUNCTION_INVALID_ID (0xff) marks "unset", so that's
	// the real ceiling on how many functions one module can register.
	if (n >= GT_FUNCTION_INVALID_ID) {
		return -ENOSPC;
	}

	rc = gt_vec_resize(mod->worker_func_name_table, gt_get_kallocator(),
			   n + 1, 0);
	if (rc) {
		return rc;
	}

	i = n;
	gt_strzcpy(mod->worker_func_name_table[i], name,
		   GT_WORKER_FUNC_NAME_MAX);

out:
	fn->fn_module_id = module_id;
	fn->fn_id = i;

	return 0;
}
