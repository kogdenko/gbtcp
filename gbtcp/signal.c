#include "internals.h"

struct signal_mod {
	struct log_scope log_scope;
};

void *gt_signal_stack;
size_t gt_signal_stack_size;
static struct signal_mod *curmod;

int
signal_mod_init(struct log *log, void **pp)
{
	int rc;
	struct signal_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "signal");
	rc = sys_malloc(log, &gt_signal_stack, SIGSTKSZ);
	if (rc == 0)
		gt_signal_stack_size = SIGSTKSZ;
	return rc;
}

int
signal_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
signal_mod_deinit(struct log *log, void *raw_mod)
{
	struct signal_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	free(gt_signal_stack);
	gt_signal_stack = NULL;
	gt_signal_stack_size = 0;
	shm_free(mod);
}

void
signal_mod_detach(struct log *log)
{
	curmod = NULL;
}

int
gt_signal_sigaction(int signum, const struct sigaction *act,
	struct sigaction *oldact)
{
	int rc;
	struct sigaction newact;
	struct log *log;

	log = log_trace0();
	if (act == NULL) {
		rc = sys_sigaction(log, signum, NULL, oldact);
	} else {
		memcpy(&newact, act, sizeof(newact));
		newact.sa_flags |= SA_ONSTACK;
		rc = sys_sigaction(log, signum, &newact, oldact);
	}
	return rc;
}

int
gt_signal_sigaltstack(const stack_t *ss, stack_t *oss)
{
	BUG; // TODO:
	return -EINVAL;
}

int
gt_signal_sigstack(struct sigstack *ss, struct sigstack *oss)
{
	BUG;
	return -EINVAL;
}
