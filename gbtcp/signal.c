#include "internals.h"

struct signal_mod {
	struct log_scope log_scope;
};

void *gt_signal_stack;
size_t gt_signal_stack_size;
static struct signal_mod *curmod;

int
signal_mod_init(void **pp)
{
	int rc;
	struct signal_mod *mod;

	rc = shm_malloc(pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "signal");
	rc = sys_malloc(&gt_signal_stack, SIGSTKSZ);
	if (rc == 0)
		gt_signal_stack_size = SIGSTKSZ;
	return rc;
}

int
signal_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
signal_mod_deinit(void *raw_mod)
{
	struct signal_mod *mod;

	mod = raw_mod;
	log_scope_deinit(&mod->log_scope);
	free(gt_signal_stack);
	gt_signal_stack = NULL;
	gt_signal_stack_size = 0;
	shm_free(mod);
}

void
signal_mod_detach()
{
	curmod = NULL;
}

int
gt_signal_sigaction(int signum, const struct sigaction *act,
	struct sigaction *oldact)
{
	int rc;
	struct sigaction newact;

	if (act == NULL) {
		rc = sys_sigaction(signum, NULL, oldact);
	} else {
		memcpy(&newact, act, sizeof(newact));
		newact.sa_flags |= SA_ONSTACK;
		rc = sys_sigaction(signum, &newact, oldact);
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
