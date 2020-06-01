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

	rc = shm_malloc(pp, sizeof(*curmod));
	if (rc) {
		return rc;
	}
	curmod = *pp;
	log_scope_init(&curmod->log_scope, "signal");
	return rc;
}

int
signal_mod_attach(void *p)
{
	int rc;

	curmod = p;
	rc = sys_malloc(&gt_signal_stack, SIGSTKSZ);
	if (rc == 0) {
		gt_signal_stack_size = SIGSTKSZ;
	} else {
		curmod = NULL;
	}
	return rc;
}

void
signal_mod_deinit()
{
	if (curmod != NULL) {
		log_scope_deinit(&curmod->log_scope);
		shm_free(curmod);
		curmod = NULL;
	}
}

void
signal_mod_detach()
{
	sys_free(gt_signal_stack);
	gt_signal_stack = NULL;
	gt_signal_stack_size = 0;
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
