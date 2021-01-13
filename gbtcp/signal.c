// GPL v2
#include "internals.h"

static sigset_t current_sigprocmask;
static int current_sigprocmask_set;

int
init_signals()
{
	int rc;
	sigset_t sigprocmask_block;

	sigfillset(&sigprocmask_block);
	rc = sys_sigprocmask(SIG_BLOCK, &sigprocmask_block,
		&current_sigprocmask);
	if (rc) {
		return rc;
	}
	current_sigprocmask_set = 1;
	return 0;
}

void
deinit_signals()
{
	if (current_sigprocmask_set) {
		current_sigprocmask_set = 0;
		sys_sigprocmask(SIG_SETMASK, &current_sigprocmask, NULL);
	}
}

int
signal_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;
	sigset_t tmp;

	if (!current_sigprocmask_set) {
		rc = sys_sigprocmask(how, set, oldset);
	} else {
		// unblock
		sys_sigprocmask(SIG_SETMASK, &current_sigprocmask, &tmp);
		rc = sys_sigprocmask(how, set, oldset);
		sys_sigprocmask(SIG_SETMASK, &tmp, &current_sigprocmask);
	}
	return rc;
}

const sigset_t *
signal_sigprocmask_get()
{
	return current_sigprocmask_set ? &current_sigprocmask : NULL;
}


// ALT stack implementation
#if 0
void *gt_signal_stack;
size_t gt_signal_stack_size;
static struct signal_mod *curmod;

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
#endif
