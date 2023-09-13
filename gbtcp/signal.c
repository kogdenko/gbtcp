// SPDX-License-Identifier: LGPL-2.1-only

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
