#include "signal.h"
#include "log.h"
#include "sys.h"
#include "subr.h"

struct signal_mod {
	struct log_scope log_scope;
};

void *gt_signal_stack;
size_t gt_signal_stack_size;

static struct signal_mod *this_mod;

int
gt_signal_mod_init()
{
	int rc;
	struct gt_log *log;

	log_scope_init(&this_mod->log_scope, "signal");
	log = log_trace0();
	rc = gt_sys_malloc(log, &gt_signal_stack, SIGSTKSZ);
	if (rc == 0) {
		gt_signal_stack_size = SIGSTKSZ;
	}
	return rc;
}

void
gt_signal_mod_deinit(struct gt_log *log)
{
	LOG_TRACE(log);
	log_scope_deinit(log, &this_mod->log_scope);
	free(gt_signal_stack);
	gt_signal_stack = NULL;
	gt_signal_stack_size = 0;
}

int
gt_signal_sigaction(int signum, const struct sigaction *act,
	struct sigaction *oldact)
{
	int rc;
	struct sigaction newact;
	struct gt_log *log;

	log = log_trace0();
	if (act == NULL) {
		rc = gt_sys_sigaction(log, signum, NULL, oldact);
	} else {
		memcpy(&newact, act, sizeof(newact));
		newact.sa_flags |= SA_ONSTACK;
		rc = gt_sys_sigaction(log, signum, &newact, oldact);
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
