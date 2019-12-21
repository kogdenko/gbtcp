#include "signal.h"
#include "log.h"
#include "sys.h"
#include "subr.h"

#define GT_SIGNAL_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(mod_deinit) \
	x(sigaction) \

void *gt_signal_stack;
size_t gt_signal_stack_size;

static struct gt_log_scope this_log;
GT_SIGNAL_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

int
gt_signal_mod_init()
{
	int rc;
	struct gt_log *log;

	gt_log_scope_init(&this_log, "signal");
	GT_SIGNAL_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);	
	log = GT_LOG_TRACE1(mod_init);
	rc = gt_sys_malloc(log, &gt_signal_stack, SIGSTKSZ);
	if (rc == 0) {
		gt_signal_stack_size = SIGSTKSZ;
	}
	return rc;
}

void
gt_signal_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_log_scope_deinit(log, &this_log);
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

	log = GT_LOG_TRACE1(sigaction);
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
	GT_BUG; // TODO:
	return -EINVAL;
}

int
gt_signal_sigstack(struct sigstack *ss, struct sigstack *oss)
{
	GT_BUG;
	return -EINVAL;
}
