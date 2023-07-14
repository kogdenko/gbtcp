// SPDX-License-Identifier: GPL-2.0
#ifndef GBTCP_TOOLS_COMMON_WORKER_H
#define GBTCP_TOOLS_COMMON_WORKER_H

struct worker {
	pthread_t wrk_pthread;
	int wrk_pid;
	unsigned long long wrk_reqs;
	int wrk_conns;
	int wrk_concurrency;
	int wrk_cpu;
};

void start_master(cpuset_t *worker_cpus, int, const char *, int, int,
		void *(*)(void *), pid_t (*)(void), unsigned int (*)(unsigned int));

#endif // GBTCP_TOOLS_COMMON_WORKER_H
