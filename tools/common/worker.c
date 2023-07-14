// SPDX-License-Identifier: GPL-2.0
#include "subr.h"
#include "pid.h"
#include "worker.h"

static int master_done;
static struct worker *workers[CPU_SETSIZE];
static int worker_num;

static void
kill_workers(void)
{
	int i, rc, wstatus;

	//signal(SIGCHLD, SIG_IGN);
	for (i = 0; i < worker_num; ++i) {
		if (workers[i]->wrk_pid) {
			rc = kill(workers[i]->wrk_pid, SIGKILL);
			if (rc == -1) {
				errorf(errno, "kill(pid=%d) failed", workers[i]->wrk_pid);
			}
			rc = waitpid(workers[i]->wrk_pid, &wstatus, 0);
			if (rc == -1) {
				errorf(errno, "waitpid(pid=%d) failed", workers[i]->wrk_pid);
			}
		}
	}
}

static struct worker *
alloc_worker(void)
{
	struct worker *worker;

	worker = mmap(NULL, sizeof(*worker), PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (worker == MAP_FAILED) {
		die(errno, "mmap(%zu, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS) failed",
			sizeof(*worker));
	} else {
		worker->wrk_pid = 0;
		worker->wrk_reqs = 0;
		worker->wrk_conns = 0;
		worker->wrk_concurrency = 0;
		worker->wrk_cpu = 0;
	}
	return worker;
}

void
free_worker(struct worker *worker)
{
	munmap(worker, sizeof(*worker));
}

static int
alloc_workers(cpuset_t *worker_cpus)
{
	int i;
	struct worker *worker;

	worker_num = 0;
	for (i = 0; i < CPU_SETSIZE; ++i) {
		if (CPU_ISSET(i, worker_cpus)) {
			worker = alloc_worker();
			worker->wrk_cpu = i;
			workers[worker_num++] = worker;
		}
	}
	return worker_num;
}

static void
master_quit(void)
{
	master_done = true;
}

static void
master_loop(int report_num, unsigned int (*sleep_fn)(unsigned int))
{
	int i, j;

	unsigned long long reqs, reqs_prev;
	double rps;
	suseconds_t usec;
	struct timeval tv, tv2;

	gettimeofday(&tv, NULL);
	reqs_prev = 0;
	for (j = 0; j < report_num; ++j) {
		if (master_done) {
			break;
		}
		(*sleep_fn)(1);
		gettimeofday(&tv2, NULL);
		reqs = 0;
		for (i = 0; i < worker_num; ++i) {
			reqs += workers[i]->wrk_reqs;
		}
		usec = 1000000 * (tv2.tv_sec - tv.tv_sec) +  (tv2.tv_usec - tv.tv_usec);
		rps = 1000000.0 * (reqs - reqs_prev) / usec;
		printf("%d\n", (int)rps);
		tv = tv2;
		reqs_prev = reqs;
	}
	master_done = 1;
}

static void
sigusr1(int signum)
{
	master_quit();	
}

/*static void
sigchld(int signum)
{
	int i, rc, pid, wstatus;

	wstatus = 0;
	rc = wait(&wstatus);
	if (rc >= 0) {
		pid = rc;
		for (i = 0; i < worker_num; ++i) {
			if (workers[i]->wrk_pid == pid) {
				errorf(errno, "Worker %d terminated", pid);
				workers[i]->wrk_pid = 0;
				master_quit();
				return;
			}
		}
	}
}*/

void
start_master(cpuset_t *worker_cpus, int concurrency, const char *pname, int port,
	int report_num,
	void *(*worker_loop_fn)(void *),
	pid_t (*fork_fn)(void),
	unsigned int (*sleep_fn)(unsigned int))
{
	int i, rc, pid, pid_file_fd, concurrency_per_worker;
	struct worker *worker;
	char pid_file_path[PATH_MAX];

	pid_file_fd = -1;
	if (port) {
		pid_file_get_path(pid_file_path, pname, port); 
		pid_file_fd = pid_file_open(pid_file_path);
		pid = getpid();
		rc = pid_file_acquire(pid_file_fd, pid);
		if (rc < 0) {
			die(0, "%s already listen on port %d", pname, port);
		}
	}
	alloc_workers(worker_cpus);
	if (worker_num == 0) {
		die(0, "No workers specified");
	}
	if (concurrency < worker_num) {
		concurrency = worker_num;
	}
	concurrency_per_worker = concurrency / worker_num;
	signal(SIGUSR1, sigusr1);
//	signal(SIGCHLD, sigchld);
	for (i = 0; i < worker_num; ++i) {
		worker = workers[i];
		worker->wrk_concurrency = concurrency_per_worker;
		if (fork_fn == NULL) {
			rc = pthread_create(&worker->wrk_pthread, NULL, worker_loop_fn, worker);
			set_affinity2(worker->wrk_pthread, worker->wrk_cpu);
			if (rc) {
				die(rc, "pthread_create() failed");
			}
		} else {
			rc = (*fork_fn)();
			if (rc == -1) {
				kill_workers();
				die(errno, "fork() failed");
			} else if (rc == 0) {
				set_affinity(worker->wrk_cpu);
				(*worker_loop_fn)(worker);
			} else {
				worker->wrk_pid = rc;
			}
		}
	}
	master_loop(report_num, sleep_fn);
	kill_workers();
	if (port) {
		close(pid_file_fd);
	}
}

