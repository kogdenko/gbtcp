// GPL V2 License
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/epoll.h>
#else
#include <pthread_np.h>
#include <sys/event.h>
typedef cpuset_t cpu_set_t;
#endif

#define PROG_NAME "gbtcp-epoll-helloworld"

union my_data {
	struct {
		uint32_t fd;
		uint32_t state;
	};
	uint64_t u64;
};

struct worker {
	pthread_t wrk_pthread;
	int wrk_pid;
	unsigned long long wrk_reqs;
	int wrk_conns;
	int wrk_concurrency;
	int wrk_cpu;
	char wrk_buf[2048];
};

static int g_lflag;
static bool g_done = false;
static char reqbuf[] =
	"GET / HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: so_echo\r\n"
        "\r\n";
static struct sockaddr_in g_addr;
static int Cflag;


#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define UNUSED(x) ((void)(x))

#define dbg(fmt, ...) do { \
	printf("%-20s %-5d %-20s: ", __FILE__, __LINE__, __func__); \
	printf(fmt, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)

static void on_event(struct worker *, int, const union my_data *, short);

static void errorf(int errnum, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

static void die(int errnum, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

static void
verror(int errnum, const char *format, va_list ap)
{
	vfprintf(stderr, format, ap);
	if (errnum) {
		fprintf(stderr, " (%s)\n", strerror(errnum));
	} else {
		fprintf(stderr, "\n");
	}
}

static void
errorf(int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	verror(errnum, format, ap);
	va_end(ap);
}

static void
die(int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	verror(errnum, format, ap);
	va_end(ap);
	exit(1);
}

static void *
xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		die(0, "malloc(%zu) failed", size);
	}
	return ptr;
}

#define sys_close(fd) do { \
	close(fd); \
} while (0)

static int
sys_socket(int domain, int type, int protocol)
{
	int rc;

	rc = socket(domain, type, protocol);
	if (rc == -1) {
		assert(errno);
		die(errno, "socket(domain=0x%x, type=0x%x) failed", domain, type);
	}
	return rc;
}

static void
connect_failed(int errnum, struct sockaddr_in *addr)
{
	die(errnum, "connect(%s:%hu) failed", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
}

static int
sys_connect(int fd, struct sockaddr_in *addr)
{
	int rc;

	rc = connect(fd, (struct sockaddr *)addr, sizeof(*addr));
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		if (errno != EINPROGRESS) {
			connect_failed(errno, addr);
		}
	}
	return rc;
}

static int
sys_listen(int fd, int backlog)
{
	int rc;

	rc = listen(fd, backlog);
	if (rc == -1) {
		assert(errno);
		die(errno, "listen(fd=%d, backlog=%d) failed", fd, backlog);
	}
	return rc;
}

static int
sys_bind(int fd, struct sockaddr_in *addr)
{
	int rc;

	rc = bind(fd, (struct sockaddr *)addr, sizeof(*addr));
	if (rc == -1) {
		assert(errno);
		die(errno, "bind(fd=%d, addr=%s, port=%hu) failed",
			fd, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	}
	return rc;
}

static int
sys_accept4(int fd, int flags)
{
	int rc;

	rc = accept4(fd, NULL, NULL, flags);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		if (errno != EAGAIN) {
			die(-rc, "accept4(fd=%d, 0x%x) failed", fd, flags);
		}
	}
	return rc;
}

static int
sys_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	int rc;

	rc = setsockopt(fd, level, optname, optval, optlen);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		die(-rc, "setsockopt(fd=%d, %d, %d) failed", fd, level, optname);
	}
	return rc;
}

#ifdef __linux__
static int
event_queue_create()
{
	int rc;

	rc = epoll_create1(0);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		die(-rc, "epoll_create1() failed");
	}
	return rc;
}

static void
event_queue_ctl(int eq_fd, int is_new, const union my_data *data, int write)
{
	int rc;
	struct epoll_event event;

	event.events = EPOLLRDHUP;
	event.events |= EPOLLET;
	event.events |= write ? EPOLLOUT : EPOLLIN;
	event.data.u64 = data->u64;
	rc = epoll_ctl(eq_fd, is_new ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, data->fd, &event);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		die(-rc, "epoll_ctl(%s, events=0x%x, fd=%d) failed",
			is_new ? "EPOLL_CTL_ADD" : "EPOLL_CTL_MOD", event.events, data->fd);
	}
}

static void
event_queue_wait(struct worker *worker, int eq_fd, int to_ms)
{
	int i, n;
	short revents;
	struct epoll_event *e, events[128];
	union my_data data;

	n = epoll_wait(eq_fd, events, ARRAY_SIZE(events), to_ms);
	for (i = 0; i < n; ++i) {
		e = events + i;
		revents = 0;
		assert(e->events);
		if (e->events & EPOLLIN) {
			revents |= POLLIN;
		}
		if (e->events & EPOLLOUT) {
			revents |= POLLOUT;
		}
		if (e->events & (EPOLLERR|EPOLLHUP|EPOLLRDHUP)) {
			revents |= POLLERR;	
		}
		assert(revents);
		data.u64 = e->data.u64;
		on_event(worker, eq_fd, &data, revents);
	}
}
#else // __linux__
static int
event_queue_create()
{
	int rc;

	rc = kqueue();
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		die(-rc, "kqueue() failed");
	}
	return rc;
}

static void
event_queue_ctl(int eq_fd, int is_new, const union my_data *data, int write)
{
	int rc;
	struct kevent e;

	e.ident = data->fd;
	e.filter = write ? EVFILT_WRITE : EVFILT_READ;
	e.flags = EV_ADD;
	e.fflags = 0;
	e.udata = (void *)(uintptr_t)data->state;
	rc = kevent(eq_fd, &e, 1, NULL, 0, NULL);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		die(-rc, "kevent(EV_ADD, EVFILT_READ, fd=%d) failed",
			data->fd);
	}
}

static void
event_queue_wait(struct worker *worker, int eq_fd, int to_ms)
{
	int i, n;
	short revents;
	struct timespec ts;
	union my_data data;
	struct kevent *e, eventlist[128];

	ts.tv_sec = 0;
	ts.tv_nsec = to_ms * 1000 * 1000;
	n = kevent(eq_fd, NULL, 0, eventlist, ARRAY_SIZE(eventlist), &ts);
	for (i = 0; i < n; ++i) {
		e = eventlist + i;
		revents = 0;
		if (e->filter & EVFILT_READ) {
			revents |= POLLIN;
		}
		if (e->filter & EVFILT_WRITE) {
			revents |= POLLOUT;
		}
		if (e->flags & (EV_ERROR|EV_EOF)) {
			revents |= POLLERR;
		}
		data.fd = e->ident;
		data.state = (uintptr_t)e->udata;
		on_event(worker, eq_fd, &data, revents);
	}
}
#endif // __linux__

static ssize_t
write_record(int fd, const void *buf, size_t cnt)
{
	ssize_t rc;
	size_t off;

	for (off = 0; off < cnt; off += rc) {
		rc = write(fd, (const u_char *)buf + off, cnt - off);
		if (rc == -1) {
			assert(errno);
			if (errno == EINTR) {
				rc = 0;
			} else if (errno == EAGAIN) {
				break;
			} else {
				return -errno;
			}
		}
	}
	return off;
}

static int
read_record(int fd, void *buf, int cnt, int *len)
{
	int rc, n;

	*len = 0;
	while (*len < cnt) {
		n = cnt - *len;
		rc = read(fd, (u_char *)buf + *len, n);
		if (rc == 0) {
			return 0;
		} else if (rc == -1) {
			assert(errno);
			if (errno == EINTR) {
				continue;
			} else if (errno == EAGAIN) {
				break;
			} else {
				return -errno;
			}
		} else {
			*len += rc;
			if (rc < n) {
				break;
			}
		}
	}
	return 1;
}

static char *
pid_file_get_path(char *path, int port)
{
	snprintf(path, PATH_MAX, "/var/run/%s-%d.pid", PROG_NAME, port);
	return path;
}

static int
pid_file_open(const char *path)
{
	int rc;

	rc = open(path, O_CREAT|O_RDWR, 0666);
	if (rc == -1) {
		die(errno, "pid_file_open('%s') failed", path);
	}
	return rc;
}

static int
pid_file_lock(int fd, bool nonblock)
{
	int rc, flags;

	flags = LOCK_EX;
	if (nonblock) {
		flags |= LOCK_NB;
	}
	rc = flock(fd, flags);
	if (rc == -1) {
		if (errno != EWOULDBLOCK) {
			die(errno, "flock() failed");
		} else {
			rc = -errno;
		}
	}
	return rc;
}

static int
pid_file_read(int fd)
{
	int rc, pid;
	char buf[32];

	rc = read(fd, buf, sizeof(buf) - 1);
	if (rc == -1) {
		die(errno, "read() failed");
	}
	buf[rc] = '\0';
	rc = sscanf(buf, "%d", &pid);
	if (rc != 1 || pid <= 0) {
		die(0, "Bad pid file format");
	}
	return pid;
}

static int
pid_file_write(int fd, int pid)
{
	int rc, len;
	char buf[32];

	assert(pid >= 0);
	len = snprintf(buf, sizeof(buf), "%d", pid);
	rc = write_record(fd, buf, len);
	if (rc < 0) {
		die(-rc, "pid_file_write() failed");
	}
	return rc;
}

static int
pid_file_acquire(int fd, int pid)
{
	int rc;

	rc = pid_file_lock(fd, true);
	if (rc < 0) {
		return rc;
	}
	pid_file_write(fd, pid);
	return pid;
}

#define STATE_LISTEN 33
#define STATE_SERVER 44
#define STATE_CONNECT 55
#define STATE_CLIENT 66

static int
server(int eq_fd)
{
	int rc, fd, o;
	union my_data data;

	rc = sys_socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	o = 1;
	rc = sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));
	if (rc < 0) {
		sys_close(fd);
		return rc;
	}
	rc = sys_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &o, sizeof(o));
	if (rc < 0) {
		sys_close(fd);
		return rc;
	}
	rc = sys_bind(fd, &g_addr);
	if (rc < 0) {
		sys_close(fd);
		return rc;
	}
	rc = sys_listen(fd, 128);
	if (rc < 0) {
		sys_close(fd);
		return rc;
	}
	data.u64 = 0;
	data.fd = fd;
	data.state = STATE_LISTEN;
	event_queue_ctl(eq_fd, 1, &data, 0);
	return 0;
}

static int
client(struct worker *worker, int eq_fd)
{
	int rc, fd, write;
	union my_data data;

	rc = sys_socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	data.u64 = 0;
	data.fd = fd;
	rc = sys_connect(fd, &g_addr);
	if (rc == 0) {
		rc = write_record(fd, reqbuf, sizeof(reqbuf) - 1);
		if (rc < 0) {
			goto err;
		}
		data.state = STATE_CLIENT;
		write = 0;
	} if (rc == -EINPROGRESS) {
		data.state = STATE_CONNECT;
		write = 1;
	} else {
		goto err;
	}
	worker->wrk_conns++;
	event_queue_ctl(eq_fd, 1, &data, write);
	return 0;
err:
	sys_close(fd);
	return rc;
}

static int
clientn(struct worker *worker, int eq_fd)
{
	int rc;

	while (worker->wrk_conns < worker->wrk_concurrency) {
		rc = client(worker, eq_fd);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

static void
on_event(struct worker *worker, int eq_fd, const union my_data *data, short revents)
{
	int rc, fin, len, listen_fd, closed;
	union my_data new_data;

	switch (data->state) {
	case STATE_LISTEN:
		listen_fd = data->fd;
		while (1) {
			rc = sys_accept4(listen_fd, SOCK_NONBLOCK);
			if (rc < 0) {
				break;
			}
			new_data.fd = rc;
			new_data.state = STATE_SERVER;
			event_queue_ctl(eq_fd, 1, &new_data, 0);
			worker->wrk_conns++;
		}
		break;
	case STATE_SERVER:
		fin = 0;
		len = 0;
		assert(revents & (POLLIN|POLLERR));
		if (revents & POLLIN) {
			rc = read_record(data->fd, worker->wrk_buf, sizeof(worker->wrk_buf), &len);
			if (rc <= 0) {
				fin = 1;
			}
			if (len > 0) {
				rc = write_record(data->fd, worker->wrk_buf, len);
				if (rc < 0) {
					fin = 1;
				}
			}
		}
		if (revents & POLLERR) {
			fin = 1;
		}
		if (Cflag || fin) {
			sys_close(data->fd);
			worker->wrk_reqs++;
			worker->wrk_conns--;
		}
		break;
	case STATE_CONNECT:
		if (revents & POLLERR) {
			connect_failed(0, &g_addr);
			break;
		}
		rc = write_record(data->fd, reqbuf, sizeof(reqbuf) - 1);
		if (rc < 0) {
			sys_close(data->fd);
			worker->wrk_reqs++;
			worker->wrk_conns--;
			clientn(worker, eq_fd);
		} else {
			new_data = *data;
			new_data.state = STATE_CLIENT;
			event_queue_ctl(eq_fd, 0, &new_data, 0);
		}
		break;
	case STATE_CLIENT:
		closed = 0;
		if (revents & POLLERR) {
			closed = 1;
		} else {
			rc = read_record(data->fd, worker->wrk_buf, sizeof(worker->wrk_buf), &len);
			if (rc <= 0) {
				closed = 1;
			}
		}
		if (Cflag || closed) {
			sys_close(data->fd);
			worker->wrk_reqs++;
			worker->wrk_conns--;
			clientn(worker, eq_fd);
		}
		break;
	default:
		assert(0);
	}
}

static void
set_affinity(int cpu_id)
{
	int rc;
	cpu_set_t cpumask;

	CPU_ZERO(&cpumask);
	CPU_SET(cpu_id, &cpumask);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(cpumask), &cpumask);
	if (rc != 0) {
		die(rc, "pthread_setaffinity_np(%d) failed", cpu_id);
	}
}

static void *
loop(void *udata)
{
	int rc, eq_fd;
	struct worker *worker;

	worker = udata;
	set_affinity(worker->wrk_cpu);
	rc = event_queue_create();
	if (rc < 0) {
		return NULL;
	}
	eq_fd = rc;
	if (g_lflag) {
		rc = server(eq_fd);
	} else {
		rc = clientn(worker, eq_fd);
	}
	if (rc < 0) {
		sys_close(eq_fd);
		return NULL;
	}
	while (!g_done) {
		event_queue_wait(worker, eq_fd, -1);
	}
	return NULL;
}

static void
usage()
{
	printf(
	"Usage: so_echo [address]\n"
	"\n"
	"\tOptions:\n"
	"\t-h              Print this help\n"
	"\t-p port         Port number (default: 80)\n"
	"\t-l              Listen incoming connections\n"
	"\t-c concurrency  Number of parallel connections (default: 1)\n"
	"\t-C              Close connection after data transmit\n"
	"\t-a cpu-list     Affinity of processes\n"
	);
	exit(EXIT_SUCCESS);
}

//CPU_SETSIZE

static int
parse_cpu(char *s)
{
	char *endptr;
	int rc;

	rc = strtoul(s, &endptr, 10);
	if (*endptr == '\0') {
		if (rc >= CPU_SETSIZE) {
			return -ERANGE;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

static int
parse_cpus(cpu_set_t *cpumask, char *s)
{
	int i, cpu[2];
	char *range, *delim;

	for (range = strtok(s, ","); range != NULL; range = strtok(NULL, ",")) {
		delim = strchr(range, '-');
		if (delim == NULL) {
			cpu[0] = cpu[1] = parse_cpu(range);
		} else {
			*delim = '\0';
			cpu[0] = parse_cpu(range);
			cpu[1] = parse_cpu(delim + 1);
		}
		for (i = 0; i < 2; ++i) {
			if (cpu[i] < 0) {
				return cpu[i];
			}
		}
		if (cpu[0] > cpu[1]) {
			return -EINVAL;
		}
		for (i = cpu[0]; i <= cpu[1]; ++i) {
			CPU_SET(i, cpumask);
		}
	}
	return 0;
}

static void
kill_workers(struct worker **workers, int worker_num)
{
	int i, rc, wstatus;

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

static void
sigusr1(int signum)
{
	g_done = true;	
}

int
main(int argc, char **argv)
{
	int i, rc, opt, pid, port, worker_num, worker_num_safe;
	int concurrency, concurrency_per_worker, pid_file_fd;
	bool use_threads, stop;
	unsigned long long reqs, reqs2;
	double rps;
	char pid_file_path[PATH_MAX];
	suseconds_t usec;
	struct timeval tv, tv2, to;
	cpu_set_t cpumask;
	struct worker *worker, *workers[CPU_SETSIZE];

	use_threads = false;
	stop = false;
	CPU_ZERO(&cpumask);
	concurrency = 0;
	assert(sizeof(union my_data) == sizeof(uint64_t));
	port = 80;
	pid_file_fd = -1;
	while ((opt = getopt(argc, argv, "hp:lc:Ca:tSv")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			break;
		case 'p':
			port = strtoul(optarg, NULL, 10);
			break;
		case 'l':
			g_lflag = 1;
			break;
		case 'c':
			concurrency = strtoul(optarg, NULL, 10); 
			if (concurrency < 1) {
				concurrency = 1;
			}
			break;
		case 'C':
			Cflag = 1;
			break;
		case 'a':
			rc = parse_cpus(&cpumask, optarg);
			if (rc < 0) {
				die(-rc, "-a: Invalid cpu list");
			}
			break;
		case 't':
			use_threads = true;
			break;
		case 'S':
			stop = true;
			break;
		case 'v':
			printf("%s 0.5.1\n", PROG_NAME);
			return 0;
		}
	}
	g_addr.sin_family = AF_INET;
	g_addr.sin_port = htons(port);
	g_addr.sin_addr.s_addr = INADDR_ANY;
	if (stop) {
		pid_file_get_path(pid_file_path, port); 
		pid_file_fd = pid_file_open(pid_file_path);
		rc = pid_file_lock(pid_file_fd, true);
		if (rc < 0) {
			pid = pid_file_read(pid_file_fd);
			kill(pid, SIGUSR1);
			pid_file_lock(pid_file_fd, false);
		}
		return 0;
	}
	if (g_lflag) {
		pid_file_get_path(pid_file_path, port); 
		pid_file_fd = pid_file_open(pid_file_path);
		pid = getpid();
		rc = pid_file_acquire(pid_file_fd, pid);
		if (rc < 0) {
			die(0, "%s already listen on port %d", PROG_NAME, port);
		}
	}
	worker_num = CPU_COUNT(&cpumask);
	if (worker_num == 0) {
		usage();
		die(0, "-a: Not specified");
	}
	if (concurrency == 0) {
		concurrency = worker_num;
	}
	if (concurrency < worker_num) {
		die(0, "Number of workers should be greater then concurrency");
	}
	concurrency_per_worker = concurrency / worker_num;
	if (optind < argc) {
		rc = inet_aton(argv[optind], &g_addr.sin_addr);
		if (rc != 1) {
			die(0, "Invalid address: '%s'", argv[optind]);
		}
	} else {
		if (g_lflag == 0) {
			usage();
			die(0, "Address or '-l' flag must be specified");
		}
	}
	//printf("%s %s:%hu\n", g_lflag ? "Listening on" : "Connecting to",
	//	inet_ntoa(g_addr.sin_addr), ntohs(g_addr.sin_port));
	worker_num_safe = worker_num;
	worker_num = 0;
	for (i = 0; i < CPU_SETSIZE; ++i) {
		if (CPU_ISSET(i, &cpumask)) {
			worker = xmalloc(sizeof(*worker));
			worker->wrk_pid = 0;
			worker->wrk_reqs = 0;
			worker->wrk_cpu = i;
			worker->wrk_concurrency = concurrency_per_worker;
			if (use_threads) {
				rc = pthread_create(&worker->wrk_pthread, NULL, loop, worker);
				if (rc) {
					die(rc, "pthread_create() failed");
				}
			} else {
				rc = fork();
				if (rc == -1) {
					kill_workers(workers, worker_num);
					die(errno, "fork() failed");
				} else if (rc == 0) {
					loop(worker);
				} else {
					worker->wrk_pid = rc;
				}
			}
			workers[worker_num++] = worker;
		}
	}
	signal(SIGUSR1, sigusr1);
	assert(worker_num == worker_num_safe);
	UNUSED(worker_num_safe);
	gettimeofday(&tv, NULL);
	reqs = reqs2 = 0;
	while (!g_done) {
		to.tv_sec = 1;
		to.tv_usec = 0;
		select(0, NULL, NULL, NULL, &to);
		gettimeofday(&tv2, NULL);
		reqs2 = 0;
		for (i = 0; i < worker_num; ++i) {
			reqs2 += workers[i]->wrk_reqs;
		}
		usec = 1000000 * (tv2.tv_sec - tv.tv_sec) +  (tv2.tv_usec - tv.tv_usec);
		rps = 1000000.0 * (reqs2 - reqs) / usec;
		printf("%d\n", (int)rps);
		tv = tv2;
		reqs = reqs2;
	}
	if (!use_threads) {
		kill_workers(workers, worker_num);
	}
	if (g_lflag) {
		sys_close(pid_file_fd);
	}
	return 0;
}
