// GPL v2
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>
#ifdef __linux__
#include <sys/epoll.h>
#else
#include <pthread_np.h>
#include <sys/event.h>
typedef cpuset_t cpu_set_t;
#endif

#define N_WORKERS_MAX 32

union my_data {
	struct {
		uint32_t fd;
		uint32_t state;
	};
	uint64_t u64;
};

static char req_GET[] =
	"GET / HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: epoll_helloworld\r\n"
        "\r\n";

static char rpl_200OK[] = 
	"HTTP/1.0 200 OK\r\n"
	"Server: epoll_helloworld\r\n"
	"Content-Type: text/html\r\n"
	"Connection: close\r\n"
	"Hi\r\n"
	"\r\n";

static __thread int worker_id;
static __thread int conns;

static void *counters;
static struct sockaddr_in conf_addr;
static int worker_eq_fd;
static int n_workers;
static int affinity = -1;
static int concurrency = 1;
static int Lflag;
static int Cflag;

#define CACHE_LINE_SIZE 64

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define STRSZ(s) s, sizeof(s) - 1

#define dbg(fmt, ...) do { \
	printf("%-20s %-5d %-20s: ", __FILE__, __LINE__, __func__); \
	printf(fmt, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)

static void on_event(int eq_fd, union my_data *data, short revents);

static void
log_errf(int e, const char *format, ...)
{
	va_list ap;

	fprintf(stderr, "%d: ", getpid());
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (e) {
		fprintf(stderr, " (%s)\n", strerror(e));
	} else {
		fprintf(stderr, "\n");
	}
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
		rc = -errno;
		log_errf(-rc, "socket(domain=0x%x, type=0x%x) failed",
			domain, type);
	}
	return rc;
}

static void
log_connect_failed(int err, struct sockaddr_in *addr)
{
	log_errf(err, "connect(%s:%hu) failed",
		inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
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
			log_connect_failed(errno, addr);
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
		rc = -errno;
		log_errf(-rc, "listen(fd=%d, backlog=%d) failed", fd, backlog);
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
		rc = -errno;
		log_errf(-rc, "bind(fd=%d, addr=%s, port=%hu) failed",
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
			log_errf(-rc, "accept4(fd=%d, flags=0x%x) failed",
				fd, flags);
		}
	}
	return rc;
}

static int
sys_setsockopt(int fd, int level, int optname,
               const void *optval, socklen_t optlen)
{
	int rc;

	rc = setsockopt(fd, level, optname, optval, optlen);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		log_errf(-rc, "setsockopt(fd=%d, level=%d, optname=%d) failed",
			fd, level, optname);
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
		log_errf(-rc, "epoll_create1() failed");
	}
	return rc;
}

static void
event_queue_ctl(int eq_fd, int is_new, union my_data *data, int write)
{
	int rc;
	struct epoll_event event;

	event.events = EPOLLRDHUP;
	event.events |= EPOLLET;
	event.events |= write ? EPOLLOUT : EPOLLIN;
	event.data.u64 = data->u64;
	rc = epoll_ctl(eq_fd,
	               is_new ? EPOLL_CTL_ADD : EPOLL_CTL_MOD,
	               data->fd, &event);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		log_errf(-rc, "epoll_ctl(%s, events=0x%x, fd=%d) failed",
		         is_new ? "EPOLL_CTL_ADD" : "EPOLL_CTL_MOD",
		         event.events, data->fd);
		exit(1);
	}
}

static void
event_queue_wait(int eq_fd, int to_ms)
{
	int i, n;
	short revents;
	struct epoll_event *e, events[128];

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
		on_event(eq_fd, (union my_data *)&e->data, revents);
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
		log_errf(-rc, "kqueue() failed");
	}
	return rc;
}

static void
event_queue_ctl(int eq_fd, int is_new, union my_data *data, int write)
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
		log_errf(-rc, "kevent(EV_ADD, EVFILT_READ, fd=%d) failed",
		         data->fd);
		exit(1);
	}
}

static void
event_queue_wait(int eq_fd, int to_ms)
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
		on_event(eq_fd, &data, revents);
	}
}
#endif // __linux__

static ssize_t
write_all(int fd, const void *buf, size_t cnt)
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
read_all(int fd, int *len)
{
	int rc;
	char buf[2048];

	*len = 0;
	while (1) {
		rc = read(fd, buf, sizeof(buf));
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
			if (rc < sizeof(buf)) {
				break;
			}
		}
	}
	return 1;
}

static uint64_t *
get_requests(int id)
{
	return (uint64_t *)((u_char *)counters + id * CACHE_LINE_SIZE);

}

static void
inc_requests()
{
	(*get_requests(worker_id))++;
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
	rc = sys_bind(fd, &conf_addr);
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
client(int eq_fd)
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
	rc = sys_connect(fd, &conf_addr);
	if (rc == 0) {
		rc = write_all(fd, STRSZ(req_GET));
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
	conns++;
	event_queue_ctl(eq_fd, 1, &data, write);
	return 0;
err:
	sys_close(fd);
	return rc;
}

static int
clientn(int eq_fd)
{
	int rc;

	while (conns < concurrency) {
		rc = client(eq_fd);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

static void
on_event(int eq_fd, union my_data *data, short revents)
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
			conns++;
		}
		break;
	case STATE_SERVER:
		fin = 0;
		len = 0;
		assert(revents & (POLLIN|POLLERR));
		if (revents & POLLIN) {
			rc = read_all(data->fd, &len);
			if (rc <= 0) {
				fin = 1;
			}
			if (len > 0) {
				rc = write_all(data->fd, STRSZ(rpl_200OK));
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
			inc_requests();
			conns--;
		}
		break;
	case STATE_CONNECT:
		if (revents & POLLERR) {
			log_connect_failed(0, &conf_addr);
			break;
		}
		rc = write_all(data->fd, STRSZ(req_GET));
		if (rc < 0) {
			sys_close(data->fd);
			inc_requests();
			conns--;
			clientn(eq_fd);
		} else {
			data->state = STATE_CLIENT;
			event_queue_ctl(eq_fd, 0, data, 0);
		}
		break;
	case STATE_CLIENT:
		closed = 0;
		if (revents & POLLERR) {
			closed = 1;
		} else {
			rc = read_all(data->fd, &len);
			if (rc <= 0) {
				closed = 1;
			}
		}
		if (Cflag || closed) {
			sys_close(data->fd);
			inc_requests();
			conns--;
			clientn(eq_fd);
		}
		break;
	default:
		assert(0);
	}
}

static int
set_affinity(int cpu_id)
{
	int rc;
	cpu_set_t cpumask;

	CPU_ZERO(&cpumask);
	CPU_SET(cpu_id, &cpumask);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(cpumask), &cpumask);
	if (rc != 0) {
		log_errf(rc, "pthread_setaffinity_np(%d) failed", cpu_id);
	}
	return -rc;
}

static struct timeval tv, tv2;
static unsigned long long requests;

static void
sighandler(int signum)
{
	int i;
	double rps;
	suseconds_t usec;
	unsigned long long requests2;

	gettimeofday(&tv2, NULL);
	usec = 1000000 * (tv2.tv_sec - tv.tv_sec) + 
		(tv2.tv_usec - tv.tv_usec);
	requests2 = 0;
	for (i = 0; i < n_workers; ++i) {
		requests2 += *get_requests(i);
	}
	rps = 1000000.0 * (requests2 - requests) / usec;
	printf("%d: rps=%d\n", (int)getpid(), (int)rps);
	tv = tv2;
	requests = requests2;
	alarm(1);
}

static void
worker_loop(int idx)
{
	int rc;

	if (affinity != -1) {
		set_affinity(affinity + idx);
	}
	worker_id = idx;;
	if (Lflag) {
		rc = server(worker_eq_fd);
	} else {
		rc = clientn(worker_eq_fd);
	}
	if (rc < 0) {
		sys_close(worker_eq_fd);
		return;
	}
	while (1) {
		event_queue_wait(worker_eq_fd, -1);
	}
}

static void *
worker_routine(void *arg)
{
	worker_loop((uintptr_t)arg);
	return NULL;
}

static void
usage(const char *comm)
{
	printf(
	"Usage: %s [address]\n"
	"\n"
	"\tOptions:\n"
	"\t-h              Print this help\n"
	"\t-p port         Port number (default: 80)\n"
	"\t-L              Listen incoming connections\n"
	"\t-c concurrency  Number of parallel connections (default: 1)\n"
	"\t-C              Close connection after data transmit\n"
	"\t-w n            Number of worker\n"
	"\t-F              Fork worker instead of create thread\n"
	"\t-a cpu          Affinity of first worker\n",
	comm);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	int i, rc, opt, Fflag;
	pthread_t t;

	Fflag = 0;
	assert(sizeof(union my_data) == sizeof(uint64_t));
	conf_addr.sin_family = AF_INET;
	conf_addr.sin_port = htons(80);
	conf_addr.sin_addr.s_addr = INADDR_ANY;
	while ((opt = getopt(argc, argv, "hp:Lc:Cw:Fa:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'p':
			conf_addr.sin_port = htons(strtoul(optarg, NULL, 10));
			break;
		case 'L':
			Lflag = 1;
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
		case 'w':
			n_workers = strtoul(optarg, NULL, 10);
			break;
		case 'F':
			Fflag = 1;
			break;
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		}
	}
	if (optind < argc) {
		rc = inet_aton(argv[optind], &conf_addr.sin_addr);
		if (rc != 1) {
			log_errf(0, "Invalid address '%s'", argv[optind]);
			return 1;
		}
	} else {
		if (Lflag == 0) {
			log_errf(0, "Address or '-L' flag must be specified");
			return 2;
		}
	}
	if (n_workers < 1) {
		n_workers = 1;
	} else if (n_workers > N_WORKERS_MAX) {
		n_workers = N_WORKERS_MAX;
	}
	counters = mmap(NULL, n_workers * CACHE_LINE_SIZE,
		PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (counters == MAP_FAILED) {
		log_errf(errno, "mmap() failed");
		return 3;
	}
	rc = event_queue_create();
	if (rc < 0) {
		return 4;
	}
	worker_eq_fd = rc;
	printf("%s %s:%hu\n", Lflag ? "Listening on" : "Connecting to",
		inet_ntoa(conf_addr.sin_addr), ntohs(conf_addr.sin_port));	
	for (i = 1; i < n_workers; ++i) {
		if (Fflag) {
			rc = fork();
			if (rc == 0) {
				worker_loop(i);
			} else if (rc == -1) {
				log_errf(errno, "fork() failed");
			}
		} else {
			rc = pthread_create(&t, NULL, worker_routine,
				(void*)(uintptr_t)i);
			if (rc) {
				log_errf(rc, "pthread_create() failed");
			}
		}
	}
	gettimeofday(&tv, NULL);
	signal(SIGALRM, sighandler);
	alarm(1);
	worker_loop(0);
	return 0;
}
