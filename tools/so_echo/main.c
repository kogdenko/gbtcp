#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
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

#define PROCS_MAX 32

union my_data {
	struct {
		uint32_t fd;
		uint32_t state;
	};
	uint64_t u64;
};

static int dflag;
static int lflag;
static int proc_idx;
static char reqbuf[] =
	"GET / HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: so_echo\r\n"
        "\r\n";
static char rcvbuf[65536];
static struct sockaddr_in conf_addr;
static unsigned long long requests2;
static int concurrency = 1;
static int conns;
static int Cflag;

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define dbg(fmt, ...) do { \
	printf("%-20s %-5d %-20s: ", __FILE__, __LINE__, __func__); \
	printf(fmt, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)

static int on_event(int eq_fd, union my_data *data, short revents);

static void
E(int e, const char *format, ...)
{
	va_list ap;

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
		E(-rc, "socket(domain=0x%x, type=0x%x) failed", domain, type);
	}
	return rc;
}

static void
log_connect_failed(int err, struct sockaddr_in *addr)
{
	E(err, "connect(%s:%hu) failed",
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
		E(-rc, "listen(fd=%d, backlog=%d) failed", fd, backlog);
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
		E(-rc, "bind(fd=%d, addr=%s, port=%hu) failed",
		  fd, inet_ntoa(addr->sin_addr),
		  ntohs(addr->sin_port));
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
			E(-rc, "accept4(fd=%d, flags=0x%x) failed", fd, flags);
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
		E(-rc, "setsockopt(fd=%d, level=%d, optname=%d) failed",
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
		E(-rc, "epoll_create1() failed");
	}
	return rc;
}
#else
static int
event_queue_create()
{
	int rc;

	rc = kqueue();
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		E(-rc, "kqueue() failed");
	}
	return rc;
}
#endif

#ifdef __linux__
static void
event_queue_ctl(int eq_fd, int is_new, union my_data *data, int write)
{
	int rc;
	struct epoll_event event;

	event.events = EPOLLET|EPOLLRDHUP;
	event.events |= write ? EPOLLOUT : EPOLLIN;
	event.data.u64 = data->u64;
	rc = epoll_ctl(eq_fd,
	               is_new ? EPOLL_CTL_ADD : EPOLL_CTL_MOD,
	               data->fd, &event);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		E(-rc, "epoll_ctl(%s, events=0x%x, fd=%d) failed",
		  is_new ? "EPOLL_CTL_ADD" : "EPOLL_CTL_MOD",
		  event.events, data->fd);
		exit(1);
	}
}
#else /* __linux__ */
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
		E(-rc, "kevent(EV_ADD, EVFILT_READ, fd=%d) failed", data->fd);
		exit(1);
	}
}
#endif

#ifdef __linux__
static int
event_queue_wait(int eq_fd, int to_ms)
{
	int i, n, rc;
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
		if (!revents) {
			printf("! %x\n", e->events);
		}
		assert(revents);
		rc = on_event(eq_fd, (union my_data *)&e->data, revents);
		if (rc) {
			return rc;
		}
	}
	return 0;
}
#else /* __linux__ */
static void
event_queue_wait(int eq_fd, int to_ms)
{
	int i, n, rc;
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
		rc = on_event(eq_fd, &data, revents);
		if (rc) {
			return rc;
		}
	}
	return 0;
}
#endif /* __linux__ */

static ssize_t
write_all(int fd, const void *buf, size_t cnt)
{
	ssize_t rc;
	size_t off;

	for (off = 0; off < cnt; off += rc) {
		rc = write(fd, (const uint8_t *)buf + off, cnt - off);
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
read_all(int fd, void *buf, int cnt, int *len)
{
	int rc, n;

	*len = 0;
	while (*len < cnt) {
		n = cnt - *len;
		rc = read(fd, (uint8_t *)buf + *len, n);
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
		rc = write_all(fd, reqbuf, sizeof(reqbuf) - 1);
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

static int
on_event(int eq_fd, union my_data *data, short revents)
{
	int rc, len, listen_fd, closed;
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
		rc = 0;
		len = 0;
		assert(revents & (POLLIN|POLLERR));
		if (revents & POLLIN) {
			rc = read_all(data->fd, rcvbuf, sizeof(rcvbuf), &len);
			if (len > 0) {
				rc = write_all(data->fd, rcvbuf, len);
			}
		}
		if (revents & POLLERR) {
			rc = -ECONNRESET;
		}
		if (Cflag || rc <= 0) {
			sys_close(data->fd);
			requests2++;
			conns--;
		}
		break;
	case STATE_CONNECT:
		if (revents & POLLERR) {
			log_connect_failed(0, &conf_addr);
			return -ECONNRESET;
		}
		rc = write_all(data->fd, reqbuf, sizeof(reqbuf) - 1);
		if (rc < 0) {
			sys_close(data->fd);
			requests2++;
			conns--;
			rc = clientn(eq_fd);
			if (rc) {
				return rc;
			}
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
			rc = read_all(data->fd, rcvbuf, sizeof(rcvbuf), &len);
			if (rc <= 0) {
				closed = 1;
			}
		}
		if (Cflag || closed) {
			sys_close(data->fd);
			requests2++;
			conns--;
			rc = clientn(eq_fd);
			if (rc) {
				return rc;
			}
		}
		break;
	}
	return 0;
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
		E(rc, "pthread_setaffinity_np(%d) failed", cpu_id);
	}
	return -rc;
}

static void
loop(int idx, int affinity)
{
	int rc, eq_fd, to_ms;
	unsigned long long requests;
	double rps;
	suseconds_t usec;
	struct timeval tv, tv2;

	if (affinity != -1) {
		set_affinity(affinity + idx);
	}
	proc_idx = idx;
	printf("loop %d\n", idx);
	rc = event_queue_create();
	if (rc < 0) {
		return;
	}
	eq_fd = rc;
	if (lflag) {
		rc = server(eq_fd);
	} else {
		rc = clientn(eq_fd);
	}
	if (rc < 0) {
		sys_close(eq_fd);
		return;
	}
	requests = 0;
	to_ms = dflag ? -1 : 200;
	gettimeofday(&tv, NULL);
	do {
		gettimeofday(&tv2, NULL);
		usec = 1000000 * (tv2.tv_sec - tv.tv_sec) + 
			(tv2.tv_usec - tv.tv_usec);
		if (usec >= 1000000) {
			rps = 1000000.0 * (requests2 - requests) / usec;
			printf("%d: rps=%d\n", (int)getpid(), (int)rps);
			tv = tv2;
			requests = requests2;
		}
		rc = event_queue_wait(eq_fd, to_ms);
	} while (rc == 0);
}

static void
usage()
{
	printf(
	"Usage: so_echo [address]\n"
	"\n"
	"\tOptions:\n"
	"\t-h              Print this help\n"
	"\t-d              Debugging mode\n"
	"\t-p port         Port number (default: 80)\n"
	"\t-l              Listen incoming connections\n"
	"\t-c concurrency  Number of parallel connections (default: 1)\n"
	"\t-C              Close connection after data transmit\n"
	"\t-P n            Number of processes\n"
	"\t-a cpu          Affinity of first process\n"
	);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	int i, rc, opt, nr_procs, affinity;

	nr_procs = 1;
	affinity = -1;
	assert(sizeof(union my_data) == sizeof(uint64_t));
	conf_addr.sin_family = AF_INET;
	conf_addr.sin_port = htons(80);
	conf_addr.sin_addr.s_addr = INADDR_ANY;
	while ((opt = getopt(argc, argv, "hdp:lc:CP:a:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			break;
		case 'd':
			dflag = 1;
			break;
		case 'p':
			conf_addr.sin_port = htons(strtoul(optarg, NULL, 10));
			break;
		case 'l':
			lflag = 1;
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
		case 'P':
			nr_procs = strtoul(optarg, NULL, 10);
			break;
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		}
	}
	if (nr_procs < 1) {
		nr_procs = 1;
	} else if (nr_procs >= PROCS_MAX) {
		nr_procs = PROCS_MAX;
	}
	if (optind < argc) {
		rc = inet_aton(argv[optind], &conf_addr.sin_addr);
		if (rc != 1) {
			E(0, "Invalid address '%s'", argv[optind]);
			return 1;
		}
	} else {
		if (lflag == 0) {
			E(0, "Address or '-l' flag must be specified");
			return 2;
		}
	}
	printf("%s %s:%hu\n", lflag ? "Listening on" : "Connecting to",
	       inet_ntoa(conf_addr.sin_addr),
	       ntohs(conf_addr.sin_port));
	for (i = 1; i < nr_procs; ++i) {
		printf("fork\n");
		rc = fork();
		printf("fork ret %d\n", rc);
		if (rc == 0) {
			loop(i, affinity);
		}
	}
	loop(0, affinity);
	return 0;
}
