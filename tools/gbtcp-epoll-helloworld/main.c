// SPDX-License-Identifier: LGPL-2.1-only

#include <tools/common/subr.h>
#include <tools/common/worker.h>

#define PROG_NAME "gbtcp-epoll-helloworld"

union connection {
	struct {
		uint32_t conn_fd;
		uint32_t conn_state;
	};
	uint64_t conn_u64;
};

static int g_lflag;
static struct sockaddr_in g_addr;
static int g_Cflag;
static char g_http[512];
static int g_http_len;
static __thread char g_buf[2048];

static void on_event(struct worker *, int, const union connection *, short);

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
event_queue_create(void)
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
event_queue_ctl(int eq_fd, int is_new, const union connection *cp, int write)
{
	int rc;
	struct epoll_event event;

	event.events = EPOLLRDHUP;
	event.events |= EPOLLET;
	event.events |= write ? EPOLLOUT : EPOLLIN;
	event.data.u64 = cp->conn_u64;
	rc = epoll_ctl(eq_fd, is_new ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, cp->conn_fd, &event);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		die(-rc, "epoll_ctl(%s, events=0x%x, fd=%d) failed",
			is_new ? "EPOLL_CTL_ADD" : "EPOLL_CTL_MOD", event.events, cp->conn_fd);
	}
}

static void
event_queue_wait(struct worker *worker, int eq_fd, int to_ms)
{
	int i, n;
	short revents;
	struct epoll_event *e, events[128];
	union connection conn;

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
		conn.conn_u64 = e->data.u64;
		on_event(worker, eq_fd, &conn, revents);
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
event_queue_ctl(int eq_fd, int is_new, const union connection *cp, int write)
{
	int rc;
	struct kevent e;

	e.ident = cp->conn_fd;
	e.filter = write ? EVFILT_WRITE : EVFILT_READ;
	e.flags = EV_ADD;
	e.fflags = 0;
	e.udata = (void *)(uintptr_t)cp->conn_state;
	rc = kevent(eq_fd, &e, 1, NULL, 0, NULL);
	if (rc == -1) {
		assert(errno);
		rc = -errno;
		die(-rc, "kevent(EV_ADD, EVFILT_READ, fd=%d) failed", cp->conn_fd);
	}
}

static void
event_queue_wait(struct worker *worker, int eq_fd, int to_ms)
{
	int i, n;
	short revents;
	struct timespec ts;
	union connection conn;
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
		conn.conn_fd = e->ident;
		conn.conn_state = (uintptr_t)e->udata;
		on_event(worker, eq_fd, &conn, revents);
	}
}
#endif // __linux__

#define STATE_LISTEN 33
#define STATE_SERVER 44
#define STATE_CONNECT 55
#define STATE_CLIENT 66

static void
server(int eq_fd)
{
	int fd, o;
	union connection conn;

	fd = sys_socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	o = 1;
	sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));
	sys_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &o, sizeof(o));
	sys_bind(fd, &g_addr);
	sys_listen(fd, 128);
	conn.conn_u64 = 0;
	conn.conn_fd = fd;
	conn.conn_state = STATE_LISTEN;
	event_queue_ctl(eq_fd, 1, &conn, 0);
}

static void
client(struct worker *worker, int eq_fd)
{
	int rc, fd, write;
	union connection conn;

	fd = sys_socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	conn.conn_u64 = 0;
	conn.conn_fd = fd;
	rc = sys_connect(fd, &g_addr);
	if (rc == 0) {
		rc = write_record(fd, g_http, g_http_len);
		if (rc < 0) {
			close(fd);
			return;
		}
		conn.conn_state = STATE_CLIENT;
		write = 0;
	} else {
		assert(rc == -EINPROGRESS);
		conn.conn_state = STATE_CONNECT;
		write = 1;
	}
	worker->wrk_conns++;
	event_queue_ctl(eq_fd, 1, &conn, write);
}

static void
clientn(struct worker *worker, int eq_fd)
{
	while (worker->wrk_conns < worker->wrk_concurrency) {
		client(worker, eq_fd);
	}
}

static void
on_event(struct worker *worker, int eq_fd, const union connection *cp, short revents)
{
	int rc, fin, len, listen_fd, closed;
	union connection new_conn;

	switch (cp->conn_state) {
	case STATE_LISTEN:
		listen_fd = cp->conn_fd;
		while (1) {
			rc = sys_accept4(listen_fd, SOCK_NONBLOCK);
			if (rc < 0) {
				break;
			}
			new_conn.conn_fd = rc;
			new_conn.conn_state = STATE_SERVER;
			event_queue_ctl(eq_fd, 1, &new_conn, 0);
			worker->wrk_conns++;
		}
		break;

	case STATE_SERVER:
		fin = 0;
		len = 0;
		assert(revents & (POLLIN|POLLERR));
		if (revents & POLLIN) {
			rc = read_record(cp->conn_fd, g_buf, sizeof(g_buf), &len);
			if (rc <= 0) {
				fin = 1;
			}
			if (len > 0) {
				rc = write_record(cp->conn_fd, g_http, g_http_len);
				if (rc < 0) {
					fin = 1;
				}
			}
		}
		if (revents & POLLERR) {
			fin = 1;
		}
		if (g_Cflag || fin) {
			close(cp->conn_fd);
			worker->wrk_reqs++;
			worker->wrk_conns--;
		}
		break;

	case STATE_CONNECT:
		if (revents & POLLERR) {
			connect_failed(0, &g_addr);
			break;
		}
		rc = write_record(cp->conn_fd, g_http, g_http_len);
		if (rc < 0) {
			close(cp->conn_fd);
			worker->wrk_reqs++;
			worker->wrk_conns--;
			clientn(worker, eq_fd);
		} else {
			new_conn = *cp;
			new_conn.conn_state = STATE_CLIENT;
			event_queue_ctl(eq_fd, 0, &new_conn, 0);
		}
		break;

	case STATE_CLIENT:
		closed = 0;
		if (revents & POLLERR) {
			closed = 1;
		} else {
			rc = read_record(cp->conn_fd, g_buf, sizeof(g_buf), &len);
			if (rc <= 0) {
				closed = 1;
			}
		}
		if (g_Cflag || closed) {
			close(cp->conn_fd);
			worker->wrk_reqs++;
			worker->wrk_conns--;
			clientn(worker, eq_fd);
		}
		break;

	default:
		assert(0);
	}
}

static void *
worker_loop(void *udata)
{
	int eq_fd;
	struct worker *worker;

	worker = udata;
	eq_fd = event_queue_create();
	if (g_lflag) {
		server(eq_fd);
	} else {
		clientn(worker, eq_fd);
	}
	for (;;) {
		event_queue_wait(worker, eq_fd, -1);
	}
	return NULL;
}

static void
usage(void)
{
	printf(
		"Usage: %s [options] {-a cpus} -l [address]\n"
		"       %s [options] {-a cpus} {address}\n"
		"\n"
		"\tOptions:\n"
		"\t-h              Print this help\n"
		"\t-v              Show version\n"
		"\t-p port         Port number (default: 80)\n"
		"\t-l              Listen incoming connections\n"
		"\t-c concurrency  Number of parallel connections (default: 1)\n"
		"\t-C              Close connection after data transmit\n"
		"\t-a cpus         Workers cpu affinity\n"
		"\t-t              Use threads to start workers (instead of processes)\n"
		"\t-S              Send stop signal to master process\n",
		PROG_NAME, PROG_NAME
	);
}

int
main(int argc, char **argv)
{
	int rc, opt, nflag, tflag, port;
	int concurrency;
	char hostname[32];
	cpuset_t worker_cpus;

	tflag = 0;
	CPU_ZERO(&worker_cpus);
	concurrency = 0;
	assert(sizeof(union connection) == sizeof(uint64_t));
	nflag = 0;
	port = 80;
	while ((opt = getopt(argc, argv, "hvp:lc:n:Ca:t")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'v':
			printf("version: 0.5.1\n");
			return 0;
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
		case 'n':
			nflag = strtoul(optarg, NULL, 10);
			break;
		case 'C':
			g_Cflag = 1;
			break;
		case 'a':
			rc = cpuset_from_string(&worker_cpus, optarg);
			if (rc < 0) {
				die(-rc, "-a: Invalid cpu list");
			}
			break;
		case 't':
			tflag = 1;
			break;
		default:
			usage();
			return EXIT_FAILURE;
		}
	}
	if (nflag == 0) {
		nflag = INT_MAX;
	}
	g_addr.sin_family = AF_INET;
	g_addr.sin_port = htons(port);
	g_addr.sin_addr.s_addr = INADDR_ANY;
	if (g_lflag) {
		g_http_len = snprintf(g_http, sizeof(g_http),
			"HTTP/1.0 200 OK\r\n"
			"Server: %s\r\n"
			"Content-Type: text/html\r\n"
			"Connection: close\r\n"
			"Hi\r\n\r\n",
			PROG_NAME);
	} else {
		rc = gethostname(hostname, sizeof(hostname));
		if (rc) {
			die(errno, "gethostname() failed");
		}
		g_http_len = snprintf(g_http, sizeof(g_http),
			"GET / HTTP/1.0\r\n"
		        "Host: %s\r\n"
		        "User-Agent: %s\r\n"
		        "\r\n",
			hostname, PROG_NAME);
	}
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
	start_master(&worker_cpus,
		concurrency,
		PROG_NAME,
		g_lflag ? port : 0,
		nflag,
		worker_loop,
		tflag ? NULL : fork,
		sleep);
	return 0;
}
