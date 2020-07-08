// gpl2
// bench_gbtcp
#include <gbtcp/internals.h>

#define CURMOD app

static int http_len;
static const char *http =
	"HTTP/1.0 200 OK\r\n"
	"Server: so_echo\r\n"
	"Content-Type: text/html\r\n"
	"Connection: close\r\n"
	"Hi\r\n\r\n";

#if 0
static void
on_read(void *aio, int fd, short revents)
{
	int rc;
	struct sock *so;
	struct iovec iov;

	so = container_of(aio, struct sock, so_file.fl_aio);
	if (revents & POLLIN) {
		rc = so_aio_recvfrom(so, &iov, 0, NULL, NULL);
		if (rc > 0) {
			so_recvdrain(so, rc);
			iov.iov_base = (char *)http;
			iov.iov_len = http_len;
			so_sendto(so, &iov, 1, 0, 0, 0);
			so_close(so);
			return;
		}
	}
	if (revents & (POLLERR|POLLHUP)) {
		so_close(so);
	}
}

struct sock *lso;

static void
on_accept(void *aio, int fd, short revents)
{
	int rc;
	struct sock *so;

	while (1) {
		rc = so_accept(&so, lso, NULL, NULL, SOCK_NONBLOCK);
		if (rc < 0) {
			break;
		}
		file_aio_add(&so->so_file, &so->so_file.fl_aio, on_read);
	}
}

static void
loop(struct sockaddr_in *a, int affinity)
{
	int rc;
	struct file_aio aio;

	if (affinity >= 0) {
		set_affinity(affinity);
	}
	rc = service_attach("111");
	if (rc) {
		die(-rc, "service_attach() failed");
	}
	SERVICE_LOCK;
	rc = so_socket(&lso, AF_INET, SOCK_STREAM, SOCK_NONBLOCK, 0);
	if (rc < 0) {
		die(-rc, "socket() failed");
	}
	rc = so_bind(lso, a);
	if (rc < 0) {
		die(-rc, "bind() failed");
	}
	rc = so_listen(lso, 0);
	if (rc < 0) {
		die(-rc, "listen() failed");
	}
	file_aio_init(&aio);
	file_aio_add(&lso->so_file, &aio, on_accept);
	while (1) {
		wait_for_fd_events();
	}
	SERVICE_UNLOCK;
}

int
main(int argc, char **argv)
{
	int i, rc, opt, nprocs, affinity;
	struct sockaddr_in a;

	nprocs = 1;
	affinity = -1;
	while ((opt = getopt(argc, argv, "a:P:")) != -1) {
		switch (opt) {
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		case 'P':
			nprocs = strtoul(optarg, NULL, 10);
			break;
		}
	}
	http_len = strlen(http);
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = 0;
	a.sin_port = htons(80);
	if (nprocs < 1) {
		nprocs = 1;
	}
	gt_init(NULL, LOG_NOTICE);
	gt_preload_passthru = 1;
	for (i = 1; i < nprocs; ++i) {
		rc = sys_fork();
		if (rc == 0) {
			loop(&a, affinity == -1 ? affinity : affinity + i);
		}
	}
	loop(&a, affinity);
	return 0;
}
#else


static void
read_handler(void *unused, int fd, short revents)
{
	int rc;
	struct iovec iov;

	if (revents & POLLIN) {
		rc = gt_aio_recvfrom(fd, &iov, 0, NULL, NULL);
		if (rc > 0) {
			gt_recvdrain(fd, rc);
			iov.iov_base = (char *)http;
			iov.iov_len = http_len;
			gt_send(fd, http, http_len, MSG_NOSIGNAL);
			gt_close(fd);
			return;
		}
	}
	if (revents & (POLLERR|POLLHUP)) {
		gt_close(fd);
	}
}

static void
accept_handler(void *unused, int fd, short revents)
{
	int rc, new_fd;

	rc = gt_accept4(fd, NULL, NULL, 0);
	if (rc > 0) {
		new_fd = rc;
		gt_aio_set(new_fd, read_handler);
	}
}

static void
loop(int fd, int affinity)
{
	if (affinity >= 0) {
		set_affinity(affinity);
	}
	gt_aio_set(fd, accept_handler);
	gt_poll(NULL, 0, -1);
}

int
main(int argc, char **argv)
{
	int i, rc, fd, opt, n_workers, affinity;
	struct sockaddr_in a;

	//signal(SIGPIPE, SIG_IGN);
	n_workers = 1;
	affinity = -1;
	while ((opt = getopt(argc, argv, "a:P:")) != -1) {
		switch (opt) {
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		case 'P':
			n_workers = strtoul(optarg, NULL, 10);
			break;
		}
	}
	http_len = strlen(http);
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = 0;
	a.sin_port = htons(80);
	if (n_workers < 1) {
		n_workers = 1;
	}
	gt_preload_passthru = 1;
	rc = gt_socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (rc < 0) {
		return 1;
	}
	fd = rc;
	rc = gt_bind(fd, (struct sockaddr *)&a, sizeof(a));
	if (rc < 0) {
		return 2;
	}
	rc = gt_listen(fd, 0);
	if (rc < 0) {
		return 3;
	}
	for (i = 1; i < n_workers; ++i) {
		rc = gt_fork();
		if (rc == 0) {
			loop(fd, affinity == -1 ? affinity : affinity + i);
		}
	}
	loop(fd, affinity);
	return 0;
}
#endif
