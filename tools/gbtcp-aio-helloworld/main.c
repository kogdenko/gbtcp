#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <gbtcp/gbtcp.h>

#ifdef GTL_HAVE_XDP
#define HAVE_XDP " GTL_HAVE_XDP"
#else // GTL_HAVE_XDP
#define HAVE_XDP ""
#endif // GTL_HAVE_XDP

#ifdef GTL_HAVE_NETMAP
#define HAVE_NETMAP " GTL_HAVE_NETMAP"
#else // GTL_HAVE_NETMAP
#define HAVE_NETMAP ""
#endif // GTL_HAVE_NETMAP

#ifdef GTL_HAVE_VALE
#define HAVE_VALE " GTL_HAVE_VALE"
#else // GTL_HAVE_VAL
#define HAVE_VALE ""
#endif // GTL_HAVE_VALE

static int http_len;
static const char *http =
	"HTTP/1.0 200 OK\r\n"
	"Server: gbtcp-aio-helloworld\r\n"
	"Content-Type: text/html\r\n"
	"Connection: close\r\n"
	"Hi\r\n\r\n";

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
		gtl_set_affinity(affinity);
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
	while ((opt = getopt(argc, argv, "a:P:V")) != -1) {
		switch (opt) {
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		case 'P':
			n_workers = strtoul(optarg, NULL, 10);
			break;
		case 'V':
			printf("version: 0.2.1\n");
			printf("commit: %s\n", GTL_COMMIT);
			printf("config:%s%s%s\n", HAVE_XDP, HAVE_NETMAP, HAVE_VALE);
			return 0;
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
