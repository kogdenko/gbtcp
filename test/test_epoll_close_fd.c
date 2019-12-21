#include "test.h"

int
main(int argc, char **argv)
{
	int epfd, fd, rc;
	struct epoll_event event;

	epfd = epoll_create1(0);
	ASSERT(errno, epfd != -1);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ASSERT(errno, fd != -1);
	event.data.fd = fd;
	event.events = EPOLLOUT|EPOLLERR|EPOLLHUP;
	rc = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
	ASSERT(errno, rc == 0);
	close(fd);
	rc = epoll_wait(epfd, &event, 1, 0);
//	printf("%d\n", rc);
	ASSERT(0, rc == 0);
	return 0;
}
