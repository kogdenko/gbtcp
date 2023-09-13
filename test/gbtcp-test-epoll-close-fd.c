// SPDX-License-Identifier: LGPL-2.1-only

#include "test.h"

int
main(int argc, char **argv)
{
	int epfd, fd;
	struct epoll_event event;

	TRACE_API((epfd = epoll_create1(0)), != -1);
	TRACE_API((fd = socket(AF_INET, SOCK_DGRAM, 0)), != -1);
	event.data.fd = fd;
	event.events = EPOLLOUT|EPOLLERR|EPOLLHUP;
	TRACE_API(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event), == 0);
	close(fd);
	TRACE_API(epoll_wait(epfd, &event, 1, 0), == 0);
	return 0;
}
