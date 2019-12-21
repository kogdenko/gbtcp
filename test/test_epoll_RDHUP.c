#include "test.h"

int
main(int argc, char **argv)
{
	int fd, epfd;
	struct epoll_event event;

	fd = test_accept(argc, argv);
	TRACE_API((epfd = epoll_create(1)), != -1);
	event.events = EPOLLIN;
	TRACE_API(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event), == 0);
	TRACE_API(epoll_wait(epfd, &event, 1, -1), == 1);
	if (event.events == EPOLLIN) {
		return 0;
	} else {
		return 1;
	}
}
