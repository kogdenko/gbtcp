// SPDX-License-Identifier: LGPL-2.1-only

#include "subr.h"

static void
test_epoll_close_fd(void **state)
{
	int epfd, fd;
	struct epoll_event event;

	epfd = epoll_create1(0);
	assert_return_code(epfd, errno);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert_return_code(fd, errno);
	event.data.fd = fd;
	event.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
	assert_return_code(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event), errno);
	close(fd);
	// A closed fd must be removed from the epoll set automatically
	assert_int_equal(epoll_wait(epfd, &event, 1, 0), 0);
}

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_epoll_close_fd),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
