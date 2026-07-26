// SPDX-License-Identifier: LGPL-2.1-only

#include "subr.h"

static void
test_epoll_RDHUP(void **state)
{
	int fd, epfd;
	struct epoll_event event;

	fd = test_accept();
	epfd = epoll_create(1);
	assert_return_code(epfd, errno);
	event.events = EPOLLIN;
	assert_return_code(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event), errno);
	assert_int_equal(epoll_wait(epfd, &event, 1, -1), 1);
	assert_int_equal(event.events, EPOLLIN);
}

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_epoll_RDHUP),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
