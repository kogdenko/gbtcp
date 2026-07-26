// SPDX-License-Identifier: LGPL-2.1-only

#include "subr.h"

static void
test_epoll_create(void **state)
{
	assert_return_code(socket(AF_INET, SOCK_STREAM, 0), errno);
	// Exercise the preload epoll_create() path; the return value is
	// intentionally ignored (size 0 is invalid on native Linux epoll).
	epoll_create(0);
	assert_return_code(socket(AF_INET, SOCK_STREAM, 0), errno);
}

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_epoll_create),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
