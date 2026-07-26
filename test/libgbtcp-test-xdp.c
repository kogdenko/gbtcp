// SPDX-License-Identifier: LGPL-2.1-only

#include <getopt.h>
#include <test/subr.h>
#include <kernel/dev.h>

static char *intf_name;

static void
rx_drop(struct dev *dev, void *data, int len)
{
}

static void
test_xdp_init_deinit(void **state)
{
	int i;
	struct dev dev;

	gt_socket(AF_INET, SOCK_STREAM, 0);
	memset(&dev, 0, sizeof(dev));
	for (i = 0; i < 2; ++i) {
		assert_int_equal(gt_dev_init(&dev, GT_DEV_IO_XDP, intf_name, 0,
					     rx_drop),
				 0);
		assert_int_equal(gt_dev_deinit(&dev, 0), 0);
	}
}

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_xdp_init_deinit),
	};

	test_parse_argv(argc, argv, &intf_name, NULL);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
