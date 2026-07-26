// SPDX-License-Identifier: LGPL-2.1-only

#include <kernel/dev.h>
#include <kernel/inet.h>
#include <kernel/fd_event.h>
#include <test/subr.h>

static char *intf_name;
static char *peer_name;
static int n_rx;

static void
rx(struct dev *dev, void *data, int len)
{
	assert_int_equal(len, 70);
	n_rx++;
}

static void
test_dev(const char *intf, const char *peer, u8 io)
{
	int i, j, n_tx, n_q;
	struct eth_hdr *eh;
	struct dev *rxdev, *txdev;
	struct dev_pkt pkt;

	n_rx = 0;
	n_q = 1;
	rxdev = xmalloc(n_q * sizeof(struct dev));
	txdev = xmalloc(n_q * sizeof(struct dev));

	for (i = 0; i < n_q; ++i) {
		assert_int_equal(gt_dev_init(rxdev + i, io, intf, i, rx), 0);
		assert_int_equal(gt_dev_init(txdev + i, io, peer, i, rx), 0);
	}

	n_tx = 0;
	for (i = 0; i < n_q; ++i) {
		for (j = 0; j < 10; ++j) {
			assert_int_equal(dev_get_tx_packet(txdev + i, &pkt), 0);
			eh = (struct eth_hdr *)pkt.pkt_data;
			eh->eh_type = ETH_TYPE_ARP_BE;
			pkt.pkt_len = 70;
			dev_transmit(&pkt);
			n_tx++;
		}
	}

	for (i = 0; i < 2000 && n_rx < n_tx; ++i) {
		wait_for_fd_events2(1, GT_NSEC_PER_MSEC);
	}

	assert_int_equal(n_tx, n_rx);
}

#if GT_HAVE_NETMAP
static void
test_dev_netmap(void **state)
{
	test_dev(intf_name, peer_name, GT_DEV_IO_NETMAP);
}
#endif

#if GT_HAVE_XDP
static void
test_dev_xdp(void **state)
{
	test_dev(intf_name, peer_name, GT_DEV_IO_XDP);
}
#endif

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
#if GT_HAVE_NETMAP
		cmocka_unit_test(test_dev_netmap),
#endif
#if GT_HAVE_XDP
		cmocka_unit_test(test_dev_xdp),
#endif
	};

	test_parse_argv(argc, argv, &intf_name, &peer_name);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
