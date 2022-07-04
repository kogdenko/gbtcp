#include <getopt.h>
#include <test/test.h>
#include <gbtcp/dev.h>

#ifdef GTL_HAVE_XDP
static void
rx_drop(struct dev *dev, void *data, int len)
{
}

int
main(int argc, char **argv)
{
	int i, opt;
	const char *ifname;
	struct dev dev;

	ifname = NULL;
	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		}
	}
	if (ifname == NULL) {
		die(0, "'-i' not specified");
	}
	gt_socket(AF_INET, SOCK_STREAM, 0);
	memset(&dev, 0, sizeof(dev));
	for (i = 0; i < 2; ++i) {
		TRACE_API(dev_init(&dev, DEV_TRANSPORT_XDP, ifname, 0, rx_drop), == 0);
		TRACE_API(dev_deinit(&dev, false), == 0);
	}
	return EXIT_SUCCESS;
}
#else // GTL_HAVE_XDP
int
main(int argc, char **argv)
{
	return EXIT_SUCCESS;
}
#endif // GTL_HAVE_XDP