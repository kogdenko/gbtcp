#include "test.h"

int
main(int argc, char **argv)
{
	socket(AF_INET, SOCK_STREAM, 0);
	printf("2\n");
	epoll_create(0);
	socket(AF_INET, SOCK_STREAM, 0);
	return 0;
}
