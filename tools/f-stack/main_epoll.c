#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <sched.h>

#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"


#define MAX_EVENTS 512

struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];

int epfd;
int sockfd;

#if 1
char html[] = 
"HTTP/1.1 200 OK\r\n"
"Server: F-Stack\r\n"
"Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
"Content-Type: text/html\r\n"
"Hello world!!!\r\n\r\n";
#else
char html[] = 
"HTTP/1.1 200 OK\r\n"
"Server: F-Stack\r\n"
"Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
"Content-Type: text/html\r\n"
"Content-Length: 438\r\n"
"Last-Modified: Tue, 21 Feb 2017 09:44:03 GMT\r\n"
"Connection: keep-alive\r\n"
"Accept-Ranges: bytes\r\n"
"\r\n"
"<!DOCTYPE html>\r\n"
"<html>\r\n"
"<head>\r\n"
"<title>Welcome to F-Stack!</title>\r\n"
"<style>\r\n"
"    body {  \r\n"
"        width: 35em;\r\n"
"        margin: 0 auto; \r\n"
"        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n"
"    }\r\n"
"</style>\r\n"
"</head>\r\n"
"<body>\r\n"
"<h1>Welcome to F-Stack!</h1>\r\n"
"\r\n"
"<p>For online documentation and support please refer to\r\n"
"<a href=\"http://F-Stack.org/\">F-Stack.org</a>.<br/>\r\n"
"\r\n"
"<p><em>Thank you for using F-Stack.</em></p>\r\n"
"</body>\r\n"
"</html>";
#endif

int loop(void *arg)
{
    /* Wait for events to happen */

    int nevents = ff_epoll_wait(epfd,  events, MAX_EVENTS, 0);
    int i;

    for (i = 0; i < nevents; ++i) {
        /* Handle new connect */
        if (events[i].data.fd == sockfd) {
            while (1) {
                int nclientfd = ff_accept(sockfd, NULL, NULL);
                if (nclientfd < 0) {
                    break;
                }

                /* Add to event list */
                ev.data.fd = nclientfd;
                ev.events  = EPOLLIN;
                if (ff_epoll_ctl(epfd, EPOLL_CTL_ADD, nclientfd, &ev) != 0) {
                    printf("ff_epoll_ctl failed:%d, %s\n", errno,
                        strerror(errno));
                    break;
                }
            }
        } else { 
            if (events[i].events & EPOLLERR ) {
                /* Simply close socket */
                ff_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                ff_close(events[i].data.fd);
            } else if (events[i].events & EPOLLIN) {
                char buf[256];
                size_t readlen = ff_read( events[i].data.fd, buf, sizeof(buf));
                if(readlen > 0) {
                    ff_write( events[i].data.fd, html, sizeof(html) - 1);
                } else {
                    ff_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    ff_close( events[i].data.fd);
                }
            } else {
                printf("unknown event: %8.8X\n", events[i].events);
            }
        }
    }
}

//#ifdef __linux__
//#include <sched.h>
//typedef cpuset_t cpu_set_t;
//#endif

static int
set_affinity(int cpu_id)
{
	int rc;
	cpu_set_t cpumask;

	CPU_ZERO(&cpumask);
	CPU_SET(cpu_id, &cpumask);
	rc = sched_setaffinity(0, sizeof(cpumask), &cpumask);
	assert(rc == 0);
	return -rc;
}

int
ff_mod_init(const char *conf, int proc_id, int proc_type) {
    int rc, i;
    int ff_argc = 4;

    char **ff_argv = malloc(sizeof(char *)*ff_argc);
    for (i = 0; i < ff_argc; i++) {
        ff_argv[i] = malloc(4096); // PATH_MAX
    }

    sprintf(ff_argv[0], "helloworld_epoll");
    sprintf(ff_argv[1], "--conf=%s", conf);
    sprintf(ff_argv[2], "--proc-id=%d", proc_id);
    if (proc_type == 1) {
        sprintf(ff_argv[3], "--proc-type=primary");
    } else {
        sprintf(ff_argv[3], "--proc-type=secondary");
    }

    rc = ff_init(ff_argc, ff_argv);
    for (i = 0; i < ff_argc; i++) {
        free(ff_argv[i]);
    }

    free(ff_argv);

    return rc;
}



int
run(int i, int affinity)
{
	if (affinity != -1) {
		set_affinity(affinity + i);
	}
    ff_mod_init("config.ini", i, i == 0); 
    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0) {
        printf("ff_socket failed\n");
        exit(1);
    }

    int on = 1;
    ff_ioctl(sockfd, FIONBIO, &on);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(80);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = ff_bind(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed\n");
        exit(1);
    }

    ret = ff_listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("ff_listen failed\n");
        exit(1);
    }



    assert((epfd = ff_epoll_create(0)) > 0);
    ev.data.fd = sockfd;
    ev.events = EPOLLIN;
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    ff_run(loop, NULL);
    return 0;

}

int
main(int argc, char * argv[])
{
	int i, opt, n_workers, affinity;

	n_workers = 1;
	affinity = -1;
	while ((opt = getopt(argc, argv, "a:P:")) != -1) {
		switch (opt) {
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		case 'P':
			n_workers = strtoul(optarg, NULL, 10);
			break;
		}
	}

	for (i = 1; i < n_workers; ++i) {
		if (fork() == 0) {
			run(i, affinity);
		}
	}
	run(0, affinity);
	return 0;
}
