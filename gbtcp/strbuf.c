#include "strbuf.h"
#include "log.h"

static int gt_strbuf_add_recv_flags_os(struct gt_strbuf *sb, int flags);

static int gt_strbuf_add_send_flags_os(struct gt_strbuf *sb, int flags);

static short gt_strbuf_add_poll_events_os(struct gt_strbuf *sb, short events);

#define GT_STRBUF_ADD_FLAG(sb, flags, flag) \
({ \
	if (flags & flag) { \
		if ((sb)->sb_len) {\
			gt_strbuf_add_ch(sb, '|'); \
		} \
		gt_strbuf_add_str(sb, #flag); \
	} \
	flags & ~flag; \
})


void
gt_strbuf_init(struct gt_strbuf *sb, void *buf, int cap)
{
	sb->sb_cap = cap;
	sb->sb_len = 0;
	sb->sb_buf = buf;
}

int
gt_strbuf_space(struct gt_strbuf *sb)
{
	return sb->sb_cap > sb->sb_len ? sb->sb_cap - sb->sb_len - 1 : 0;
}

char *
gt_strbuf_cstr(struct gt_strbuf *sb)
{
	if (sb->sb_cap == 0) {
		return "";
	} else {
		sb->sb_buf[MIN(sb->sb_len, sb->sb_cap - 1)] = '\0';
		return sb->sb_buf;
	}
}

void
gt_strbuf_add(struct gt_strbuf *sb, const void *buf, int size)
{
	int n;

	if (sb->sb_cap > sb->sb_len) {
		n = MIN(size, sb->sb_cap - sb->sb_len);
		memcpy(sb->sb_buf + sb->sb_len, buf, n);
	}
	sb->sb_len += size;
}

void
gt_strbuf_add_ch(struct gt_strbuf *sb, char ch)
{
	if (sb->sb_cap > sb->sb_len) {
		sb->sb_buf[sb->sb_len] = ch;
	}
	sb->sb_len++;
}

void
gt_strbuf_add_ch3(struct gt_strbuf *sb, int ch, int n)
{
	int i, m, space;
	
	space = gt_strbuf_space(sb);
	m = space < n ? space : n;
	for (i = 0; i < m; ++i) {
		sb->sb_buf[sb->sb_len + i] = ch;
	}
	sb->sb_len += n;
}

void
gt_strbuf_add_str(struct gt_strbuf *sb, const char *str)
{
	gt_strbuf_add(sb, str, strlen(str));
}

void
gt_strbuf_vaddf(struct gt_strbuf *sb, const char *fmt, va_list ap)
{
	int rc, cnt;

	cnt = gt_strbuf_space(sb);
	rc = vsnprintf(sb->sb_buf + sb->sb_len, cnt, fmt, ap);
	sb->sb_len += rc;
}

void
gt_strbuf_addf(struct gt_strbuf *sb, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	gt_strbuf_vaddf(sb, fmt, ap);
	va_end(ap);
}

void
gt_strbuf_add_eth_addr(struct gt_strbuf *sb, struct gt_eth_addr *a)
{
	gt_strbuf_addf(sb, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	               a->etha_bytes[0], a->etha_bytes[1], a->etha_bytes[2],
	               a->etha_bytes[3], a->etha_bytes[4], a->etha_bytes[5]);
}

void
gt_strbuf_add_ip_addr(struct gt_strbuf *sb, int af, const void *ip)
{
	char buf[INET6_ADDRSTRLEN];

	ASSERT(af == AF_INET || af == AF_INET6);
	inet_ntop(af, ip, buf, sizeof(buf));
	gt_strbuf_add_str(sb, buf);
}

void
gt_strbuf_remove(struct gt_strbuf *sb, int pos, int len)
{
	ASSERT(pos + len <= sb->sb_len);
	ASSERT(sb->sb_len <= sb->sb_cap);
	memmove(sb->sb_buf + pos,
	        sb->sb_buf + pos + len,
	        sb->sb_len - (pos + len));
	sb->sb_len -= len;
}

void
gt_strbuf_insert(struct gt_strbuf *sb, int pos, const void *data, int len)
{
	int excess;

	ASSERT(pos <= sb->sb_len);
	if (pos >= sb->sb_cap) {
		/* Nothing to copy */
	} else if (pos + len >= sb->sb_cap) {
		memcpy(sb->sb_buf + pos, data, sb->sb_cap - pos);
	} else {
		if (sb->sb_cap >= sb->sb_len + len) {
			excess = 0;
		} else {
			excess = sb->sb_cap - (sb->sb_len + len);
		}
		memmove(sb->sb_buf + pos + len,
		        sb->sb_buf + pos,
		        sb->sb_len - pos - excess);
		memcpy(sb->sb_buf + pos, data, len);
	}
	sb->sb_len += len;
}

void
gt_strbuf_add_flag_end(struct gt_strbuf *sb, int flags)
{
	if (flags) {
		if (sb->sb_len) {
			gt_strbuf_add_ch(sb, '|');
		}
		gt_strbuf_addf(sb, "0x%x", flags);
	}
}

void
gt_strbuf_add_backtrace(struct gt_strbuf *sb, int depth_off)
{
	void *buffer[128];
	char **strs;
	int i, n;

	n = backtrace(buffer, GT_ARRAY_SIZE(buffer));
	strs = backtrace_symbols(buffer, n);
	if (strs == NULL) {
		for (i = depth_off; i < n; ++i) {
			sb->sb_len = 0;
			gt_strbuf_addf(sb, "%p\n", buffer[i]);
		}
	} else {
		for (i = depth_off; i < n; ++i) {
			sb->sb_len = 0;
			gt_strbuf_add_str(sb, strs[i]);
			gt_strbuf_add_ch(sb, '\n');
		}
		free(strs);
	}
}

void
gt_strbuf_add_recv_flags(struct gt_strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_CMSG_CLOEXEC);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_DONTWAIT);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_OOB);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_PEEK);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_TRUNC);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_WAITALL);
	rem = gt_strbuf_add_recv_flags_os(sb, rem);
	gt_strbuf_add_flag_end(sb, rem);
}

void
gt_strbuf_add_send_flags(struct gt_strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_DONTROUTE);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_DONTWAIT);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_EOR);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_NOSIGNAL);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_OOB);
	rem = gt_strbuf_add_send_flags_os(sb, rem);
	gt_strbuf_add_flag_end(sb, rem);
}

void
gt_strbuf_add_tcp_state(struct gt_strbuf *sb, int tcp_state)
{
	const char *s;

	s = gt_tcp_state_str(tcp_state);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%x", tcp_state);
	}
}

void
gt_strbuf_add_socket_domain(struct gt_strbuf *sb, int domain)
{
	const char *s;

	s = gt_socket_domain_str(domain);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%x", domain);
	}
}

void
gt_strbuf_add_socket_type(struct gt_strbuf *sb, int type)
{
	const char *s;

	s = gt_socket_type_str(type);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%d", type);
	}
}

void
gt_strbuf_add_socket_flags(struct gt_strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = GT_STRBUF_ADD_FLAG(sb, rem, SOCK_NONBLOCK);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, SOCK_CLOEXEC);
	gt_strbuf_add_flag_end(sb, rem);
}

void
gt_strbuf_add_sockopt_level(struct gt_strbuf *sb, int level)
{
	const char *s;

	s = gt_sockopt_level_str(level);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%x", level);
	}

}

void
gt_strbuf_add_sockopt_optname(struct gt_strbuf *sb, int level, int optname)
{
	const char *s;

	s = gt_sockopt_optname_str(level, optname);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%x", optname);
	}
}

void
gt_strbuf_add_fcntl_cmd(struct gt_strbuf *sb, int cmd)
{
	const char *s;

	s = gt_fcntl_cmd_str(cmd);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%x", cmd);
	}
}

void
gt_strbuf_add_fcntl_setfl(struct gt_strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_RDONLY);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_WRONLY);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_RDWR);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_CREAT);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_EXCL);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_NOCTTY);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_TRUNC);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_APPEND);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_NONBLOCK);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, O_DIRECT);
	gt_strbuf_add_flag_end(sb, rem);
}

void
gt_strbuf_add_ioctl_req(struct gt_strbuf *sb, unsigned long req)
{
	const char *s;

	s = gt_ioctl_req_str(req);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%lx", req);
	}
}

void
gt_strbuf_add_shutdown_how(struct gt_strbuf *sb, int how)
{
	const char *s;

	s = gt_shutdown_how_str(how);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%x", how);
	}
}

void
gt_strbuf_add_poll_events(struct gt_strbuf *sb, short events)
{
	int rem;

	rem = events;
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLIN);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLPRI);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLOUT);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLHUP);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLERR);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLNVAL);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLRDNORM);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLRDBAND);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLWRNORM);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, POLLWRBAND);
	rem = gt_strbuf_add_poll_events_os(sb, rem);
	gt_strbuf_add_flag_end(sb, rem);
}

void
gt_strbuf_add_pollfds_events(struct gt_strbuf *sb, struct pollfd *pfds, int npfds)
{
	int i, n;

	for (n = 0, i = 0; i < npfds; ++i) {
		if (n) {
			gt_strbuf_add_ch(sb, ',');
		}
		n++;
		gt_strbuf_addf(sb, "{fd=%d:", pfds[i].fd);
		gt_strbuf_add_poll_events(sb, pfds[i].events);
		gt_strbuf_add_ch(sb, '}');
	}
}

void
gt_strbuf_add_pollfds_revents(struct gt_strbuf *sb, struct pollfd *pfds, int npfds)
{
	int i, n;

	for (n = 0, i = 0; i < npfds; ++i) {
		if (pfds[i].revents) {
			if (n) {
				gt_strbuf_add_ch(sb, ',');
			}
			n++;
			gt_strbuf_addf(sb, "{fd=%d:", pfds[i].fd);
			gt_strbuf_add_poll_events(sb, pfds[i].revents);
			gt_strbuf_add_ch(sb, '}');
		}
	}
}

void
gt_strbuf_add_sighandler(struct gt_strbuf *sb, void *fn)
{
	const char *s;

	s = gt_sighandler_str(fn);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "%p", fn);
	}
}

void
gt_strbuf_add_sigprocmask_how(struct gt_strbuf *sb, int how)
{
	const char *s;

	s = gt_sigprocmask_how_str(how);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%x", how);
	}
}

void
gt_strbuf_add_rss_key(struct gt_strbuf *sb, uint8_t *rss_key)
{
	int i;
	for (i = 0; i < GT_RSS_KEY_SIZE; ++i) {
		if (i) {
			gt_strbuf_add_ch(sb, ':');
		}
		gt_strbuf_addf(sb, "%02hhx", rss_key[i]);
	}
}

#ifdef __linux__
void
gt_strbuf_add_epoll_event_events(struct gt_strbuf *sb, short events)
{
	short rem;

	rem = events;
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLIN);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLOUT);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLRDHUP);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLPRI);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLERR);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLHUP);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLET);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLONESHOT);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, EPOLLWAKEUP);
	gt_strbuf_add_flag_end(sb, rem);
}

void
gt_strbuf_add_epoll_op(struct gt_strbuf *sb, int op)
{
	const char *s;

	s = gt_epoll_op_str(op);
	if (s != NULL) {
		gt_strbuf_add_str(sb, s);
	} else {
		gt_strbuf_addf(sb, "0x%x", op);
	}
}

void
gt_strbuf_add_clone_flags(struct gt_strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_CHILD_CLEARTID);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_CHILD_SETTID);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_FILES);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_FS);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_IO);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_NEWIPC);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_NEWNET);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_NEWNS);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_NEWPID);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_NEWUSER);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_NEWUTS);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_PARENT);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_PARENT_SETTID);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_PTRACE);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_SETTLS);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_SIGHAND);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_SYSVSEM);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_THREAD);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_UNTRACED);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_VFORK);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, CLONE_VM);
	gt_strbuf_add_flag_end(sb, rem);
	// TODO: signal  to string
}
#endif /* __linux__ */

#ifdef __linux__
static int
gt_strbuf_add_recv_flags_os(struct gt_strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	GT_STRBUF_ADD_FLAG(sb, rem, MSG_ERRQUEUE);
	return rem;
}

static int
gt_strbuf_add_send_flags_os(struct gt_strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_CONFIRM);
	rem = GT_STRBUF_ADD_FLAG(sb, rem, MSG_MORE);
	return rem;
}

static short
gt_strbuf_add_poll_events_os(struct gt_strbuf *sb, short events)
{
	int rem;

	rem = GT_STRBUF_ADD_FLAG(sb, events, POLLRDHUP);
	return rem;
}
#else /* __linux__ */
static int
gt_strbuf_add_recv_flags_os(struct gt_strbuf *sb, int flags)
{
	return flags;
}

static int
gt_strbuf_add_send_flags_os(struct gt_strbuf *sb, int flags)
{
	return flags;
}

static short
gt_strbuf_add_poll_events_os(struct gt_strbuf *sb, short events)
{
	return events;
}
#endif /* __linux__ */
