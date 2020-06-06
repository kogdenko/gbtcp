#include "strbuf.h"
#include "log.h"

#define STRBUF_ADD_FLAG(sb, flags, flag) \
({ \
	if (flags & flag) { \
		if ((sb)->sb_len) \
			strbuf_add_ch(sb, '|'); \
		strbuf_add_str(sb, #flag); \
	} \
	flags & ~flag; \
})

void
strbuf_init(struct strbuf *sb, void *buf, int cap)
{
	sb->sb_cap = cap;
	sb->sb_len = 0;
	sb->sb_buf = buf;
}

int
strbuf_space(struct strbuf *sb)
{
	return sb->sb_cap > sb->sb_len ? sb->sb_cap - sb->sb_len - 1 : 0;
}

char *
strbuf_cstr(struct strbuf *sb)
{
	if (sb->sb_cap == 0) {
		return "";
	} else {
		sb->sb_buf[MIN(sb->sb_len, sb->sb_cap - 1)] = '\0';
		return sb->sb_buf;
	}
}

void
strbuf_remove(struct strbuf *sb, int pos, int len)
{
	assert(pos + len <= sb->sb_len);
	assert(sb->sb_len <= sb->sb_cap);
	memmove(sb->sb_buf + pos,
	        sb->sb_buf + pos + len,
	        sb->sb_len - (pos + len));
	sb->sb_len -= len;
}

void
strbuf_insert(struct strbuf *sb, int pos, const void *data, int len)
{
	int excess;

	assert(pos <= sb->sb_len);
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
strbuf_add(struct strbuf *sb, const void *buf, int size)
{
	int n;

	if (sb->sb_cap > sb->sb_len) {
		n = MIN(size, sb->sb_cap - sb->sb_len);
		memcpy(sb->sb_buf + sb->sb_len, buf, n);
	}
	sb->sb_len += size;
}

void
strbuf_add_ch(struct strbuf *sb, char ch)
{
	if (sb->sb_cap > sb->sb_len) {
		sb->sb_buf[sb->sb_len] = ch;
	}
	sb->sb_len++;
}

void
strbuf_add_ch3(struct strbuf *sb, int ch, int n)
{
	int i, m, space;
	space = strbuf_space(sb);
	m = space < n ? space : n;
	for (i = 0; i < m; ++i) {
		sb->sb_buf[sb->sb_len + i] = ch;
	}
	sb->sb_len += n;
}

void
strbuf_add_str(struct strbuf *sb, const char *str)
{
	strbuf_add(sb, str, strlen(str));
}

void
strbuf_vaddf(struct strbuf *sb, const char *fmt, va_list ap)
{
	int rc, cnt;

	cnt = strbuf_space(sb);
	rc = vsnprintf(sb->sb_buf + sb->sb_len, cnt, fmt, ap);
	sb->sb_len += rc;
}

void
strbuf_addf(struct strbuf *sb, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	strbuf_vaddf(sb, fmt, ap);
	va_end(ap);
}

void
strbuf_add_eth_addr(struct strbuf *sb, struct eth_addr *a)
{
	strbuf_addf(sb, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	            a->ea_bytes[0], a->ea_bytes[1], a->ea_bytes[2],
	            a->ea_bytes[3], a->ea_bytes[4], a->ea_bytes[5]);
}

void
strbuf_add_ipaddr(struct strbuf *sb, int af, const void *ip)
{
	char buf[INET6_ADDRSTRLEN];

	assert(af == AF_INET || af == AF_INET6);
	inet_ntop(af, ip, buf, sizeof(buf));
	strbuf_add_str(sb, buf);
}

void
strbuf_add_rss_key(struct strbuf *sb, u_char *rss_key)
{
	int i;

	for (i = 0; i < RSS_KEY_SIZE; ++i) {
		if (i) {
			strbuf_add_ch(sb, ':');
		}
		strbuf_addf(sb, "%02hhx", rss_key[i]);
	}
}

void
strbuf_add_flag_end(struct strbuf *sb, int flags)
{
	if (flags) {
		if (sb->sb_len) {
			strbuf_add_ch(sb, '|');
		}
		strbuf_addf(sb, "0x%x", flags);
	}
}

void
strbuf_add_backtrace(struct strbuf *sb, int depth_off)
{
	void *buffer[128];
	char **strs;
	int i, n;

	n = backtrace(buffer, ARRAY_SIZE(buffer));
	strs = backtrace_symbols(buffer, n);
	if (strs == NULL) {
		for (i = depth_off; i < n; ++i) {
			sb->sb_len = 0;
			strbuf_addf(sb, "%p\n", buffer[i]);
		}
	} else {
		for (i = depth_off; i < n; ++i) {
			sb->sb_len = 0;
			strbuf_add_str(sb, strs[i]);
			strbuf_add_ch(sb, '\n');
		}
		free(strs);
	}
}

#ifdef __linux__
static int
strbuf_add_recv_flags_os(struct strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	STRBUF_ADD_FLAG(sb, rem, MSG_ERRQUEUE);
	return rem;
}

static int
strbuf_add_send_flags_os(struct strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_CONFIRM);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_MORE);
	return rem;
}

static short
strbuf_add_poll_events_os(struct strbuf *sb, short events)
{
	int rem;

	rem = STRBUF_ADD_FLAG(sb, events, POLLRDHUP);
	return rem;
}
#else /* __linux__ */
static int
strbuf_add_recv_flags_os(struct strbuf *sb, int flags)
{
	return flags;
}

static int
strbuf_add_send_flags_os(struct strbuf *sb, int flags)
{
	return flags;
}

static short
strbuf_add_poll_events_os(struct strbuf *sb, short events)
{
	return events;
}
#endif /* __linux__ */
void
strbuf_add_recv_flags(struct strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_CMSG_CLOEXEC);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_DONTWAIT);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_OOB);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_PEEK);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_TRUNC);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_WAITALL);
	rem = strbuf_add_recv_flags_os(sb, rem);
	strbuf_add_flag_end(sb, rem);
}

void
strbuf_add_send_flags(struct strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_DONTROUTE);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_DONTWAIT);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_EOR);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_NOSIGNAL);
	rem = STRBUF_ADD_FLAG(sb, rem, MSG_OOB);
	rem = strbuf_add_send_flags_os(sb, rem);
	strbuf_add_flag_end(sb, rem);
}

void
strbuf_add_tcp_state(struct strbuf *sb, int tcp_state)
{
	const char *s;

	s = tcp_state_str(tcp_state);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%x", tcp_state);
	}
}

void
strbuf_add_socket_domain(struct strbuf *sb, int domain)
{
	const char *s;

	s = socket_domain_str(domain);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%x", domain);
	}
}

void
strbuf_add_socket_type(struct strbuf *sb, int type)
{
	const char *s;

	s = socket_type_str(type);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%d", type);
	}
}

void
strbuf_add_socket_flags(struct strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = STRBUF_ADD_FLAG(sb, rem, SOCK_NONBLOCK);
	rem = STRBUF_ADD_FLAG(sb, rem, SOCK_CLOEXEC);
	strbuf_add_flag_end(sb, rem);
}

void
strbuf_add_shutdown_how(struct strbuf *sb, int how)
{
	const char *s;

	s = shutdown_how_str(how);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%x", how);
	}
}

void
strbuf_add_fcntl_cmd(struct strbuf *sb, int cmd)
{
	const char *s;

	s = fcntl_cmd_str(cmd);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%x", cmd);
	}
}

void
strbuf_add_fcntl_setfl(struct strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = STRBUF_ADD_FLAG(sb, rem, O_RDONLY);
	rem = STRBUF_ADD_FLAG(sb, rem, O_WRONLY);
	rem = STRBUF_ADD_FLAG(sb, rem, O_RDWR);
	rem = STRBUF_ADD_FLAG(sb, rem, O_CREAT);
	rem = STRBUF_ADD_FLAG(sb, rem, O_EXCL);
	rem = STRBUF_ADD_FLAG(sb, rem, O_NOCTTY);
	rem = STRBUF_ADD_FLAG(sb, rem, O_TRUNC);
	rem = STRBUF_ADD_FLAG(sb, rem, O_APPEND);
	rem = STRBUF_ADD_FLAG(sb, rem, O_NONBLOCK);
	rem = STRBUF_ADD_FLAG(sb, rem, O_DIRECT);
	strbuf_add_flag_end(sb, rem);
}

void
strbuf_add_ioctl_req(struct strbuf *sb, unsigned long req)
{
	const char *s;

	s = ioctl_req_str(req);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%lx", req);
	}
}

void
strbuf_add_sockopt_level(struct strbuf *sb, int level)
{
	const char *s;

	s = sockopt_level_str(level);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%x", level);
	}
}

void
strbuf_add_sockopt_optname(struct strbuf *sb, int level, int optname)
{
	const char *s;

	s = sockopt_optname_str(level, optname);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%x", optname);
	}
}

void
strbuf_add_poll_events(struct strbuf *sb, short events)
{
	int rem;

	rem = events;
	rem = STRBUF_ADD_FLAG(sb, rem, POLLIN);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLPRI);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLOUT);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLHUP);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLERR);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLNVAL);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLRDNORM);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLRDBAND);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLWRNORM);
	rem = STRBUF_ADD_FLAG(sb, rem, POLLWRBAND);
	rem = strbuf_add_poll_events_os(sb, rem);
	strbuf_add_flag_end(sb, rem);
}

void
strbuf_add_pollfds_events(struct strbuf *sb, struct pollfd *pfds, int npfds)
{
	int i, n;

	for (n = 0, i = 0; i < npfds; ++i) {
		if (n) {
			strbuf_add_ch(sb, ',');
		}
		n++;
		strbuf_addf(sb, "{fd=%d:", pfds[i].fd);
		strbuf_add_poll_events(sb, pfds[i].events);
		strbuf_add_ch(sb, '}');
	}
}

void
strbuf_add_pollfds_revents(struct strbuf *sb, struct pollfd *pfds, int npfds)
{
	int i, n;

	for (n = 0, i = 0; i < npfds; ++i) {
		if (pfds[i].revents) {
			if (n) {
				strbuf_add_ch(sb, ',');
			}
			n++;
			strbuf_addf(sb, "{fd=%d:", pfds[i].fd);
			strbuf_add_poll_events(sb, pfds[i].revents);
			strbuf_add_ch(sb, '}');
		}
	}
}
void
strbuf_add_sighandler(struct strbuf *sb, void *fn)
{
	const char *s;

	s = sighandler_str(fn);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "%p", fn);
	}
}

void
strbuf_add_sigprocmask_how(struct strbuf *sb, int how)
{
	const char *s;

	s = sigprocmask_how_str(how);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%x", how);
	}
}
#ifdef __linux__
void
strbuf_add_epoll_event_events(struct strbuf *sb, short events)
{
	short rem;

	rem = events;
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLIN);
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLOUT);
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLRDHUP);
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLPRI);
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLERR);
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLHUP);
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLET);
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLONESHOT);
	rem = STRBUF_ADD_FLAG(sb, rem, EPOLLWAKEUP);
	strbuf_add_flag_end(sb, rem);
}

void
strbuf_add_epoll_op(struct strbuf *sb, int op)
{
	const char *s;

	s = epoll_op_str(op);
	if (s != NULL) {
		strbuf_add_str(sb, s);
	} else {
		strbuf_addf(sb, "0x%x", op);
	}
}

void
strbuf_add_clone_flags(struct strbuf *sb, int flags)
{
	int rem;

	rem = flags;
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_CHILD_CLEARTID);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_CHILD_SETTID);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_FILES);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_FS);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_IO);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_NEWIPC);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_NEWNET);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_NEWNS);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_NEWPID);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_NEWUSER);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_NEWUTS);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_PARENT);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_PARENT_SETTID);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_PTRACE);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_SETTLS);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_SIGHAND);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_SYSVSEM);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_THREAD);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_UNTRACED);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_VFORK);
	rem = STRBUF_ADD_FLAG(sb, rem, CLONE_VM);
	strbuf_add_flag_end(sb, rem);
	// TODO: signal  to string
}
#endif /* __linux__ */
