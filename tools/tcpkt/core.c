#include "core.h"

int debuging;
ipaddr_t ipaddr_zero;
struct eth_addr eth_zero;

void
die(int err_num, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (err_num) {
		fprintf(stderr, " (%d:%s)\n", err_num, strerror(err_num));
	} else {
		fputc('\n', stderr);
	}
	exit(1);
}

void
vdbg(const char *file, int line, const char *func, const char *format, va_list ap)
{
	if (debuging) {
		printf("%-10s %-4d %-30s: ", file, line, func);
		vfprintf(stdout, format, ap);
		fprintf(stdout, "\n");
	}
}

void
dbg4(const char *file, int line, const char *func, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vdbg(file, line, func, format, ap);
	va_end(ap);
}

void *
xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		die(errno, "malloc(%zu) failed", size);
	}
	return ptr;
}

void *
xmalloc_zero(size_t size)
{
	void *ptr;

	ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}

void *
xrealloc(void *ptr, size_t size)
{
	void *new_ptr;

	new_ptr = realloc(ptr, size);
	if (new_ptr == NULL) {
		die(errno, "realloc(%zu) failed", size);
	}
	return new_ptr;
}

char *
strzcpy(char *dst, const char *src, size_t len)
{
	size_t i;

	assert(len);
	for (i = 0; i < len - 1; ++i) {
		if (src[i] == '\0') {
			break;
		}
		dst[i] = src[i];	
	}
	dst[i] = '\0';
	return dst;
}


char *
trim(char *string, const char *what)
{
	char *p, *first, *last;

	for (p = string; *p != '\0'; ++p) {
		if (strchr(what, *p) == NULL) {
			break;
		}
	}
	first = last = p; 
	for (p = first + 1; *p != '\0'; ++p) {
		if (strchr(what, *p) == NULL) {
			last = p; 
		}
	}
	*(last + 1) = '\0';
	return first;
}

int
set_bit(long *l, size_t i)
{
	if (test_bit(*l, i)) {
		return 1;
	} else {
		(*l) |= (1l << i);
		return 0;
	}
}

int
unset_bit(long *l, size_t i)
{
	if (test_bit(*l, i)) {
		(*l) &= ~(1l << i);
		return 1;
	} else {
		return 0;
	}
}

int
test_bit(long l, size_t i)
{
	assert(i < CHAR_BIT * sizeof(l));
	return l & (1l << i);
}

int
eth_aton(struct eth_addr *a, const char *cp)
{
	int rc;

	rc = sscanf(cp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	            a->bytes + 0, a->bytes + 1, a->bytes + 2,
	            a->bytes + 3, a->bytes + 4, a->bytes + 5);
	return rc == 6 ? 0 : -1;
}

char *
eth_ntoa(const struct eth_addr *src, char *dst)
{
	snprintf(dst, ETH_ADDRSTRLEN,
		"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		src->bytes[0], src->bytes[1], src->bytes[2],
		src->bytes[3], src->bytes[4], src->bytes[5]);
	return dst;
}

int
eth_is_bcast(struct eth_addr *a)
{
	int i;

	for (i = 0; i < sizeof(a->bytes); ++i) {
		if (a->bytes[i] != 0xff) {
			return 0;
		}
	}
	return 1;	
}

ipaddr_t *
ipaddr_cpy(int af, ipaddr_t *dst, const ipaddr_t *src)
{
	if (af == AF_INET) {
		dst->ipv4 = src->ipv4;
	} else {
		memcpy(dst->ipv6, src->ipv6, sizeof(dst->ipv6));
	}
	return dst;
}

int
ipaddr_cmp(int af, const ipaddr_t *l, const ipaddr_t *r)
{
	if (af == AF_INET) {
		return l->ipv4 - r->ipv4;
	} else {
		return memcmp(l->ipv6, r->ipv6, sizeof(l->ipv6));
	}
}

int
ipaddr_prefix(int af, const ipaddr_t *addr)
{
	int i, n, pfx;
	uint32_t x;

	pfx = 0;
	n = af == AF_INET ? 1 : 4;
	for (i = 0; i < n; ++i) {
		x = BE32_TO_CPU(addr->data_32[i]);
		if (x == -1) {
			pfx += 32; 
		} else {
			if (x) {
				pfx = 32 - (ffsl(x) - 1); 
			}
			break;
		}
	}
	return pfx;
}

int
ipaddr_is_zero(int af, const ipaddr_t *addr)
{
	if (af == AF_INET) {
		return addr->ipv4 == 0;
	} else {
		return !memcmp(addr->ipv6, ipaddr_zero.ipv6, 16);
	}
}

int
ipport_pton(int af, const char *str, void *addr, be16_t *port)
{
	int len, rc;
	char *endptr, *ptr;
	char buf[INET6_ADDRSTRLEN + 16];

	len = strlen(str);
	if (len + 1 > sizeof(buf)) {
		return -EINVAL;
	}
	memcpy(buf, str, len + 1);
	if (af != AF_INET) {
		return -ENOTSUP;
	}
	ptr = strchr(buf, ':');
	if (ptr != NULL) {
		*ptr = '\0';
		rc = strtoul(ptr + 1, &endptr, 10);
		if (*endptr != '\0' || rc < 0 || rc > 65535) {
			return -EINVAL;
		}
		*port = CPU_TO_BE16(rc);
	}
	rc = inet_pton(af, buf, addr);
	return rc == 1 ? 0 : -EINVAL;
}
