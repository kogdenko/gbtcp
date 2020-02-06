#include "ip_addr.h"

struct gt_ip_addr gt_ip_addr_zero;

int
gt_ip_addr_is_zero(int af, const struct gt_ip_addr *a)
{
	if (af == AF_INET) {
		return a->ipa_4 == 0;
	} else {
		return !memcmp(a->ipa_6, gt_ip_addr_zero.ipa_6,
		               sizeof(a->ipa_6));
	}
}

int
gt_ip_addr_cmp(int af, const struct gt_ip_addr *a, const struct gt_ip_addr *b)
{
	if (af == AF_INET) {
		return a->ipa_4 - b->ipa_4;
	} else {
		return memcmp(a->ipa_6, b->ipa_6, sizeof(a->ipa_6));
	}
}

struct gt_ip_addr *
gt_ip_addr_cpy(int af, struct gt_ip_addr *dst, const struct gt_ip_addr *src)
{
	if (af == AF_INET) {
		dst->ipa_4 = src->ipa_4;
	} else {
		memcpy(dst->ipa_6, src->ipa_6, sizeof(src->ipa_6));
	}
	return dst;
}

int
gt_ip_addr_pfx(int af, const struct gt_ip_addr *addr)
{
	int i, n, pfx;
	uint32_t x;

	pfx = 0;
	n = af == AF_INET ? 1 : 4;
	for (i = 0; i < n; ++i) {
		x = GT_NTOH32(addr->ipa_data_32[i]);
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
gt_ip_addr_pton(int af, struct gt_ip_addr *dst, const char *src)
{
	int rc;

	rc = inet_pton(af, src, dst->ipa_data);
	if (rc <= 0) {
		return -EINVAL;
	} else {
		return 0;
	}
}

int
gt_ip_addr_aton(be32_t *dst, const char *src)
{
	int rc;
	struct gt_ip_addr x;

	rc = gt_ip_addr_pton(AF_INET, &x, src);
	if (rc) {
		return rc;
	}
	*dst = x.ipa_4;
	return 0;
}

int
gt_ip_addr4_is_loopback(be32_t ip)
{
	return (ip & GT_HTON32(0xff000000)) == GT_HTON32(0x7f000000);
}

int
gt_ip_addr4_is_mcast(be32_t ip)
{
	return (ip & GT_HTON32(0xf0000000)) == GT_HTON32(0xe0000000);
}

int
gt_ip_addr4_is_bcast(be32_t ip)
{
	return ip == 0xffffffff;
}

int
gt_ip_addr6_is_mcast(const void *ip) 
{
	int rc;

	rc = *((uint8_t *)ip) == 0xff;
	return rc;
}

int
gt_ip_addr6_is_unspecified(const void *ip)
{
	return !memcmp(ip, gt_ip_addr_zero.ipa_6, GT_IP6_ADDR_LEN);
}
 
int
gt_ip_addr6_is_solicited_node_mcast(const void *ip)
{
	static uint8_t pfx[13] = {
		0xff, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0xff
	};
 	return !memcmp(ip, pfx, sizeof(pfx));
}

int
ip6_is_link_local(const void *ip)
{
	int rc;
	static uint8_t pfx[16] = {
		0xfe, 0x80, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	rc = gt_ip_addr6_net_cmp(ip, pfx, 10);
	return rc == 0 ? 1 : 0;
}

int
gt_ip_addr6_net_cmp(const uint8_t *a, const uint8_t *b, int len)
{
	int i, n, rc;
	uint8_t m;

	i = len >> 3;
	assert(i <= 16);
	rc = memcmp(a, b, i);
	if (rc != 0) {
		return rc;
	}
	n = len - (i << 3);
	if (n == 0) {
		return 0;
	}
	m = 0xff;
	m <<= (n - 8);
	rc = (a[i + 1] & m) - (b[i + 1] & m);
	return rc;
}
