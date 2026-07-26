// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/api.h>
#include <gbtcp/kernel/api.pb-c.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/mm.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/vector.h>

#define GT_API_MSG_TYPE_REQUEST 1
#define GT_API_MSG_TYPE_REPLY 2

#define GT_API_MSG_NAME_SIZE_MAX 128
#define GT_API_BUF_SIZE_MAX 16384

struct gt_api_request {
	struct gt_dlist req_link;
	char req_name[GT_API_MSG_NAME_SIZE_MAX];
	u8 req_is_dump;
	gt_api_request_handler_f req_handler;
	gt_api_callback_f req_send_callback;
	gt_api_callback_f req_free_callback;
};

struct gt_api_header {
	be32_t ah_payload_size;
	be16_t ah_type;
	be16_t ah_code;
} __attribute__((packed));

void *
gt_pbc_alloc(void *allocator_data, size_t size)
{
	void *pointer;
	struct gt_allocator *a;
	struct gt_pbc_allocator *pbc_allocator;

	pbc_allocator = allocator_data;
	a = pbc_allocator->our_allocator;

	// Why GT_MAX(1)
	pointer = gt_a_malloc_align(a, GT_MAX(size, 1), GT_L1_CACHE_BYTES, 0);
	assert(GT_IS_ALIGNED((uintptr_t)pointer, GT_L1_CACHE_BYTES));
	return pointer;
}

void
gt_pbc_free(void *allocator_data, void *pointer)
{
	struct gt_allocator *a;
	struct gt_pbc_allocator *pbc_allocator;

	pbc_allocator = allocator_data;
	a = pbc_allocator->our_allocator;

	if (GT_IS_ALIGNED((uintptr_t)pointer, GT_L1_CACHE_BYTES)) {
		gt_a_free_internal(a, pointer);
	} else {
		gt_vec_free(pointer, a);
	}
}

char *
gt_pbc_strdup(struct gt_api_conn *cp, const char *s)
{
	size_t size;
	char *dst;

	size = strlen(s) + 1;
	dst = gt_pbc_alloc(&cp->cn_pbc_allocator.protobuf_allocator, size);
	if (dst != NULL) {
		memcpy(dst, s, size);
	}
	return dst;
}

struct gt_api_conn *
gt_api_conn_alloc(struct gt_allocator *alc)
{
	struct gt_api_conn *cp;

	cp = gt_a_malloc_align(alc, sizeof(struct gt_api_conn),
			       GT_L1_CACHE_BYTES, 0);
	if (cp != NULL) {
		gt_api_conn_init(cp, alc);
	}
	return cp;
}

void
gt_api_conn_free(struct gt_api_conn *cp)
{
	gt_a_free_internal(cp->cn_pbc_allocator.our_allocator, cp);
}

void
gt_api_conn_init(struct gt_api_conn *cp, struct gt_allocator *alc)
{
	memset(cp, 0, sizeof(*cp));
	cp->cn_pbc_allocator.protobuf_allocator.alloc = gt_pbc_alloc;
	cp->cn_pbc_allocator.protobuf_allocator.free = gt_pbc_free;
	// protobuf-c invokes alloc/free as (*alloc)(allocator_data, size) /
	// (*free)(allocator_data, ptr) — allocator_data must point back at
	// this gt_pbc_allocator so gt_pbc_alloc()/gt_pbc_free() can recover
	// our_allocator; it is not implied by protobuf_allocator's own
	// address.
	cp->cn_pbc_allocator.protobuf_allocator.allocator_data =
		&cp->cn_pbc_allocator;
	cp->cn_pbc_allocator.our_allocator = alc;
	gt_dlist_init(&cp->cn_request_head);
	gt_deferred_init(&cp->cn_deferred_entry);
	cp->cn_fd = -1;
}

int
gt_api_conn_get_fd(struct gt_api_conn *cp)
{
	return cp->cn_fd;
}

u8
gt_api_conn_is_opened(struct gt_api_conn *cp)
{
	return cp->cn_fd >= 0;
}

// State of the sync exec (gt_api__exec_request), see there. Declared before
// gt_api__conn_close: a close of the conn an exec is spinning on must fail
// the exec.
static int gt_api_exec_errnum;
static struct gt_api_conn *gt_api_exec_conn;

static int
gt_api_conn_open(struct gt_api_conn *cp, int fd, fd_event_f fn)
{
	int rc;

	assert(cp->cn_fd < 0);
	cp->cn_fd = fd;
	rc = fd_event_add(&cp->cn_event, cp->cn_fd, cp, fn);
	if (rc == 0) {
		fd_event_set(cp->cn_event, POLLIN);
	}
	return rc;
}

static int
gt_api_conn_send(struct gt_api_conn *cp)
{
	size_t size;
	ssize_t rc;

	size = gt_vec_size(cp->cn_sndbuf);
	if (size == 0) {
		return 0;
	}

	if (cp->cn_throttled) {
		return 0;
	}

	rc = sys_send(cp->cn_fd, cp->cn_sndbuf, size, MSG_NOSIGNAL);
	if (rc > 0) {
		gt_vec_pop_front(cp->cn_sndbuf,
				 cp->cn_pbc_allocator.our_allocator, rc);
	}

	if (rc == -EAGAIN || rc < size) {
		cp->cn_throttled = 1;
		fd_event_set(cp->cn_event, POLLOUT);
	} else if (rc < 0) {
		return rc;
	}

	return 0;
}

static void
gt_api_server_done(struct gt_api_conn *cp)
{
	if (cp->cn_server.req != NULL) {
		(*cp->cn_server.req->req_free_callback)(cp);
		cp->cn_server.req = NULL;
	}
}

void
gt_api__conn_close(struct gt_api_conn *cp)
{
	if (cp == gt_api_exec_conn) {
		// An exec is spinning on this conn: its reply can never
		// arrive, fail it (see gt_api__exec_request()).
		gt_api_exec_errnum = ECONNRESET;
		gt_api_exec_conn = NULL;
	}
	if (gt_api_conn_is_opened(cp)) {
		gt_api_server_done(cp);

		if (cp->cn_close_callback != NULL) {
			(*cp->cn_close_callback)(cp);
		}

		gt_deferred_cancel(&cp->cn_deferred_entry);

		sys_close(cp->cn_fd);
		fd_event_del(cp->cn_event);
		gt_vec_free(cp->cn_rcvbuf, cp->cn_pbc_allocator.our_allocator);
		gt_vec_free(cp->cn_sndbuf, cp->cn_pbc_allocator.our_allocator);

		gt_api_conn_init(cp, cp->cn_pbc_allocator.our_allocator);
	}
}

void *
gt_api_conn_get_udata(struct gt_api_conn *cp)
{
	return cp->cn_udata;
}

void
gt_api_conn_set_udata(struct gt_api_conn *cp, void *udata)
{
	cp->cn_udata = udata;
}

void
gt_api_conn_set_close_handler(struct gt_api_conn *cp, gt_api_callback_f fn)
{
	cp->cn_close_callback = fn;
}

static int
gt_api_parse_request_name(const char *req_name, int buf_size)
{
	int i;

	for (i = 0; i < buf_size; ++i) {
		if (req_name[i] == '\0') {
			return i + 1;
		} else if (i == GT_API_MSG_NAME_SIZE_MAX) {
			return -EINVAL;
		} else if (!isalnum(req_name[i])) {
			return -EINVAL;
		}
	}

	return -EAGAIN;
}

static int
gt_api_make_request_name(char *dst, const char *src)
{
	int i, len, ch, upper;

	// SnakeCase to camel_case
	upper = 1;
	for (i = 0, len = 0; len < GT_API_MSG_NAME_SIZE_MAX - 1; ++i) {
		ch = src[i];
		if (ch == '_') {
			upper = 1;
		} else if (ch == '\0') {
			break;
		} else {
			dst[len++] = upper ? toupper(ch) : ch;
			upper = 0;
		}
	}

	dst[len] = '\0';

	return len + 1;
}

static int
gt_api_conn_add_request(struct gt_api_conn *cp, u8 **pay, u32 pay_size,
			const char *snake_case)
{
	int rc, off, req_name_size;
	size_t req_size;
	char req_name[GT_API_MSG_NAME_SIZE_MAX];
	struct gt_api_header *ah;

	assert(gt_vec_size(cp->cn_sndbuf) == 0);
	req_name_size = gt_api_make_request_name(req_name, snake_case);
	req_size = sizeof(*ah) + req_name_size + pay_size;
	if (req_size > GT_API_BUF_SIZE_MAX) {
		return -EINVAL;
	}

	off = gt_vec_size(cp->cn_sndbuf);
	rc = gt_vec_resize(cp->cn_sndbuf, cp->cn_pbc_allocator.our_allocator,
			   off + req_size, 0);
	if (rc) {
		return -ENOMEM;
	}

	ah = (struct gt_api_header *)((u8 *)cp->cn_sndbuf + off);
	ah->ah_payload_size = hton32(pay_size);
	ah->ah_type = hton16(GT_API_MSG_TYPE_REQUEST);
	ah->ah_code = 0;
	memcpy(ah + 1, req_name, req_name_size);

	if (pay != NULL) {
		*pay = (u8 *)(ah + 1) + req_name_size;
	}
	return 0;
}

static int
gt_api_conn_add_reply(struct gt_api_conn *cp, u8 **pay, u32 pay_size,
		      u32 errnum)
{
	int rc;
	size_t off, rpl_size;
	struct gt_api_header *ah;

	rpl_size = sizeof(*ah) + pay_size;
	if (rpl_size > GT_API_BUF_SIZE_MAX) {
		return -EINVAL;
	}

	// ???
	off = gt_vec_size(cp->cn_sndbuf);
	if (pay_size && cp->cn_server.req->req_send_callback != NULL) {
		if (off) {
			assert(cp->cn_throttled);
			return -EAGAIN;
		}
	}

	rc = gt_vec_resize(cp->cn_sndbuf, cp->cn_pbc_allocator.our_allocator,
			   off + rpl_size, 0);
	if (rc) {
		return -ENOMEM;
	}

	ah = (struct gt_api_header *)(cp->cn_sndbuf + off);
	ah->ah_payload_size = hton32(pay_size);
	ah->ah_type = hton16(GT_API_MSG_TYPE_REPLY);
	ah->ah_code = hton16(errnum);

	if (pay != NULL) {
		*pay = (u8 *)(ah + 1);
	}
	return 0;
}

int
gt_api__send_request(struct gt_api_conn *cp, const char *snake_case, void *rq,
		     gt_pb2_get_packed_size_f get_packed_size,
		     gt_pb2_pack_f pack, gt_pb2_free_unpacked_f free_unpacked,
		     gt_api_reply_handler_f handler)
{
	int rc;
	u32 pay_size;
	u8 *pay;

	if (cp->cn_client.reply_handler != NULL) {
		(*free_unpacked)(rq, &cp->cn_pbc_allocator.protobuf_allocator);
		return -EAGAIN;
	}

	pay_size = (*get_packed_size)(rq);
	rc = gt_api_conn_add_request(cp, &pay, pay_size, snake_case);
	if (rc == 0) {
		(*pack)(rq, pay);
		rc = gt_api_conn_send(cp);
	}
	(*free_unpacked)(rq, &cp->cn_pbc_allocator.protobuf_allocator);

	if (rc == 0) {
		cp->cn_client.reply_handler = handler;
		cp->cn_client.is_dump = gt_strendswith(snake_case, "_dump");
	} else {
		gt_api_conn_close(cp);
	}

	return rc;
}

static int gt_api_exec_errnum;
static void *gt_api_exec_rp;
static gt_pb2_unpack_f gt_api_exec_unpack;

static int
gt_api_exec_api_handler(struct gt_api_conn *cp, u32 errnum, void *buf, u32 len)
{
	if (errnum) {
		gt_api_exec_errnum = errnum;
		return 0;
	}

	gt_api_exec_rp = (*gt_api_exec_unpack)(
		&cp->cn_pbc_allocator.protobuf_allocator, len, buf);
	if (gt_api_exec_rp == NULL) {
		gt_api_exec_errnum = EINVAL;
		return -EINVAL;
	} else {
		gt_api_exec_errnum = 0;
		return 0;
	}
}

int
gt_api__exec_request(struct gt_api_conn *cp, const char *snake_case, void **rp,
		     gt_pb2_unpack_f rep_unpack, void *rq,
		     gt_pb2_get_packed_size_f get_packed_size,
		     gt_pb2_pack_f req_pack,
		     gt_pb2_free_unpacked_f free_unpacked)
{
	int rc;

	gt_api_exec_errnum = -1;
	gt_api_exec_unpack = rep_unpack;

	rc = gt_api__send_request(cp, snake_case, rq, get_packed_size, req_pack,
				  free_unpacked, gt_api_exec_api_handler);
	if (rc) {
		return rc;
	}

	gt_api_exec_conn = cp;
	while (gt_api_exec_errnum < 0) {
		wait_for_fd_events();
	}
	gt_api_exec_conn = NULL;

	if (gt_api_exec_errnum == 0) {
		*rp = gt_api_exec_rp;
		return 0;
	} else {
		return gt_api_exec_errnum;
	}
}

int
gt_api_send_reply6(struct gt_api_conn *cp, void *rp, u32 errnum,
		   gt_pb2_get_packed_size_f get_packed_size, gt_pb2_pack_f pack,
		   gt_pb2_free_unpacked_f free_unpacked)
{
	int rc;
	u32 pay_size;
	u8 *pay;

	pay_size = (*get_packed_size)(rp);
	rc = gt_api_conn_add_reply(cp, &pay, pay_size, errnum);
	if (rc == 0) {
		(*pack)(rp, pay);
		rc = gt_api_conn_send(cp);
	}
	(*free_unpacked)(rp, &cp->cn_pbc_allocator.protobuf_allocator);

	if (rc && rc != -EAGAIN) {
		gt_api_conn_close(cp);
	}

	return rc;
}

int
gt_api_free_udata(struct gt_api_conn *cp)
{
	gt_a_free_internal(cp->cn_pbc_allocator.our_allocator,
			   gt_api_conn_get_udata(cp));
	return 0;
}

int
gt_api_nothing(struct gt_api_conn *cp)
{
	return 0;
}

int
gt_api__register_request(struct gt_api_conn *cp, const char *snake_case,
			 gt_api_request_handler_f req_handler,
			 gt_api_callback_f send_callback,
			 gt_api_callback_f free_callback)

{
	u8 is_dump;
	char req_name[GT_API_MSG_NAME_SIZE_MAX];
	struct gt_api_request *req;

	assert(free_callback != NULL);

	gt_api_make_request_name(req_name, snake_case);

	GT_DLIST_FOREACH(req, &cp->cn_request_head, req_link) {
		if (!strcmp(req->req_name, req_name)) {
			return -EEXIST;
		}
	}

	is_dump = gt_strendswith(snake_case, "_dump");
	if (!is_dump && send_callback != NULL) {
		GT_BUG0;
		return -EINVAL;
	}

	req = gt_a_malloc_align(cp->cn_pbc_allocator.our_allocator,
				sizeof(*req), GT_L1_CACHE_BYTES, 0);
	if (req == NULL) {
		return -ENOMEM;
	}

	req->req_is_dump = is_dump;
	gt_strzcpy(req->req_name, req_name, sizeof(req->req_name));
	req->req_handler = req_handler;
	req->req_send_callback = send_callback;
	req->req_free_callback = free_callback;

	GT_DLIST_INSERT_TAIL(&cp->cn_request_head, req, req_link);

	return 0;
}

static int
gt_api_server_after_handler(struct gt_api_conn *cp, int user_rc)
{
	int rc, errnum;
	u8 send;
	struct gt_api_request *req;

	if (!gt_api_conn_is_opened(cp)) {
		return -ECONNRESET;
	}

	send = rc = 0;
	req = cp->cn_server.req;
	if (req->req_is_dump) {
		if (user_rc == -EAGAIN) {
			return 0;
		}
		errnum = user_rc == 0 ? EAGAIN : -user_rc;
		rc = gt_api_conn_add_reply(cp, NULL, 0, errnum);
		send = 1;
	} else {
		if (user_rc < 0) {
			rc = gt_api_conn_add_reply(cp, NULL, 0, -user_rc);
			send = 1;
		}
	}

	if (send && rc == 0) {
		rc = gt_api_conn_send(cp);
	}

	gt_api_server_done(cp);

	return rc;
}

static struct gt_api_request *
gt_api_conn_find_request(struct gt_api_conn *cp, const char *req_name)
{
	struct gt_api_request *req;

	GT_DLIST_FOREACH(req, &cp->cn_request_head, req_link) {
		if (!strcmp(req->req_name, req_name)) {
			return req;
		}
	}

	if (cp->cn_listener != NULL) {
		return gt_api_conn_find_request(cp->cn_listener, req_name);
	}

	return NULL;
}

static int
gt_api_conn_recv_request(struct gt_api_conn *cp, struct gt_api_header *ah,
			 size_t size)
{
	int rc, msg_size;
	u32 pay_size;
	u8 *pay;
	char *req_name;
	struct gt_api_request *req;

	if (cp->cn_server.req != NULL) {
		return -EBUSY;
	}

	pay_size = ntoh32(ah->ah_payload_size);
	if (pay_size >= GT_API_BUF_SIZE_MAX) {
		return -EINVAL;
	}

	req_name = (char *)(ah + 1);
	rc = gt_api_parse_request_name(req_name, size - sizeof(*ah));
	if (rc < 0) {
		return rc;
	}

	msg_size = sizeof(*ah) + rc + pay_size;
	pay = (u8 *)ah + msg_size - pay_size;

	if (size < msg_size) {
		return -EAGAIN;
	}

	req = gt_api_conn_find_request(cp, req_name);
	if (req == NULL) {
		return -ESRCH;
	}

	cp->cn_server.req = req;

	rc = (*req->req_handler)(cp, pay, pay_size);
	assert(rc <= 0);

	rc = gt_api_server_after_handler(cp, rc);
	if (rc) {
		return rc;
	}

	return msg_size;
}

static int
gt_api_conn_recv_reply(struct gt_api_conn *cp, struct gt_api_header *ah,
		       size_t size)
{
	int rc, msg_size;
	u16 errnum;
	u32 pay_size;
	u8 *pay;

	if (cp->cn_client.reply_handler == NULL) {
		return -EINVAL;
	}

	pay_size = ntoh32(ah->ah_payload_size);
	if (pay_size >= GT_API_BUF_SIZE_MAX) {
		return -EINVAL;
	}

	errnum = ntoh16(ah->ah_code);

	msg_size = sizeof(*ah) + pay_size;
	pay = (u8 *)(ah + 1);

	if (size < msg_size) {
		return -EAGAIN;
	}

	rc = (cp->cn_client.reply_handler)(cp, errnum, pay, pay_size);
	assert(rc <= 0);
	if (rc) {
		return rc;
	}

	if (cp->cn_client.is_dump == 0 || errnum) {
		cp->cn_client.reply_handler = NULL;
	}

	return msg_size;
}

static int
gt_api_conn_recv(struct gt_api_conn *cp, size_t off)
{
	int size;
	u16 type;
	struct gt_api_header *ah;

	size = gt_vec_size(cp->cn_rcvbuf) - off;

	if (size < sizeof(*ah)) {
		return -EAGAIN;
	}

	ah = (struct gt_api_header *)(cp->cn_rcvbuf + off);
	type = ntoh16(ah->ah_type);
	switch (type) {
	case GT_API_MSG_TYPE_REQUEST:
		return gt_api_conn_recv_request(cp, ah, size);

	case GT_API_MSG_TYPE_REPLY:
		return gt_api_conn_recv_reply(cp, ah, size);

	default:
		return -EINVAL;
	}
}

static void
gt_api_conn_process(struct gt_deferred_entry *de)
{
	int rc;
	size_t off;
	struct gt_api_conn *cp;

	cp = container_of(de, struct gt_api_conn, cn_deferred_entry);

	off = 0;
	while (1) {
		rc = gt_api_conn_recv(cp, off);
		if (rc < 0) {
			if (rc == -EAGAIN) {
				break;
			} else {
				gt_api_conn_close(cp);
				gt_api_conn_free(cp);
				return;
			}
		}

		off += rc;
	}

	gt_vec_pop_front(cp->cn_rcvbuf, cp->cn_pbc_allocator.our_allocator,
			 off);
}

static int
gt_api_conn_handler(void *udata, short events, struct gt_dlist *deferred)
{
	int rc;
	size_t size;
	struct gt_api_conn *cp;

	cp = udata;

	if (GT_FLAG_ISSET(events, POLLOUT)) {
		cp->cn_throttled = 0;
		fd_event_clear(cp->cn_event, POLLOUT);

		gt_api_conn_send(cp);

		if (cp->cn_throttled == 0 && cp->cn_server.req != NULL &&
		    cp->cn_server.req->req_send_callback != NULL) {
			rc = (*cp->cn_server.req->req_send_callback)(cp);
			rc = gt_api_server_after_handler(cp, rc);
			if (rc) {
				goto err;
			}
		}
	}

	if (!GT_FLAG_ISSET(events, POLLIN)) {
		return 0;
	}

	size = gt_vec_size(cp->cn_rcvbuf);
	if (size == GT_API_BUF_SIZE_MAX) {
		goto err;
	}
	rc = gt_vec_reserve(cp->cn_rcvbuf, cp->cn_pbc_allocator.our_allocator,
			    GT_API_BUF_SIZE_MAX);
	if (rc < 0) {
		goto err;
	}

	rc = sys_read(cp->cn_fd, cp->cn_rcvbuf + size,
		      GT_API_BUF_SIZE_MAX - size);
	if (rc < 0) {
		if (rc == -EAGAIN) {
			return 0;
		} else {
			goto err;
		}
	} else if (rc == 0) {
		goto err;
	}

	gt_vec_resize(cp->cn_rcvbuf, cp->cn_pbc_allocator.our_allocator,
		      size + rc, 0);

	gt_deferred_add(deferred, &cp->cn_deferred_entry, gt_api_conn_process);

	return 0;

err:
	gt_api_conn_close(cp);
	gt_api_conn_free(cp);
	return 0;
}

static int
gt_api_accept(void *udata, short events, struct gt_dlist *dh)
{
	int rc, fd;
	struct gt_api_conn *cp, *new_cp;

	cp = udata;
	rc = sys_accept4(cp->cn_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (rc < 0) {
		return 0;
	}
	fd = rc;

	rc = fcntl_setfl_nonblock(fd, NULL);
	if (rc) {
		goto err;
	}

	// Inherit the listener's allocator: an accepted connection's own
	// memory comes from the same place as the listener's.
	new_cp = gt_api_conn_alloc(cp->cn_pbc_allocator.our_allocator);
	if (new_cp == NULL) {
		goto err;
	}

	new_cp->cn_listener = cp;
	rc = gt_api_conn_open(new_cp, fd, gt_api_conn_handler);
	if (rc) {
		gt_api_conn_free(new_cp);
		goto err;
	}

	return 0;

err:
	sys_close(fd);
	return 0;
}

int
gt_api_client_connect(struct gt_api_conn *cp, const char *sock_path)
{
	int rc, fd;
	u64 to;
	struct sockaddr_un sun;

	rc = sys_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	gt_strzcpy(sun.sun_path, sock_path, sizeof(sun.sun_path));

	to = 2 * GT_NSEC_PER_SEC;
	rc = gt_connect_timed(fd, (struct sockaddr *)&sun, sizeof(sun), &to);
	if (rc < 0) {
		goto err;
	}

	rc = fcntl_setfl_nonblock(fd, NULL);
	if (rc) {
		goto err;
	}

	rc = gt_api_conn_open(cp, fd, gt_api_conn_handler);
	if (rc) {
		goto err;
	}

	return 0;

err:
	sys_close(fd);
	return rc;
}

static int
gt_api_echo_api_handler(struct gt_api_conn *cp, Gt__ApiEcho *rq)
{
	Gt__ApiEchoReply *rp;

	rp = gt_api_alloc_reply(cp, rp, api_echo);
	if (rp == NULL) {
		return -ENOMEM;
	}

	rp->data = gt_pbc_strdup(cp, rq->data);
	if (rp->data == NULL) {
		return -ENOMEM;
	}

	return gt_api_send_reply(cp, rp, api_echo);
}

GT_API_SERVER_DEFINE_HANDLER(api_echo, gt_api_echo_api_handler)

struct gt_api_echo_data {
	u32 i, n;
	char *string;
};

static int
gt_api_echo_details_send(struct gt_api_conn *cp)
{
	int rc;
	struct gt_api_echo_data *e;
	Gt__ApiEchoDetails *rp;

	e = gt_api_conn_get_udata(cp);

	for (; e->i < e->n; ++e->i) {
		rp = gt_api_alloc_details(cp, rp, api_echo);
		if (rp == NULL) {
			return -ENOMEM;
		}

		rp->data = gt_pbc_strdup(cp, e->string);
		if (rp->data == NULL) {
			return -ENOMEM;
		}

		rc = gt_api_send_details(cp, rp, api_echo);
		if (rc) {
			return rc;
		}
	}

	return 0;
}

static int
gt_api_echo_details_done(struct gt_api_conn *cp)
{
	struct gt_api_echo_data *e;

	e = gt_api_conn_get_udata(cp);
	if (e != NULL) {
		gt_a_free_internal(cp->cn_pbc_allocator.our_allocator,
				   e->string);
		gt_a_free_internal(cp->cn_pbc_allocator.our_allocator, e);
	}

	return 0;
}

static int
gt_api_echo_dump_api_handler(struct gt_api_conn *cp, Gt__ApiEchoDump *rq)
{
	struct gt_api_echo_data *e;

	e = gt_a_malloc_align(cp->cn_pbc_allocator.our_allocator, sizeof(*e),
			      GT_L1_CACHE_BYTES, 0);
	if (e == NULL) {
		return -ENOMEM;
	}
	e->string = gt_pbc_strdup(cp, rq->data);
	if (e->string == NULL) {
		gt_a_free_internal(cp->cn_pbc_allocator.our_allocator, e);
		return -ENOMEM;
	}

	e->i = 0;
	e->n = rq->n_details;

	gt_api_conn_set_udata(cp, e);

	return gt_api_echo_details_send(cp);
}

GT_API_SERVER_DEFINE_HANDLER(api_echo_dump, gt_api_echo_dump_api_handler)

void
gt_api_server_init(struct gt_api_conn *cp, struct gt_allocator *alc)
{
	gt_api_conn_init(cp, alc);

	gt_api_register_request(cp, api_echo);
	gt_api_register_dump(cp, api_echo_dump, gt_api_echo_details_send,
			     gt_api_echo_details_done);
}

int
gt_api_server_start(struct gt_api_conn *cp)
{
	int rc, fd;
	struct sockaddr_un sun;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	gt_strzcpy(sun.sun_path, GT_API_SOCK_PATH, sizeof(sun.sun_path));

	rc = sys_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;

	sys_unlink(sun.sun_path);
	rc = sys_bind(fd, (const struct sockaddr *)&sun, sizeof(sun));
	if (rc < 0) {
		goto err;
	}

	rc = sys_listen(fd, 5);
	if (rc < 0) {
		goto err;
	}

	rc = fcntl_setfl_nonblock(fd, NULL);
	if (rc) {
		goto err;
	}

	rc = gt_api_conn_open(cp, fd, gt_api_accept);
	if (rc) {
		goto err;
	}

	return 0;

err:
	sys_close(fd);
	return rc;
}
