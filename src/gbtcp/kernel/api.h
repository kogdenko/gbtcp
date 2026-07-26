// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_API_H
#define GBTCP_API_H

#include <protobuf-c/protobuf-c.h>

#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/list.h>
#include <gbtcp/kernel/subr.h>

#define gt_api_alloc_msg(cp, msg, snake_case) \
	({ \
		if (((msg) = gt_pbc_alloc( \
			     &(cp)->cn_pbc_allocator.protobuf_allocator, \
			     sizeof(*(msg)))) != NULL) { \
			gt__##snake_case##__init(msg); \
		} \
		msg; \
	})

#define gt_api_alloc_request(cp, request, snake_case) \
	gt_api_alloc_msg(cp, request, snake_case)

#define gt_api_alloc_dump(cp, dump, snake_case) \
	gt_api_alloc_msg(cp, dump, snake_case##_dump)

#define gt_api_alloc_details(cp, details, snake_case) \
	gt_api_alloc_msg(cp, details, snake_case##_details)

#define gt_api_alloc_reply(cp, reply, snake_case) \
	gt_api_alloc_msg(cp, reply, snake_case##_reply)

#define gt_api_free_msg(cp, msg, snake_case) \
	if (msg != NULL) { \
		gt__##snake_case##__free_unpacked( \
			msg, &(cp)->cn_pbc_allocator.protobuf_allocator); \
	}

#define gt_api_free_request(cp, request, snake_case) \
	gt_api_free_msg(cp, request, snake_case)

#define gt_api_free_dump(cp, dump, snake_case) \
	gt_api_free_msg(cp, dump, snake_case##_dump)

#define gt_api_free_details(cp, details, snake_case) \
	gt_api_free_msg(cp, details, snake_case##_details)

#define gt_api_send_request(cp, rq, snake_case) \
	gt_api__send_request( \
		cp, #snake_case, rq, \
		(gt_pb2_get_packed_size_f)gt__##snake_case##__get_packed_size, \
		(gt_pb2_pack_f)gt__##snake_case##__pack, \
		(gt_pb2_free_unpacked_f)gt__##snake_case##__free_unpacked, \
		gt__##snake_case##_reply_api_handler)

#define gt_api_exec_request(cp, rp, rq, snake_case) \
	gt_api__exec_request( \
		cp, #snake_case, (void **)&rp, \
		(gt_pb2_unpack_f)gt__##snake_case##_reply__unpack, rq, \
		(gt_pb2_get_packed_size_f)gt__##snake_case##__get_packed_size, \
		(gt_pb2_pack_f)gt__##snake_case##__pack, \
		(gt_pb2_free_unpacked_f)gt__##snake_case##__free_unpacked)

#define gt_api_send_dump(cp, rq, snake_case) \
	gt_api__send_request(cp, #snake_case "_dump", rq, \
			     (gt_pb2_get_packed_size_f) \
				     gt__##snake_case##_dump__get_packed_size, \
			     (gt_pb2_pack_f)gt__##snake_case##_dump__pack, \
			     (gt_pb2_free_unpacked_f) \
				     gt__##snake_case##_dump__free_unpacked, \
			     gt__##snake_case##_details_api_handler)

#define gt_api_send_reply(cp, rp, snake_case) \
	gt_api_send_reply6(cp, rp, 0, \
			   (gt_pb2_get_packed_size_f) \
				   gt__##snake_case##_reply__get_packed_size, \
			   (gt_pb2_pack_f)gt__##snake_case##_reply__pack, \
			   (gt_pb2_free_unpacked_f) \
				   gt__##snake_case##_reply__free_unpacked)

#define gt_api_send_details(cp, rp, snake_case) \
	gt_api_send_reply6( \
		cp, rp, 0, \
		(gt_pb2_get_packed_size_f) \
			gt__##snake_case##_details__get_packed_size, \
		(gt_pb2_pack_f)gt__##snake_case##_details__pack, \
		(gt_pb2_free_unpacked_f) \
			gt__##snake_case##_details__free_unpacked)

#define gt_api_register_request(cp, snake_case) \
	gt_api__register_request(cp, #snake_case, \
				 gt__##snake_case##_api_handler, NULL, \
				 gt_api_nothing)

#define gt_api_register_dump(cp, snake_case, on_send, on_free) \
	gt_api__register_request(cp, #snake_case, \
				 gt__##snake_case##_api_handler, on_send, \
				 on_free)

#define GT_API_SERVER_DEFINE_HANDLER(snake_case, handler) \
	static int gt__##snake_case##_api_handler(struct gt_api_conn *cp, \
						  void *buf, u32 len) \
	{ \
		int rc; \
		void *rq; \
\
		rq = gt__##snake_case##__unpack( \
			&cp->cn_pbc_allocator.protobuf_allocator, len, buf); \
		if (rq == NULL) { \
			return -EINVAL; \
		} \
\
		rc = (*handler)(cp, rq); \
		gt__##snake_case##__free_unpacked( \
			rq, &cp->cn_pbc_allocator.protobuf_allocator); \
\
		return rc; \
	}

#define GT_API_CLIENT_DEFINE_HANDLER(snake_case, handler) \
	static int gt__##snake_case##_api_handler( \
		struct gt_api_conn *cp, u32 errnum, void *buf, u32 len) \
	{ \
		int rc; \
		void *rp; \
\
		if (errnum) { \
			rc = (*handler)(cp, errnum, NULL); \
			return rc; \
		} \
\
		rp = gt__##snake_case##__unpack( \
			&cp->cn_pbc_allocator.protobuf_allocator, len, buf); \
		if (rp == NULL) { \
			return -EINVAL; \
		} \
\
		rc = (*handler)(cp, 0, rp); \
		gt__##snake_case##__free_unpacked( \
			rp, &cp->cn_pbc_allocator.protobuf_allocator); \
		return rc; \
	}

struct fd_event;
struct gt_allocator;
struct gt_api_conn;
struct gt_api_request;

typedef size_t (*gt_pb2_get_packed_size_f)(void *message);
typedef size_t (*gt_pb2_pack_f)(const void *message, u8 *out);
typedef void *(*gt_pb2_unpack_f)(ProtobufCAllocator *allocator, size_t len,
				 const u8 *data);
typedef void (*gt_pb2_free_unpacked_f)(void *message,
				       ProtobufCAllocator *allocator);

typedef int (*gt_api_callback_f)(struct gt_api_conn *cp);
typedef int (*gt_api_reply_handler_f)(struct gt_api_conn *cp, u32 errnum,
				      void *buf, u32 len);
typedef int (*gt_api_request_handler_f)(struct gt_api_conn *cp, void *buf,
					u32 len);

struct gt_pbc_allocator {
	ProtobufCAllocator protobuf_allocator;
	struct gt_allocator *our_allocator;
};

struct gt_api_conn_client {
	u8 is_dump;
	gt_api_reply_handler_f reply_handler;
};

struct gt_api_conn_server {
	struct gt_api_request *req;
};

struct gt_api_conn {
	int cn_fd;
	struct fd_event *cn_event;

	// protobuf_allocator.alloc/free are gt_pbc_alloc()/gt_pbc_free();
	// our_allocator is where cn_rcvbuf/cn_sndbuf/cn_request_head entries
	// and (for a heap-allocated conn) the struct itself come from — set
	// once, at gt_api_conn_alloc()/gt_api_conn_init(), by whichever
	// caller knows its own context (attached service vs. unattached
	// utility tool). Unpack/pack/free_unpacked calls scoped to this conn
	// pass &cn_pbc_allocator.protobuf_allocator directly, instead of
	// resolving an allocator ambiently via gt_get_allocator() on every
	// call.
	struct gt_pbc_allocator cn_pbc_allocator;

	struct gt_api_conn *cn_listener;

	u8 cn_throttled;
	u8 *cn_rcvbuf;
	u8 *cn_sndbuf;

	void *cn_udata;

	// TODO: use htable
	// TODO: request timer
	struct gt_dlist cn_request_head;

	gt_api_callback_f cn_close_callback;

	struct gt_deferred_entry cn_deferred_entry;

	struct gt_api_conn_server cn_server;
	struct gt_api_conn_client cn_client;
};

void *gt_pbc_alloc(void *allocator_data, size_t size);
void gt_pbc_free(void *allocator_data, void *pointer);
char *gt_pbc_strdup(struct gt_api_conn *cp, const char *s);

struct gt_api_conn *gt_api_conn_alloc(struct gt_allocator *alc);
void gt_api_conn_free(struct gt_api_conn *cp);
void gt_api_conn_init(struct gt_api_conn *cp, struct gt_allocator *alc);

int gt_api_conn_get_fd(struct gt_api_conn *cp);

u8 gt_api_conn_is_opened(struct gt_api_conn *cp);

void gt_api__conn_close(struct gt_api_conn *cp);
#define gt_api_conn_close(cp) ({ gt_api__conn_close(cp); })

void *gt_api_conn_get_udata(struct gt_api_conn *cp);
void gt_api_conn_set_udata(struct gt_api_conn *cp, void *udata);
void gt_api_conn_set_close_handler(struct gt_api_conn *cp,
				   gt_api_callback_f fn);

int gt_api__send_request(struct gt_api_conn *cp, const char *snake_case,
			 void *rq, gt_pb2_get_packed_size_f get_packed_size,
			 gt_pb2_pack_f req_pack,
			 gt_pb2_free_unpacked_f free_unpacked,
			 gt_api_reply_handler_f reply_handler);

int gt_api__exec_request(struct gt_api_conn *cp, const char *snake_case,
			 void **rp, gt_pb2_unpack_f rep_unpack, void *rq,
			 gt_pb2_get_packed_size_f get_packed_size,
			 gt_pb2_pack_f req_pack,
			 gt_pb2_free_unpacked_f free_unpacked);

int gt_api_send_reply6(struct gt_api_conn *cp, void *rp, u32 errnum,
		       gt_pb2_get_packed_size_f get_packed_size,
		       gt_pb2_pack_f pack,
		       gt_pb2_free_unpacked_f free_unpacked);

int gt_api_free_udata(struct gt_api_conn *cp);
int gt_api_nothing(struct gt_api_conn *cp);

int gt_api__register_request(struct gt_api_conn *cp, const char *name,
			     gt_api_request_handler_f req_handler,
			     gt_api_callback_f send_callback,
			     gt_api_callback_f free_callback);

int gt_api_client_connect(struct gt_api_conn *cp, const char *sock_path);

extern struct gt_api_conn gt_main_conn;

void gt_api_server_init(struct gt_api_conn *cp, struct gt_allocator *alc);

int gt_api_server_start(struct gt_api_conn *cp);

#endif
