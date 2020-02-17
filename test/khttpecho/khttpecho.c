#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/net.h>

#include <net/sock.h>

#define MODNAM "khttpecho"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Konstantin Kogdenko");

struct he_thr {
	struct workqueue_struct *ht_wq;
	struct work_struct ht_work;
	struct socket *ht_so;
	struct kmem_cache *ht_slab;
};

struct he_so {
	uint16_t hs_port;
	int hs_cpuid;
	struct he_thr *hs_thr;
	struct socket *hs_so;
	struct work_struct hs_work;
	void (*hs_data_ready)(struct sock *);
};

static const char http[] =
	"HTTP/1.0 200 OK\r\n"
	"Server: khttpecho\r\n"
	"Content-Type: text/html\r\n"
	"Connection: close\r\n"
	"Hi\r\n\r\n";
static char *httpbuf;
static int httplen;
static struct he_thr he_thr[NR_CPUS];

#if 1
#define D(fmt, ...)
#else
#define D(fmt, ...) \
	if (0) { \
		printk(MODNAM ": " fmt "\n", ##__VA_ARGS__); \
	}
#endif

#define Dl D("%d", __LINE__)

static int
he_socket(struct socket **pso)
{
	int rc;

	rc = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, pso);
	if (rc < 0) {
		D("sock_create() failed (%d)", -rc);
		return rc;
	}
	return 0;
}

static int
he_socket2(struct socket *so, struct socket **aso)
{
	int rc;

	rc = sock_create_lite(so->sk->sk_family, so->sk->sk_type,
	                      so->sk->sk_protocol, aso);
	if (rc < 0) {
		D("sock_create_lite() failed (%d)", -rc);
		return rc;
	}
	(*aso)->type = so->type;
	(*aso)->ops = so->ops;
	return 0;
}

static void
he_accept_ready(struct sock *sk)
{
	int cpuid;
	struct he_thr *t;

	read_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_state == TCP_LISTEN) {
		t = sk->sk_user_data;
		cpuid = smp_processor_id();
		D("accept_ready: cpu=%d", cpuid);
		queue_work_on(cpuid, t->ht_wq, &t->ht_work);
	} else {
		D("??????");
	}
	read_unlock_bh(&sk->sk_callback_lock);
}

static void
he_soqueue(struct he_so *s)
{
	queue_work_on(s->hs_cpuid, s->hs_thr->ht_wq, &s->hs_work);
}

static void
he_data_ready(struct sock *sk)
{
	struct he_so *s;
	void (*data_ready)(struct sock *);

	data_ready = NULL;
	read_lock_bh(&sk->sk_callback_lock);
	s = sk->sk_user_data;
	if (s == NULL) {
		data_ready = sk->sk_data_ready;
	} else {
		he_soqueue(s);
		D("data_ready: cpu=%d, port=%hu", smp_processor_id(), s->hs_port);
	}
	read_unlock_bh(&sk->sk_callback_lock);
	if (data_ready != NULL) {
		(*data_ready)(sk);
	}
}

static void
he_sodel(struct he_so *s)
{
	struct sock *sk;

	sk = s->hs_so->sk;
	write_lock_bh(&sk->sk_callback_lock);
	BUG_ON(sk->sk_user_data != s);
	sk->sk_user_data = NULL;
	sk->sk_data_ready = s->hs_data_ready;
	D("del: cpu=%d, port=%hu", smp_processor_id(), s->hs_port);
	write_unlock_bh(&sk->sk_callback_lock);
	sock_release(s->hs_so);
	kmem_cache_free(s->hs_thr->ht_slab, s);
}

static void
he_read(struct work_struct *w)
{
	int len;
	struct kvec vec;
	struct msghdr msg;
	struct sock *sk;
	struct he_so *s;
	char buf[128];

	s = container_of(w, struct he_so, hs_work);
	sk = s->hs_so->sk;
	if (s->hs_so->sk->sk_state == TCP_ESTABLISHED) {
		vec.iov_len = sizeof(buf);
		vec.iov_base = buf;
		msg.msg_flags = MSG_DONTWAIT;
		iov_iter_kvec(&msg.msg_iter, READ, &vec, 1, sizeof(buf));
		len = sock_recvmsg(s->hs_so, &msg, MSG_DONTWAIT);
		if (len > 0) {
			vec.iov_base = httpbuf;
			vec.iov_len = httplen;
			msg.msg_name = NULL;
			msg.msg_namelen = 0;
			msg.msg_control = NULL;
			msg.msg_controllen = 0;
			msg.msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL;
			kernel_sendmsg(s->hs_so, &msg, &vec, 1, vec.iov_len);
			kernel_sock_shutdown(s->hs_so, SHUT_RDWR);
			D("send: cpu=%d, port=%hu", smp_processor_id(), s->hs_port);
		}
	} else {
		he_sodel(s);
	}
}

static void
he_accept(struct work_struct *w)
{
	int rc, cpuid;
	uint16_t port;
	struct sockaddr_in sin;
	struct socket *aso;
	struct sock *sk;
	struct he_so *s;
	struct he_thr *t;

	t = container_of(w, struct he_thr, ht_work);
	while (1) {
		rc = he_socket2(t->ht_so, &aso);
		if (rc < 0) {
			break;
		}
		cpuid = smp_processor_id();
		D(">accept: cpu=%d", cpuid);
		rc = t->ht_so->ops->accept(t->ht_so, aso, O_NONBLOCK, true);
		if (rc < 0) {
			goto err;
		}
		sk = aso->sk;
		write_lock_bh(&sk->sk_callback_lock);
		rc = aso->ops->getname(aso, (struct sockaddr *)&sin, sizeof(sin));
		if (rc < 0) {
			goto err1;
		}
		port = ntohs(sin.sin_port);
		D("accept ok: port=%hu", port);
		s = kmem_cache_alloc(t->ht_slab, GFP_ATOMIC);
		if (s == NULL) {
			printk("Fail\n");
			goto err1;
		}
		s->hs_port = port;
		s->hs_so = aso;
		s->hs_thr = t;
		s->hs_cpuid = cpuid;
		INIT_WORK(&s->hs_work, he_read);
		sk->sk_user_data = s;
		s->hs_data_ready = sk->sk_data_ready;
		aso->sk->sk_data_ready = he_data_ready;
		write_unlock_bh(&aso->sk->sk_callback_lock);
		he_soqueue(s);
	}
	return;
err1:
	write_unlock_bh(&aso->sk->sk_callback_lock);
err:
	sock_release(aso);	
}


static void
he_cleanup(void)
{
	int i;
	struct he_thr *t;

	D("stopped");
	for (i = 0; i < num_online_cpus(); ++i) {
		t = he_thr + i;
		if (t->ht_so != NULL) {
			sock_release(t->ht_so);
			t->ht_so = NULL;
		}
		if (t->ht_wq != NULL) {
			destroy_workqueue(t->ht_wq);
			t->ht_wq = NULL;
		}
		if (t->ht_slab != NULL) {
			kmem_cache_destroy(t->ht_slab);
			t->ht_slab = NULL;
		}
	}
}

static int __init
he_init(void)
{
	int i, rc, opt, ncpus;
	char slabnam[64];
	struct he_thr *t;
	struct sockaddr_in sin;
	struct socket *so;

	httplen = strlen(http);
	httpbuf = kmalloc(httplen, GFP_KERNEL);
	if (httpbuf == NULL) {
		return 0;
	}
	memcpy(httpbuf, http, httplen);
	ncpus = num_online_cpus();
	D("started %d %d", ncpus, NR_CPUS);
	for (i = 0; i < ncpus; ++i) {
		t = he_thr + i;
		t->ht_wq = alloc_workqueue(MODNAM, 0, 512);
		if (t->ht_wq == NULL) {
			goto err;
		}
		INIT_WORK(&t->ht_work, he_accept);
		snprintf(slabnam, sizeof(slabnam), "%s-%d", MODNAM, i);
		t->ht_slab = kmem_cache_create(slabnam, sizeof(struct he_so),
		                               0, SLAB_HWCACHE_ALIGN, NULL);
		printk("slap %p\n", t->ht_slab);
		if (t->ht_slab == NULL) {
			goto err;
		}
		rc = he_socket(&so);
		if (rc < 0) {
			goto err;
		}
		opt = 1;
		rc = kernel_setsockopt(so, SOL_SOCKET, SO_REUSEADDR,
		                       (void *)&opt, sizeof(opt));
		if (rc < 0) {
			goto err;
		}
		opt = 1;
		rc = kernel_setsockopt(so, SOL_SOCKET, SO_REUSEPORT,
		                       (void *)&opt, sizeof(opt));
		if (rc < 0) {
			goto err;
		}
		write_lock_bh(&so->sk->sk_callback_lock);
		so->sk->sk_data_ready = he_accept_ready;
		so->sk->sk_user_data = t;
		write_unlock_bh(&so->sk->sk_callback_lock);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = htons(9000);
		rc = so->ops->bind(so, (struct sockaddr *)&sin, sizeof(sin));
		if (rc < 0) {
			D("bind() failed (%d)", -rc);
			goto err;
		}
		t->ht_so = so;
		rc = so->ops->listen(so, 512);
		if (rc < 0) {
			D("listen() failed (%d)", -rc);
			goto err;
		}
		D("ok %p", t->ht_slab);
	}
	return 0;
err:
	he_cleanup();
	return 0;
}

static void __exit
he_exit(void)
{
	he_cleanup();
}

module_init(he_init)
module_exit(he_exit)
