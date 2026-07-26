// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/l2fwd/l2fwd.h>

#include <gbtcp/kernel/cli.h>
#include <gbtcp/kernel/inet.h>
#include <gbtcp/kernel/mm.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/node.h>
#include <gbtcp/kernel/route.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/sys.h>

#define gt_notice(...) gt_notice3(&gt_l2fwd_main->l2fwd_logger, ##__VA_ARGS__)
#define gt_err(...) gt_err3(&gt_l2fwd_main->l2fwd_logger, ##__VA_ARGS__)

struct gt_l2fwd_main *gt_l2fwd_main;

static int
gt_l2fwd_get_out_ifindex(int in_ifindex)
{
	int i;
	struct gt_l2fwd_pair *pair;

	for (i = 0; i < gt_l2fwd_main->l2fwd_n_pairs; ++i) {
		pair = gt_l2fwd_main->l2fwd_pairs + i;
		if (pair->l2fwd_in_ifindex == in_ifindex) {
			return pair->l2fwd_out_ifindex;
		}
	}
	return -1;
}

static int
gt_l2fwd_add_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	int rc, in_ifindex, out_ifindex;
	const char *in_ifname, *out_ifname;
	struct gt_cli_arg *arg;
	struct gt_l2fwd_pair *pair;

	in_ifname = NULL;
	out_ifname = NULL;
	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "in")) {
			in_ifname = arg->arg_value;
		} else if (!strcmp(arg->arg_name, "out")) {
			out_ifname = arg->arg_value;
		}
	}

	assert(in_ifname != NULL);
	assert(out_ifname != NULL);

	if (gt_l2fwd_main->l2fwd_n_pairs == GT_L2FWD_PAIR_MAX) {
		return -ENOSPC;
	}

	rc = sys_if_nametoindex(in_ifname);
	if (rc < 0) {
		return rc;
	}
	in_ifindex = rc;

	rc = sys_if_nametoindex(out_ifname);
	if (rc < 0) {
		return rc;
	}
	out_ifindex = rc;

	pair = gt_l2fwd_main->l2fwd_pairs + gt_l2fwd_main->l2fwd_n_pairs;
	pair->l2fwd_in_ifindex = in_ifindex;
	pair->l2fwd_out_ifindex = out_ifindex;
	gt_l2fwd_main->l2fwd_n_pairs++;

	gt_notice(0, "Forward %s -> %s", in_ifname, out_ifname);

	return 0;
}

int
gt_l2fwd_module_init(u8 module_id, void **puser)
{
	int rc;
	struct gt_l2fwd_main *mod;

	mod = gt_malloc(shm_cache(), sizeof(*mod), 0);
	if (mod == NULL) {
		return -ENOMEM;
	}
	memset(mod, 0, sizeof(*mod));

	gt_l2fwd_main = mod;
	mod->l2fwd_module_id = module_id;
	mod->l2fwd_n_pairs = 0;

	log_scope_init(&mod->l2fwd_logger, "l2fwd");

	gt_cli_register_command("l2fwd add", gt_l2fwd_add_cli_handler, NULL,
				"<in string> <out string>");

	rc = GT_WORKER_FUNC_REGISTER(module_id, rx, gt_l2fwd_module_rx,
				&mod->l2fwd_rx_fn);
	if (rc) {
		gt_l2fwd_module_deinit(mod);
		return rc;
	}

	*puser = mod;
	return 0;
}

int
gt_l2fwd_module_postinit(void *mod)
{
	return gt_add_rx_callback(&gt_l2fwd_main->l2fwd_rx_fn);
}

void
gt_l2fwd_module_deinit(void *user)
{
	gt_free_internal(shm_cache(), user);
}

void
gt_l2fwd_module_worker_start(void *m)
{
	gt_l2fwd_main = m;
}

void
gt_l2fwd_module_worker_stop(void)
{
	// gt_l2fwd_main is the shared module object used by every service-thread
	// in this process; clearing it on a per-thread detach would break
	// siblings. It is set idempotently in worker_attach.
}

// Receive a packet on `ifp` and put it out the paired device unchanged.
int
gt_l2fwd_module_rx(struct route_if *ifp, void *data, int len)
{
	int rc, out_ifindex;
	struct route_if *out_ifp;
	struct dev_pkt pkt;

	if (ifp == NULL) {
		return IN_DROP;
	}

	out_ifindex = gt_l2fwd_get_out_ifindex(ifp->rif_index);
	if (out_ifindex < 0) {
		return IN_DROP;
	}

	out_ifp = route_if_get_by_index(out_ifindex);
	if (out_ifp == NULL) {
		return IN_DROP;
	}

	rc = route_get_tx_packet(out_ifp, &pkt, TX_CAN_REDIRECT);
	if (rc) {
		// No free tx descriptor on the output device, drop.
		// TODO: increment drop counter
		return IN_DROP;
	}

	memcpy(pkt.pkt_data, data, len);
	pkt.pkt_len = len;
	route_transmit(out_ifp, &pkt);

	return IN_OK;
}
