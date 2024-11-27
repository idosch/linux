// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <linux/bpf_trace.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <net/xdp.h>

#include "pci.h"
#include "pci_xdp.h"

static void
mlxsw_xdp_frags_init(struct xdp_buff *xdp_buff,
		     const struct mlxsw_pci_rx_pkt_info *rx_pkt_info)
{
	struct skb_shared_info *skb_shared_info;
	int i;

	skb_shared_info = xdp_get_shared_info_from_buff(xdp_buff);
	skb_shared_info->nr_frags = 0;
	skb_shared_info->xdp_frags_size = 0;

	for (i = 1; i < rx_pkt_info->num_sg_entries; i++) {
		unsigned int frag_size;
		struct page *page;
		skb_frag_t *frag;

		page = rx_pkt_info->pages[i];
		frag_size = rx_pkt_info->sg_entries_size[i];

		if (!xdp_buff_has_frags(xdp_buff))
			xdp_buff_set_frags_flag(xdp_buff);

		frag = &skb_shared_info->frags[skb_shared_info->nr_frags++];
		skb_frag_fill_page_desc(frag, page, 0, frag_size);

		if (page_is_pfmemalloc(page))
			xdp_buff_set_frag_pfmemalloc(xdp_buff);

		skb_shared_info->xdp_frags_size += frag_size;
	}
}

void mlxsw_xdp_buff_init(struct xdp_buff *xdp_buff,
			 const struct mlxsw_pci_rx_pkt_info *rx_pkt_info,
			 struct xdp_rxq_info *xdp_rxq)
{
	void *page_addr;

	page_addr = page_address(rx_pkt_info->pages[0]);

	xdp_init_buff(xdp_buff, PAGE_SIZE, xdp_rxq);
	xdp_prepare_buff(xdp_buff, page_addr, MLXSW_PCI_RX_BUF_HEADROOM,
			 rx_pkt_info->sg_entries_size[0], false);

	mlxsw_xdp_frags_init(xdp_buff, rx_pkt_info);
}

enum mlxsw_xdp_status
mlxsw_xdp_run(struct xdp_buff *xdp_buff, struct bpf_prog *prog,
	      struct net_device *netdev)
{
	u32 act;

	act = bpf_prog_run_xdp(prog, xdp_buff);
	switch (act) {
	case XDP_ABORTED:
		break;
	case XDP_DROP:
		return MLXSW_XDP_STATUS_DROP;
	case XDP_PASS:
		return MLXSW_XDP_STATUS_PASS;
	default:
		bpf_warn_invalid_xdp_action(netdev, prog, act);
	}

	trace_xdp_exception(netdev, prog, act);
	return MLXSW_XDP_STATUS_FAIL;
}
