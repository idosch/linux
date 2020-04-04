/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2018 Mellanox Technologies. All rights reserved */

#ifndef _MLXSW_SPECTRUM_SPAN_H
#define _MLXSW_SPECTRUM_SPAN_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/refcount.h>

#include "spectrum_router.h"

struct mlxsw_sp;
struct mlxsw_sp_port;

struct mlxsw_sp_span_parms {
	struct mlxsw_sp_port *dest_port; /* NULL for unoffloaded SPAN. */
	unsigned int ttl;
	unsigned char dmac[ETH_ALEN];
	unsigned char smac[ETH_ALEN];
	union mlxsw_sp_l3addr daddr;
	union mlxsw_sp_l3addr saddr;
	u16 vid;
};

struct mlxsw_sp_span_entry_ops;

struct mlxsw_sp_span_entry {
	const struct net_device *to_dev;
	const struct mlxsw_sp_span_entry_ops *ops;
	struct mlxsw_sp_span_parms parms;
	refcount_t ref_count;
	int id;
};

struct mlxsw_sp_span_entry_ops {
	bool (*can_handle)(const struct net_device *to_dev);
	int (*parms)(const struct net_device *to_dev,
		     struct mlxsw_sp_span_parms *sparmsp);
	int (*configure)(struct mlxsw_sp_span_entry *span_entry,
			 struct mlxsw_sp_span_parms sparms);
	void (*deconfigure)(struct mlxsw_sp_span_entry *span_entry);
};

#endif
