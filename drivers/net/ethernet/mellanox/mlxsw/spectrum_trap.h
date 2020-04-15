/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2020 Mellanox Technologies. All rights reserved */

#ifndef _MLXSW_SPECTRUM_TRAP_H
#define _MLXSW_SPECTRUM_TRAP_H

#include <linux/list.h>
#include <net/devlink.h>

struct mlxsw_sp_trap {
	struct mlxsw_sp_trap_policer_item *policer_items_arr;
	u64 policers_count; /* Number of registered policers */

	struct mlxsw_sp_trap_group_item *group_items_arr;
	u64 groups_count; /* Number of registered groups */

	/* ASIC-specific trap groups */
	const struct mlxsw_sp_trap_group_item *specific_group_items_arr;
	u64 specific_groups_count;

	struct mlxsw_sp_trap_item *trap_items_arr;
	u64 traps_count; /* Number of registered traps */

	u64 max_policers;
	unsigned long policers_usage[]; /* Usage bitmap */
};

struct mlxsw_sp_trap_ops {
	int (*groups_init)(struct mlxsw_sp *mlxsw_sp);
};

extern const struct mlxsw_sp_trap_ops mlxsw_sp1_trap_ops;
extern const struct mlxsw_sp_trap_ops mlxsw_sp2_trap_ops;

#endif
