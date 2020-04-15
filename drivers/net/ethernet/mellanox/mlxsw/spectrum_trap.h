/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2020 Mellanox Technologies. All rights reserved */

#ifndef _MLXSW_SPECTRUM_TRAP_H
#define _MLXSW_SPECTRUM_TRAP_H

#include <linux/list.h>
#include <net/devlink.h>

struct mlxsw_sp_trap {
	struct devlink_trap_policer *policers_arr; /* Registered policers */
	u64 policers_count; /* Number of registered policers */
	struct list_head policer_item_list;
	u64 max_policers;
	unsigned long policers_usage[]; /* Usage bitmap */
};

struct mlxsw_sp_trap_policer_item {
	u16 hw_id;
	u32 id;
	struct list_head list; /* Member of policer_item_list */
};

struct mlxsw_sp_trap_group_item {
	struct devlink_trap_group trap_group;
	u16 hw_group_id;
	u8 priority;
	u8 tc;
	u8 valid:1;
};

#define MLXSW_SP_LISTENERS_MAX 3

struct mlxsw_sp_trap_item {
	struct devlink_trap trap;
	struct mlxsw_listener listeners_arr[MLXSW_SP_LISTENERS_MAX];
	size_t listeners_count;
};

struct mlxsw_sp_trap_ops {
	int (*groups_init)(struct mlxsw_sp *mlxsw_sp);
	int (*traps_init)(struct mlxsw_sp *mlxsw_sp);
};

extern const struct mlxsw_sp_trap_ops mlxsw_sp1_trap_ops;
extern const struct mlxsw_sp_trap_ops mlxsw_sp2_trap_ops;

#endif
