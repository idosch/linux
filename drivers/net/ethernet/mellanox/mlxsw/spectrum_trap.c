// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019 Mellanox Technologies. All rights reserved */

#include <linux/kernel.h>
#include <linux/list.h>
#include <net/devlink.h>
#include <uapi/linux/devlink.h>

#include "core.h"
#include "reg.h"
#include "spectrum.h"

struct mlxsw_sp_trap_core {
	const struct devlink_trap *traps_arr;
	const struct mlxsw_listener *listeners_arr;
	const u16 *listener_devlink_map;
	struct mlxsw_sp *mlxsw_sp;
	unsigned int traps_count;
	unsigned int listeners_count;
	struct list_head trap_items_list; /* Protected by devlink locking */
};

struct mlxsw_sp_trap_item {
	struct list_head list; /* Member of trap_items_list */
	struct list_head listener_items_list;
	struct mlxsw_sp_trap_core *trap_core;
	const struct mlxsw_sp_trap_item_ops *ops;
	const struct devlink_trap *trap;
	void *trap_ctx;
};

struct mlxsw_sp_listener_item {
	struct list_head list; /* Member of listener_items_list */
	const struct mlxsw_listener *listener;
};

struct mlxsw_sp_trap_item_ops {
	int (*init)(struct mlxsw_sp_trap_item *trap_item);
	void (*fini)(struct mlxsw_sp_trap_item *trap_item);
	int (*action_set)(struct mlxsw_sp_trap_item *trap_item,
			  enum devlink_trap_action action);
};

/* All driver-specific traps must be documented in
 * Documentation/networking/devlink/mlxsw.rst
 */
enum {
	DEVLINK_MLXSW_TRAP_ID_BASE = DEVLINK_TRAP_GENERIC_ID_MAX,
	DEVLINK_MLXSW_TRAP_ID_IRIF_DISABLED,
	DEVLINK_MLXSW_TRAP_ID_ERIF_DISABLED,
};

#define DEVLINK_MLXSW_TRAP_NAME_IRIF_DISABLED \
	"irif_disabled"
#define DEVLINK_MLXSW_TRAP_NAME_ERIF_DISABLED \
	"erif_disabled"

#define MLXSW_SP_TRAP_METADATA DEVLINK_TRAP_METADATA_TYPE_F_IN_PORT

static int mlxsw_sp_rx_listener(struct mlxsw_sp *mlxsw_sp, struct sk_buff *skb,
				u8 local_port,
				struct mlxsw_sp_port *mlxsw_sp_port)
{
	struct mlxsw_sp_port_pcpu_stats *pcpu_stats;

	if (unlikely(!mlxsw_sp_port)) {
		dev_warn_ratelimited(mlxsw_sp->bus_info->dev, "Port %d: skb received for non-existent port\n",
				     local_port);
		kfree_skb(skb);
		return -EINVAL;
	}

	skb->dev = mlxsw_sp_port->dev;

	pcpu_stats = this_cpu_ptr(mlxsw_sp_port->pcpu_stats);
	u64_stats_update_begin(&pcpu_stats->syncp);
	pcpu_stats->rx_packets++;
	pcpu_stats->rx_bytes += skb->len;
	u64_stats_update_end(&pcpu_stats->syncp);

	skb->protocol = eth_type_trans(skb, skb->dev);

	return 0;
}

static void mlxsw_sp_rx_drop_listener(struct sk_buff *skb, u8 local_port,
				      void *trap_ctx)
{
	struct devlink_port *in_devlink_port;
	struct mlxsw_sp_port *mlxsw_sp_port;
	struct mlxsw_sp *mlxsw_sp;
	struct devlink *devlink;
	int err;

	mlxsw_sp = devlink_trap_ctx_priv(trap_ctx);
	mlxsw_sp_port = mlxsw_sp->ports[local_port];

	err = mlxsw_sp_rx_listener(mlxsw_sp, skb, local_port, mlxsw_sp_port);
	if (err)
		return;

	devlink = priv_to_devlink(mlxsw_sp->core);
	in_devlink_port = mlxsw_core_port_devlink_port_get(mlxsw_sp->core,
							   local_port);
	skb_push(skb, ETH_HLEN);
	devlink_trap_report(devlink, skb, trap_ctx, in_devlink_port, NULL);
	consume_skb(skb);
}

static void mlxsw_sp_rx_acl_drop_listener(struct sk_buff *skb, u8 local_port,
					  void *trap_ctx)
{
	u32 cookie_index = mlxsw_skb_cb(skb)->cookie_index;
	const struct flow_action_cookie *fa_cookie;
	struct devlink_port *in_devlink_port;
	struct mlxsw_sp_port *mlxsw_sp_port;
	struct mlxsw_sp *mlxsw_sp;
	struct devlink *devlink;
	int err;

	mlxsw_sp = devlink_trap_ctx_priv(trap_ctx);
	mlxsw_sp_port = mlxsw_sp->ports[local_port];

	err = mlxsw_sp_rx_listener(mlxsw_sp, skb, local_port, mlxsw_sp_port);
	if (err)
		return;

	devlink = priv_to_devlink(mlxsw_sp->core);
	in_devlink_port = mlxsw_core_port_devlink_port_get(mlxsw_sp->core,
							   local_port);
	skb_push(skb, ETH_HLEN);
	rcu_read_lock();
	fa_cookie = mlxsw_sp_acl_act_cookie_lookup(mlxsw_sp, cookie_index);
	devlink_trap_report(devlink, skb, trap_ctx, in_devlink_port, fa_cookie);
	rcu_read_unlock();
	consume_skb(skb);
}

static void mlxsw_sp_rx_exception_listener(struct sk_buff *skb, u8 local_port,
					   void *trap_ctx)
{
	struct devlink_port *in_devlink_port;
	struct mlxsw_sp_port *mlxsw_sp_port;
	struct mlxsw_sp *mlxsw_sp;
	struct devlink *devlink;
	int err;

	mlxsw_sp = devlink_trap_ctx_priv(trap_ctx);
	mlxsw_sp_port = mlxsw_sp->ports[local_port];

	err = mlxsw_sp_rx_listener(mlxsw_sp, skb, local_port, mlxsw_sp_port);
	if (err)
		return;

	devlink = priv_to_devlink(mlxsw_sp->core);
	in_devlink_port = mlxsw_core_port_devlink_port_get(mlxsw_sp->core,
							   local_port);
	skb_push(skb, ETH_HLEN);
	devlink_trap_report(devlink, skb, trap_ctx, in_devlink_port, NULL);
	skb_pull(skb, ETH_HLEN);
	skb->offload_fwd_mark = 1;
	netif_receive_skb(skb);
}

#define MLXSW_SP_TRAP_DROP(_id, _group_id)				      \
	DEVLINK_TRAP_GENERIC(DROP, DROP, _id,				      \
			     DEVLINK_TRAP_GROUP_GENERIC(_group_id),	      \
			     MLXSW_SP_TRAP_METADATA)

#define MLXSW_SP_TRAP_DROP_EXT(_id, _group_id, _metadata)		      \
	DEVLINK_TRAP_GENERIC(DROP, DROP, _id,				      \
			     DEVLINK_TRAP_GROUP_GENERIC(_group_id),	      \
			     MLXSW_SP_TRAP_METADATA | (_metadata))

#define MLXSW_SP_TRAP_DRIVER_DROP(_id, _group_id)			      \
	DEVLINK_TRAP_DRIVER(DROP, DROP, DEVLINK_MLXSW_TRAP_ID_##_id,	      \
			    DEVLINK_MLXSW_TRAP_NAME_##_id,		      \
			    DEVLINK_TRAP_GROUP_GENERIC(_group_id),	      \
			    MLXSW_SP_TRAP_METADATA)

#define MLXSW_SP_TRAP_EXCEPTION(_id, _group_id)		      \
	DEVLINK_TRAP_GENERIC(EXCEPTION, TRAP, _id,			      \
			     DEVLINK_TRAP_GROUP_GENERIC(_group_id),	      \
			     MLXSW_SP_TRAP_METADATA)

#define MLXSW_SP_RXL_DISCARD(_id, _group_id)				      \
	MLXSW_RXL_DIS(mlxsw_sp_rx_drop_listener, DISCARD_##_id,		      \
		      TRAP_EXCEPTION_TO_CPU, false, SP_##_group_id,	      \
		      SET_FW_DEFAULT, SP_##_group_id)

#define MLXSW_SP_RXL_ACL_DISCARD(_id, _en_group_id, _dis_group_id)	      \
	MLXSW_RXL_DIS(mlxsw_sp_rx_acl_drop_listener, DISCARD_##_id,	      \
		      TRAP_EXCEPTION_TO_CPU, false, SP_##_en_group_id,	      \
		      SET_FW_DEFAULT, SP_##_dis_group_id)

#define MLXSW_SP_RXL_EXCEPTION(_id, _group_id, _action)			      \
	MLXSW_RXL(mlxsw_sp_rx_exception_listener, _id,			      \
		   _action, false, SP_##_group_id, SET_FW_DEFAULT)

static const struct devlink_trap mlxsw_sp_traps_arr[] = {
	MLXSW_SP_TRAP_DROP(SMAC_MC, L2_DROPS),
	MLXSW_SP_TRAP_DROP(VLAN_TAG_MISMATCH, L2_DROPS),
	MLXSW_SP_TRAP_DROP(INGRESS_VLAN_FILTER, L2_DROPS),
	MLXSW_SP_TRAP_DROP(INGRESS_STP_FILTER, L2_DROPS),
	MLXSW_SP_TRAP_DROP(EMPTY_TX_LIST, L2_DROPS),
	MLXSW_SP_TRAP_DROP(PORT_LOOPBACK_FILTER, L2_DROPS),
	MLXSW_SP_TRAP_DROP(BLACKHOLE_ROUTE, L3_DROPS),
	MLXSW_SP_TRAP_DROP(NON_IP_PACKET, L3_DROPS),
	MLXSW_SP_TRAP_DROP(UC_DIP_MC_DMAC, L3_DROPS),
	MLXSW_SP_TRAP_DROP(DIP_LB, L3_DROPS),
	MLXSW_SP_TRAP_DROP(SIP_MC, L3_DROPS),
	MLXSW_SP_TRAP_DROP(SIP_LB, L3_DROPS),
	MLXSW_SP_TRAP_DROP(CORRUPTED_IP_HDR, L3_DROPS),
	MLXSW_SP_TRAP_DROP(IPV4_SIP_BC, L3_DROPS),
	MLXSW_SP_TRAP_DROP(IPV6_MC_DIP_RESERVED_SCOPE, L3_DROPS),
	MLXSW_SP_TRAP_DROP(IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE, L3_DROPS),
	MLXSW_SP_TRAP_EXCEPTION(MTU_ERROR, L3_DROPS),
	MLXSW_SP_TRAP_EXCEPTION(TTL_ERROR, L3_DROPS),
	MLXSW_SP_TRAP_EXCEPTION(RPF, L3_DROPS),
	MLXSW_SP_TRAP_EXCEPTION(REJECT_ROUTE, L3_DROPS),
	MLXSW_SP_TRAP_EXCEPTION(UNRESOLVED_NEIGH, L3_DROPS),
	MLXSW_SP_TRAP_EXCEPTION(IPV4_LPM_UNICAST_MISS, L3_DROPS),
	MLXSW_SP_TRAP_EXCEPTION(IPV6_LPM_UNICAST_MISS, L3_DROPS),
	MLXSW_SP_TRAP_DRIVER_DROP(IRIF_DISABLED, L3_DROPS),
	MLXSW_SP_TRAP_DRIVER_DROP(ERIF_DISABLED, L3_DROPS),
	MLXSW_SP_TRAP_DROP(NON_ROUTABLE, L3_DROPS),
	MLXSW_SP_TRAP_EXCEPTION(DECAP_ERROR, TUNNEL_DROPS),
	MLXSW_SP_TRAP_DROP(OVERLAY_SMAC_MC, TUNNEL_DROPS),
	MLXSW_SP_TRAP_DROP_EXT(INGRESS_FLOW_ACTION_DROP, ACL_DROPS,
			       DEVLINK_TRAP_METADATA_TYPE_F_FA_COOKIE),
	MLXSW_SP_TRAP_DROP_EXT(EGRESS_FLOW_ACTION_DROP, ACL_DROPS,
			       DEVLINK_TRAP_METADATA_TYPE_F_FA_COOKIE),
};

static const struct mlxsw_listener mlxsw_sp_listeners_arr[] = {
	MLXSW_SP_RXL_DISCARD(ING_PACKET_SMAC_MC, L2_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_SWITCH_VTAG_ALLOW, L2_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_SWITCH_VLAN, L2_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_SWITCH_STP, L2_DISCARDS),
	MLXSW_SP_RXL_DISCARD(LOOKUP_SWITCH_UC, L2_DISCARDS),
	MLXSW_SP_RXL_DISCARD(LOOKUP_SWITCH_MC_NULL, L2_DISCARDS),
	MLXSW_SP_RXL_DISCARD(LOOKUP_SWITCH_LB, L2_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ROUTER2, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_ROUTER_NON_IP_PACKET, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_ROUTER_UC_DIP_MC_DMAC, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_ROUTER_DIP_LB, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_ROUTER_SIP_MC, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_ROUTER_SIP_LB, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_ROUTER_CORRUPTED_IP_HDR, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ING_ROUTER_IPV4_SIP_BC, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(IPV6_MC_DIP_RESERVED_SCOPE, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE, L3_DISCARDS),
	MLXSW_SP_RXL_EXCEPTION(MTUERROR, ROUTER_EXP, TRAP_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(TTLERROR, ROUTER_EXP, TRAP_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(RPF, RPF, TRAP_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(RTR_INGRESS1, REMOTE_ROUTE, TRAP_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(HOST_MISS_IPV4, HOST_MISS, TRAP_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(HOST_MISS_IPV6, HOST_MISS, TRAP_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(DISCARD_ROUTER3, REMOTE_ROUTE,
			       TRAP_EXCEPTION_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(DISCARD_ROUTER_LPM4, ROUTER_EXP,
			       TRAP_EXCEPTION_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(DISCARD_ROUTER_LPM6, ROUTER_EXP,
			       TRAP_EXCEPTION_TO_CPU),
	MLXSW_SP_RXL_DISCARD(ROUTER_IRIF_EN, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(ROUTER_ERIF_EN, L3_DISCARDS),
	MLXSW_SP_RXL_DISCARD(NON_ROUTABLE, L3_DISCARDS),
	MLXSW_SP_RXL_EXCEPTION(DECAP_ECN0, ROUTER_EXP, TRAP_EXCEPTION_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(IPIP_DECAP_ERROR, ROUTER_EXP,
			       TRAP_EXCEPTION_TO_CPU),
	MLXSW_SP_RXL_EXCEPTION(DISCARD_DEC_PKT, TUNNEL_DISCARDS,
			       TRAP_EXCEPTION_TO_CPU),
	MLXSW_SP_RXL_DISCARD(OVERLAY_SMAC_MC, TUNNEL_DISCARDS),
	MLXSW_SP_RXL_ACL_DISCARD(INGRESS_ACL, ACL_DISCARDS, DUMMY),
	MLXSW_SP_RXL_ACL_DISCARD(EGRESS_ACL, ACL_DISCARDS, DUMMY),
};

/* Mapping between hardware trap and devlink trap. Multiple hardware traps can
 * be mapped to the same devlink trap. Order is according to
 * 'mlxsw_sp_listeners_arr'.
 */
static const u16 mlxsw_sp_listener_devlink_map[] = {
	DEVLINK_TRAP_GENERIC_ID_SMAC_MC,
	DEVLINK_TRAP_GENERIC_ID_VLAN_TAG_MISMATCH,
	DEVLINK_TRAP_GENERIC_ID_INGRESS_VLAN_FILTER,
	DEVLINK_TRAP_GENERIC_ID_INGRESS_STP_FILTER,
	DEVLINK_TRAP_GENERIC_ID_EMPTY_TX_LIST,
	DEVLINK_TRAP_GENERIC_ID_EMPTY_TX_LIST,
	DEVLINK_TRAP_GENERIC_ID_PORT_LOOPBACK_FILTER,
	DEVLINK_TRAP_GENERIC_ID_BLACKHOLE_ROUTE,
	DEVLINK_TRAP_GENERIC_ID_NON_IP_PACKET,
	DEVLINK_TRAP_GENERIC_ID_UC_DIP_MC_DMAC,
	DEVLINK_TRAP_GENERIC_ID_DIP_LB,
	DEVLINK_TRAP_GENERIC_ID_SIP_MC,
	DEVLINK_TRAP_GENERIC_ID_SIP_LB,
	DEVLINK_TRAP_GENERIC_ID_CORRUPTED_IP_HDR,
	DEVLINK_TRAP_GENERIC_ID_IPV4_SIP_BC,
	DEVLINK_TRAP_GENERIC_ID_IPV6_MC_DIP_RESERVED_SCOPE,
	DEVLINK_TRAP_GENERIC_ID_IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE,
	DEVLINK_TRAP_GENERIC_ID_MTU_ERROR,
	DEVLINK_TRAP_GENERIC_ID_TTL_ERROR,
	DEVLINK_TRAP_GENERIC_ID_RPF,
	DEVLINK_TRAP_GENERIC_ID_REJECT_ROUTE,
	DEVLINK_TRAP_GENERIC_ID_UNRESOLVED_NEIGH,
	DEVLINK_TRAP_GENERIC_ID_UNRESOLVED_NEIGH,
	DEVLINK_TRAP_GENERIC_ID_UNRESOLVED_NEIGH,
	DEVLINK_TRAP_GENERIC_ID_IPV4_LPM_UNICAST_MISS,
	DEVLINK_TRAP_GENERIC_ID_IPV6_LPM_UNICAST_MISS,
	DEVLINK_MLXSW_TRAP_ID_IRIF_DISABLED,
	DEVLINK_MLXSW_TRAP_ID_ERIF_DISABLED,
	DEVLINK_TRAP_GENERIC_ID_NON_ROUTABLE,
	DEVLINK_TRAP_GENERIC_ID_DECAP_ERROR,
	DEVLINK_TRAP_GENERIC_ID_DECAP_ERROR,
	DEVLINK_TRAP_GENERIC_ID_DECAP_ERROR,
	DEVLINK_TRAP_GENERIC_ID_OVERLAY_SMAC_MC,
	DEVLINK_TRAP_GENERIC_ID_INGRESS_FLOW_ACTION_DROP,
	DEVLINK_TRAP_GENERIC_ID_EGRESS_FLOW_ACTION_DROP,
};

static int
mlxsw_sp_trap_item_default_init(struct mlxsw_sp_trap_item *trap_item)
{
	struct mlxsw_sp *mlxsw_sp = trap_item->trap_core->mlxsw_sp;
	struct mlxsw_sp_listener_item *listener_item;
	int err;

	list_for_each_entry(listener_item, &trap_item->listener_items_list,
			    list) {
		err = mlxsw_core_trap_register(mlxsw_sp->core,
					       listener_item->listener,
					       trap_item->trap_ctx);
		if (err)
			goto err_trap_register;
	}

	return 0;

err_trap_register:
	list_for_each_entry_continue_reverse(listener_item,
					     &trap_item->listener_items_list,
					     list)
		mlxsw_core_trap_unregister(mlxsw_sp->core,
					   listener_item->listener,
					   trap_item->trap_ctx);
	return err;
}

static void
mlxsw_sp_trap_item_default_fini(struct mlxsw_sp_trap_item *trap_item)
{
	struct mlxsw_sp *mlxsw_sp = trap_item->trap_core->mlxsw_sp;
	struct mlxsw_sp_listener_item *listener_item;

	list_for_each_entry(listener_item, &trap_item->listener_items_list,
			    list)
		mlxsw_core_trap_unregister(mlxsw_sp->core,
					   listener_item->listener,
					   trap_item->trap_ctx);
}

static int
mlxsw_sp_trap_item_default_action_set(struct mlxsw_sp_trap_item *trap_item,
				      enum devlink_trap_action action)
{
	struct mlxsw_sp *mlxsw_sp = trap_item->trap_core->mlxsw_sp;
	struct mlxsw_sp_listener_item *listener_item;
	bool enabled;
	int err;

	switch (action) {
	case DEVLINK_TRAP_ACTION_DROP:
		enabled = false;
		break;
	case DEVLINK_TRAP_ACTION_TRAP:
		enabled = true;
		break;
	default:
		return -EINVAL;
	}

	list_for_each_entry(listener_item, &trap_item->listener_items_list,
			    list) {
		err = mlxsw_core_trap_state_set(mlxsw_sp->core,
						listener_item->listener,
						enabled);
		if (err)
			goto err_trap_state_set;
	}

	return 0;

err_trap_state_set:
	list_for_each_entry_continue_reverse(listener_item,
					     &trap_item->listener_items_list,
					     list)
		mlxsw_core_trap_state_set(mlxsw_sp->core,
					  listener_item->listener, !enabled);
	return err;
}

static const struct mlxsw_sp_trap_item_ops mlxsw_sp_trap_item_default_ops = {
	.init			= mlxsw_sp_trap_item_default_init,
	.fini			= mlxsw_sp_trap_item_default_fini,
	.action_set		= mlxsw_sp_trap_item_default_action_set,
};

#define MLXSW_SP_DISCARD_POLICER_ID	(MLXSW_REG_HTGT_TRAP_GROUP_MAX + 1)
#define MLXSW_SP_THIN_POLICER_ID	(MLXSW_SP_DISCARD_POLICER_ID + 1)

static int mlxsw_sp_trap_cpu_policers_set(struct mlxsw_sp *mlxsw_sp)
{
	char qpcr_pl[MLXSW_REG_QPCR_LEN];
	int err;

	mlxsw_reg_qpcr_pack(qpcr_pl, MLXSW_SP_DISCARD_POLICER_ID,
			    MLXSW_REG_QPCR_IR_UNITS_M, false, 10 * 1024, 7);
	err = mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(qpcr), qpcr_pl);
	if (err)
		return err;

	/* The purpose of "thin" policer is to drop as many packets
	 * as possible. The dummy group is using it.
	 */
	mlxsw_reg_qpcr_pack(qpcr_pl, MLXSW_SP_THIN_POLICER_ID,
			    MLXSW_REG_QPCR_IR_UNITS_M, false, 1, 4);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(qpcr), qpcr_pl);
}

static int mlxsw_sp_trap_dummy_group_init(struct mlxsw_sp *mlxsw_sp)
{
	char htgt_pl[MLXSW_REG_HTGT_LEN];

	mlxsw_reg_htgt_pack(htgt_pl, MLXSW_REG_HTGT_TRAP_GROUP_SP_DUMMY,
			    MLXSW_SP_THIN_POLICER_ID, 0, 1);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(htgt), htgt_pl);
}

int mlxsw_sp_devlink_traps_init(struct mlxsw_sp *mlxsw_sp)
{
	struct devlink *devlink = priv_to_devlink(mlxsw_sp->core);
	struct mlxsw_sp_trap_core *trap_core;
	int err;

	err = mlxsw_sp_trap_cpu_policers_set(mlxsw_sp);
	if (err)
		return err;

	err = mlxsw_sp_trap_dummy_group_init(mlxsw_sp);
	if (err)
		return err;

	if (WARN_ON(ARRAY_SIZE(mlxsw_sp_listener_devlink_map) !=
		    ARRAY_SIZE(mlxsw_sp_listeners_arr)))
		return -EINVAL;

	trap_core = kzalloc(sizeof(*trap_core), GFP_KERNEL);
	if (!trap_core)
		return -ENOMEM;
	mlxsw_sp->trap_core = trap_core;
	trap_core->mlxsw_sp = mlxsw_sp;
	INIT_LIST_HEAD(&trap_core->trap_items_list);

	trap_core->traps_arr = mlxsw_sp_traps_arr;
	trap_core->traps_count = ARRAY_SIZE(mlxsw_sp_traps_arr);
	trap_core->listeners_arr = mlxsw_sp_listeners_arr;
	trap_core->listener_devlink_map = mlxsw_sp_listener_devlink_map;
	trap_core->listeners_count = ARRAY_SIZE(mlxsw_sp_listeners_arr);

	err = devlink_traps_register(devlink, trap_core->traps_arr,
				     trap_core->traps_count, mlxsw_sp);
	if (err)
		goto err_traps_register;

	return 0;

err_traps_register:
	kfree(trap_core);
	return err;
}

void mlxsw_sp_devlink_traps_fini(struct mlxsw_sp *mlxsw_sp)
{
	struct devlink *devlink = priv_to_devlink(mlxsw_sp->core);

	devlink_traps_unregister(devlink, mlxsw_sp->trap_core->traps_arr,
				 mlxsw_sp->trap_core->traps_count);
	WARN_ON(!list_empty(&mlxsw_sp->trap_core->trap_items_list));
	kfree(mlxsw_sp->trap_core);
}

static struct mlxsw_sp_trap_item *
mlxsw_sp_trap_item_lookup(struct mlxsw_sp *mlxsw_sp,
			  const struct devlink_trap *trap)
{
	struct mlxsw_sp_trap_core *trap_core = mlxsw_sp->trap_core;
	struct mlxsw_sp_trap_item *trap_item;

	list_for_each_entry(trap_item, &trap_core->trap_items_list, list) {
		if (trap_item->trap->id == trap->id)
			return trap_item;
	}

	return NULL;
}

static int
mlxsw_sp_trap_item_listeners_init(struct mlxsw_sp *mlxsw_sp,
				  struct mlxsw_sp_trap_item *trap_item)
{
	struct mlxsw_sp_trap_core *trap_core = mlxsw_sp->trap_core;
	struct mlxsw_sp_listener_item *listener_item, *tmp_item;
	int i;

	INIT_LIST_HEAD(&trap_item->listener_items_list);

	for (i = 0; i < trap_core->listeners_count; i++) {
		const struct mlxsw_listener *listener;

		if (trap_core->listener_devlink_map[i] != trap_item->trap->id)
			continue;
		listener = &trap_core->listeners_arr[i];

		listener_item = kzalloc(sizeof(*listener_item), GFP_KERNEL);
		if (!listener_item)
			goto err_listener_item_alloc;

		listener_item->listener = listener;
		list_add_tail(&listener_item->list,
			      &trap_item->listener_items_list);
	}

	return 0;

err_listener_item_alloc:
	list_for_each_entry_safe(listener_item, tmp_item,
				 &trap_item->listener_items_list, list) {
		list_del(&listener_item->list);
		kfree(listener_item);
	}
	return -ENOMEM;
}

static void
mlxsw_sp_trap_item_listeners_fini(struct mlxsw_sp_trap_item *trap_item)
{
	struct mlxsw_sp_listener_item *listener_item, *tmp_item;

	list_for_each_entry_safe(listener_item, tmp_item,
				 &trap_item->listener_items_list, list) {
		list_del(&listener_item->list);
		kfree(listener_item);
	}
	WARN_ON(!list_empty(&trap_item->listener_items_list));
}

static struct mlxsw_sp_trap_item *
mlxsw_sp_trap_item_create(struct mlxsw_sp *mlxsw_sp,
			  const struct devlink_trap *trap, void *trap_ctx)
{
	struct mlxsw_sp_trap_item *trap_item;
	int err;

	trap_item = kzalloc(sizeof(*trap_item), GFP_KERNEL);
	if (!trap_item)
		return ERR_PTR(-ENOMEM);
	trap_item->trap_core = mlxsw_sp->trap_core;
	trap_item->ops = &mlxsw_sp_trap_item_default_ops;
	trap_item->trap = trap;
	trap_item->trap_ctx = trap_ctx;

	err = mlxsw_sp_trap_item_listeners_init(mlxsw_sp, trap_item);
	if (err)
		goto err_listeners_init;

	list_add_tail(&trap_item->list, &mlxsw_sp->trap_core->trap_items_list);

	return trap_item;

err_listeners_init:
	kfree(trap_item);
	return ERR_PTR(err);
}

static void mlxsw_sp_trap_item_destroy(struct mlxsw_sp_trap_item *trap_item)
{
	list_del(&trap_item->list);
	mlxsw_sp_trap_item_listeners_fini(trap_item);
	kfree(trap_item);
}

int mlxsw_sp_trap_init(struct mlxsw_core *mlxsw_core,
		       const struct devlink_trap *trap, void *trap_ctx)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_core_driver_priv(mlxsw_core);
	struct mlxsw_sp_trap_item *trap_item;
	int err;

	trap_item = mlxsw_sp_trap_item_create(mlxsw_sp, trap, trap_ctx);
	if (IS_ERR(trap_item))
		return PTR_ERR(trap_item);

	err = trap_item->ops->init(trap_item);
	if (err)
		goto err_trap_item_init;

	return 0;

err_trap_item_init:
	mlxsw_sp_trap_item_destroy(trap_item);
	return err;
}

void mlxsw_sp_trap_fini(struct mlxsw_core *mlxsw_core,
			const struct devlink_trap *trap, void *trap_ctx)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_core_driver_priv(mlxsw_core);
	struct mlxsw_sp_trap_item *trap_item;

	trap_item = mlxsw_sp_trap_item_lookup(mlxsw_sp, trap);
	if (WARN_ON(!trap_item))
		return;

	trap_item->ops->fini(trap_item);
	mlxsw_sp_trap_item_destroy(trap_item);
}

int mlxsw_sp_trap_action_set(struct mlxsw_core *mlxsw_core,
			     const struct devlink_trap *trap,
			     enum devlink_trap_action action)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_core_driver_priv(mlxsw_core);
	struct mlxsw_sp_trap_item *trap_item;

	trap_item = mlxsw_sp_trap_item_lookup(mlxsw_sp, trap);
	if (WARN_ON(!trap_item))
		return -EINVAL;

	return trap_item->ops->action_set(trap_item, action);
}

int mlxsw_sp_trap_group_init(struct mlxsw_core *mlxsw_core,
			     const struct devlink_trap_group *group)
{
	char htgt_pl[MLXSW_REG_HTGT_LEN];
	u8 priority, tc, group_id;
	u16 policer_id;

	switch (group->id) {
	case DEVLINK_TRAP_GROUP_GENERIC_ID_L2_DROPS:
		group_id = MLXSW_REG_HTGT_TRAP_GROUP_SP_L2_DISCARDS;
		policer_id = MLXSW_SP_DISCARD_POLICER_ID;
		priority = 0;
		tc = 1;
		break;
	case DEVLINK_TRAP_GROUP_GENERIC_ID_L3_DROPS:
		group_id = MLXSW_REG_HTGT_TRAP_GROUP_SP_L3_DISCARDS;
		policer_id = MLXSW_SP_DISCARD_POLICER_ID;
		priority = 0;
		tc = 1;
		break;
	case DEVLINK_TRAP_GROUP_GENERIC_ID_TUNNEL_DROPS:
		group_id = MLXSW_REG_HTGT_TRAP_GROUP_SP_TUNNEL_DISCARDS;
		policer_id = MLXSW_SP_DISCARD_POLICER_ID;
		priority = 0;
		tc = 1;
		break;
	case DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_DROPS:
		group_id = MLXSW_REG_HTGT_TRAP_GROUP_SP_ACL_DISCARDS;
		policer_id = MLXSW_SP_DISCARD_POLICER_ID;
		priority = 0;
		tc = 1;
		break;
	default:
		return -EINVAL;
	}

	mlxsw_reg_htgt_pack(htgt_pl, group_id, policer_id, priority, tc);
	return mlxsw_reg_write(mlxsw_core, MLXSW_REG(htgt), htgt_pl);
}
