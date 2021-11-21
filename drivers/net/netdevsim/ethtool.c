// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include <linux/debugfs.h>
#include <linux/ethtool.h>
#include <linux/ethtool_netlink.h>
#include <linux/firmware.h>
#include <linux/random.h>

#include "netdevsim.h"

static void
nsim_get_pause_stats(struct net_device *dev,
		     struct ethtool_pause_stats *pause_stats)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (ns->ethtool.pauseparam.report_stats_rx)
		pause_stats->rx_pause_frames = 1;
	if (ns->ethtool.pauseparam.report_stats_tx)
		pause_stats->tx_pause_frames = 2;
}

static void
nsim_get_pauseparam(struct net_device *dev, struct ethtool_pauseparam *pause)
{
	struct netdevsim *ns = netdev_priv(dev);

	pause->autoneg = 0; /* We don't support ksettings, so can't pretend */
	pause->rx_pause = ns->ethtool.pauseparam.rx;
	pause->tx_pause = ns->ethtool.pauseparam.tx;
}

static int
nsim_set_pauseparam(struct net_device *dev, struct ethtool_pauseparam *pause)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (pause->autoneg)
		return -EINVAL;

	ns->ethtool.pauseparam.rx = pause->rx_pause;
	ns->ethtool.pauseparam.tx = pause->tx_pause;
	return 0;
}

static int nsim_get_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	memcpy(coal, &ns->ethtool.coalesce, sizeof(ns->ethtool.coalesce));
	return 0;
}

static int nsim_set_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	memcpy(&ns->ethtool.coalesce, coal, sizeof(ns->ethtool.coalesce));
	return 0;
}

static void nsim_get_ringparam(struct net_device *dev,
			       struct ethtool_ringparam *ring,
			       struct kernel_ethtool_ringparam *kernel_ring,
			       struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	memcpy(ring, &ns->ethtool.ring, sizeof(ns->ethtool.ring));
}

static int nsim_set_ringparam(struct net_device *dev,
			      struct ethtool_ringparam *ring,
			      struct kernel_ethtool_ringparam *kernel_ring,
			      struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	memcpy(&ns->ethtool.ring, ring, sizeof(ns->ethtool.ring));
	return 0;
}

static void
nsim_get_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct netdevsim *ns = netdev_priv(dev);

	ch->max_combined = ns->nsim_bus_dev->num_queues;
	ch->combined_count = ns->ethtool.channels;
}

static int
nsim_set_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct netdevsim *ns = netdev_priv(dev);
	int err;

	err = netif_set_real_num_queues(dev, ch->combined_count,
					ch->combined_count);
	if (err)
		return err;

	ns->ethtool.channels = ch->combined_count;
	return 0;
}

static int
nsim_get_fecparam(struct net_device *dev, struct ethtool_fecparam *fecparam)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (ns->ethtool.get_err)
		return -ns->ethtool.get_err;
	memcpy(fecparam, &ns->ethtool.fec, sizeof(ns->ethtool.fec));
	return 0;
}

static int
nsim_set_fecparam(struct net_device *dev, struct ethtool_fecparam *fecparam)
{
	struct netdevsim *ns = netdev_priv(dev);
	u32 fec;

	if (ns->ethtool.set_err)
		return -ns->ethtool.set_err;
	memcpy(&ns->ethtool.fec, fecparam, sizeof(ns->ethtool.fec));
	fec = fecparam->fec;
	if (fec == ETHTOOL_FEC_AUTO)
		fec |= ETHTOOL_FEC_OFF;
	fec |= ETHTOOL_FEC_NONE;
	ns->ethtool.fec.active_fec = 1 << (fls(fec) - 1);
	return 0;
}

static int nsim_get_module_fw_info(struct net_device *dev,
				   struct ethtool_module_fw_info *info,
				   struct netlink_ext_ack *extack)
{
	info->type = ETHTOOL_MODULE_FW_INFO_TYPE_CMIS;

	info->cmis.a_present = true;
	info->cmis.a.running = true;
	info->cmis.a.committed = true;
	info->cmis.a.valid = true;
	info->cmis.a.ver_major = 1;
	info->cmis.a.ver_minor = 2;
	info->cmis.a.ver_build = 3;
	strcpy(info->cmis.a.ver_extra_str, "test");

	info->cmis.b_present = true;
	info->cmis.b.running = false;
	info->cmis.b.committed = false;
	info->cmis.b.valid = true;
	info->cmis.b.ver_major = 5;
	info->cmis.b.ver_minor = 6;
	info->cmis.b.ver_build = 7;

	info->cmis.factory_present = true;
	info->cmis.factory.running = false;
	info->cmis.factory.committed = false;
	info->cmis.factory.valid = true;
	info->cmis.factory.ver_major = 11;
	info->cmis.factory.ver_minor = 12;
	info->cmis.factory.ver_build = 13;

	return 0;
}

static void nsim_module_fw_flash_download(struct netdevsim *ns)
{
	struct ethtool_module_fw_flash_ntf_params params = {};

	params.status = ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS;
	params.status_msg = "Downloading firmware image";
	params.done = 0;
	params.total = 1500;
	ethnl_module_fw_flash_ntf(ns->netdev, &params);

	msleep(5000);

	params.done = 750;
	ethnl_module_fw_flash_ntf(ns->netdev, &params);

	msleep(5000);

	params.done = 1500;
	ethnl_module_fw_flash_ntf(ns->netdev, &params);

	msleep(5000);
}

static void nsim_module_fw_flash_validate(struct netdevsim *ns)
{
	struct ethtool_module_fw_flash_ntf_params params = {};

	params.status = ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS;
	params.status_msg = "Validating firmware image download";
	ethnl_module_fw_flash_ntf(ns->netdev, &params);

	msleep(5000);
}

static void nsim_module_fw_flash_run(struct netdevsim *ns)
{
	struct ethtool_module_fw_flash_ntf_params params = {};

	params.status = ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS;
	params.status_msg = "Running firmware image";
	ethnl_module_fw_flash_ntf(ns->netdev, &params);

	msleep(5000);
}

static void nsim_module_fw_flash_commit(struct netdevsim *ns)
{
	struct ethtool_module_fw_flash_ntf_params params = {};

	if (!ns->ethtool.module_fw.params.commit)
		return;

	params.status = ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS;
	params.status_msg = "Committing firmware image";
	ethnl_module_fw_flash_ntf(ns->netdev, &params);

	msleep(5000);
}

static void nsim_module_fw_flash(struct work_struct *work)
{
	struct ethtool_module_fw_flash_ntf_params params = {};
	struct netdevsim *ns;

	ns = container_of(work, struct netdevsim, ethtool.module_fw.work);

	params.status = ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED;
	ethnl_module_fw_flash_ntf(ns->netdev, &params);

	if (!ns->ethtool.module_fw.fw)
		goto commit;

	nsim_module_fw_flash_download(ns);
	nsim_module_fw_flash_validate(ns);
	nsim_module_fw_flash_run(ns);
commit:
	nsim_module_fw_flash_commit(ns);

	params.status = ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED;
	ethnl_module_fw_flash_ntf(ns->netdev, &params);

	dev_put(ns->netdev);
	rtnl_lock();
	ns->ethtool.module_fw.in_progress = false;
	rtnl_unlock();
	release_firmware(ns->ethtool.module_fw.fw);
}

static int
nsim_start_fw_flash_module(struct net_device *dev,
			   const struct ethtool_module_fw_flash_params *params,
			   struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (ns->ethtool.module_fw.in_progress) {
		NL_SET_ERR_MSG(extack, "Module firmware flashing already in progress");
		return -EBUSY;
	}

	ns->ethtool.module_fw.fw = NULL;
	if (params->file_name) {
		int err;

		err = request_firmware(&ns->ethtool.module_fw.fw,
				       params->file_name, &dev->dev);
		if (err) {
			NL_SET_ERR_MSG(extack,
				       "Failed to request module firmware image");
			return err;
		}
	}

	ns->ethtool.module_fw.in_progress = true;
	dev_hold(dev);
	ns->ethtool.module_fw.params = *params;
	schedule_work(&ns->ethtool.module_fw.work);

	return 0;
}

static const struct ethtool_ops nsim_ethtool_ops = {
	.supported_coalesce_params	= ETHTOOL_COALESCE_ALL_PARAMS,
	.get_pause_stats	        = nsim_get_pause_stats,
	.get_pauseparam		        = nsim_get_pauseparam,
	.set_pauseparam		        = nsim_set_pauseparam,
	.set_coalesce			= nsim_set_coalesce,
	.get_coalesce			= nsim_get_coalesce,
	.get_ringparam			= nsim_get_ringparam,
	.set_ringparam			= nsim_set_ringparam,
	.get_channels			= nsim_get_channels,
	.set_channels			= nsim_set_channels,
	.get_fecparam			= nsim_get_fecparam,
	.set_fecparam			= nsim_set_fecparam,
	.get_module_fw_info		= nsim_get_module_fw_info,
	.start_fw_flash_module		= nsim_start_fw_flash_module,
};

static void nsim_ethtool_ring_init(struct netdevsim *ns)
{
	ns->ethtool.ring.rx_max_pending = 4096;
	ns->ethtool.ring.rx_jumbo_max_pending = 4096;
	ns->ethtool.ring.rx_mini_max_pending = 4096;
	ns->ethtool.ring.tx_max_pending = 4096;
}

void nsim_ethtool_init(struct netdevsim *ns)
{
	struct dentry *ethtool, *dir;

	ns->netdev->ethtool_ops = &nsim_ethtool_ops;

	nsim_ethtool_ring_init(ns);

	ns->ethtool.fec.fec = ETHTOOL_FEC_NONE;
	ns->ethtool.fec.active_fec = ETHTOOL_FEC_NONE;

	ns->ethtool.channels = ns->nsim_bus_dev->num_queues;

	ethtool = debugfs_create_dir("ethtool", ns->nsim_dev_port->ddir);

	debugfs_create_u32("get_err", 0600, ethtool, &ns->ethtool.get_err);
	debugfs_create_u32("set_err", 0600, ethtool, &ns->ethtool.set_err);

	dir = debugfs_create_dir("pause", ethtool);
	debugfs_create_bool("report_stats_rx", 0600, dir,
			    &ns->ethtool.pauseparam.report_stats_rx);
	debugfs_create_bool("report_stats_tx", 0600, dir,
			    &ns->ethtool.pauseparam.report_stats_tx);

	dir = debugfs_create_dir("ring", ethtool);
	debugfs_create_u32("rx_max_pending", 0600, dir,
			   &ns->ethtool.ring.rx_max_pending);
	debugfs_create_u32("rx_jumbo_max_pending", 0600, dir,
			   &ns->ethtool.ring.rx_jumbo_max_pending);
	debugfs_create_u32("rx_mini_max_pending", 0600, dir,
			   &ns->ethtool.ring.rx_mini_max_pending);
	debugfs_create_u32("tx_max_pending", 0600, dir,
			   &ns->ethtool.ring.tx_max_pending);

	/* The work item holds a reference on the netdev, so its unregistration
	 * cannot be completed while the work is queued or executing.
	 */
	INIT_WORK(&ns->ethtool.module_fw.work, nsim_module_fw_flash);
}
