// SPDX-License-Identifier: GPL-2.0-only

#include <linux/ethtool.h>

#include "netlink.h"
#include "common.h"
#include "bitset.h"

struct module_req_info {
	struct ethnl_req_info base;
};

struct module_reply_data {
	struct ethnl_reply_data	base;
	struct ethtool_module_power_mode_params power;
};

#define MODULE_REPDATA(__reply_base) \
	container_of(__reply_base, struct module_reply_data, base)

struct module_fw_info_req_info {
	struct ethnl_req_info base;
};

struct module_fw_info_reply_data {
	struct ethnl_reply_data	base;
	struct ethtool_module_fw_info fw_info;
};

#define MODULE_FW_INFO_REPDATA(__reply_base) \
	container_of(__reply_base, struct module_fw_info_reply_data, base)

/* MODULE_GET */

const struct nla_policy ethnl_module_get_policy[ETHTOOL_A_MODULE_HEADER + 1] = {
	[ETHTOOL_A_MODULE_HEADER] = NLA_POLICY_NESTED(ethnl_header_policy),
};

static int module_get_power_mode(struct net_device *dev,
				 struct module_reply_data *data,
				 struct netlink_ext_ack *extack)
{
	const struct ethtool_ops *ops = dev->ethtool_ops;

	if (!ops->get_module_power_mode)
		return 0;

	return ops->get_module_power_mode(dev, &data->power, extack);
}

static int module_prepare_data(const struct ethnl_req_info *req_base,
			       struct ethnl_reply_data *reply_base,
			       struct genl_info *info)
{
	struct module_reply_data *data = MODULE_REPDATA(reply_base);
	struct netlink_ext_ack *extack = info ? info->extack : NULL;
	struct net_device *dev = reply_base->dev;
	int ret;

	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		return ret;

	ret = module_get_power_mode(dev, data, extack);
	if (ret < 0)
		goto out_complete;

out_complete:
	ethnl_ops_complete(dev);
	return ret;
}

static int module_reply_size(const struct ethnl_req_info *req_base,
			     const struct ethnl_reply_data *reply_base)
{
	struct module_reply_data *data = MODULE_REPDATA(reply_base);
	int len = 0;

	if (data->power.policy)
		len += nla_total_size(sizeof(u8));	/* _MODULE_POWER_MODE_POLICY */

	if (data->power.mode)
		len += nla_total_size(sizeof(u8));	/* _MODULE_POWER_MODE */

	return len;
}

static int module_fill_reply(struct sk_buff *skb,
			     const struct ethnl_req_info *req_base,
			     const struct ethnl_reply_data *reply_base)
{
	const struct module_reply_data *data = MODULE_REPDATA(reply_base);

	if (data->power.policy &&
	    nla_put_u8(skb, ETHTOOL_A_MODULE_POWER_MODE_POLICY,
		       data->power.policy))
		return -EMSGSIZE;

	if (data->power.mode &&
	    nla_put_u8(skb, ETHTOOL_A_MODULE_POWER_MODE, data->power.mode))
		return -EMSGSIZE;

	return 0;
}

const struct ethnl_request_ops ethnl_module_request_ops = {
	.request_cmd		= ETHTOOL_MSG_MODULE_GET,
	.reply_cmd		= ETHTOOL_MSG_MODULE_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_MODULE_HEADER,
	.req_info_size		= sizeof(struct module_req_info),
	.reply_data_size	= sizeof(struct module_reply_data),

	.prepare_data		= module_prepare_data,
	.reply_size		= module_reply_size,
	.fill_reply		= module_fill_reply,
};

/* MODULE_SET */

const struct nla_policy ethnl_module_set_policy[ETHTOOL_A_MODULE_POWER_MODE_POLICY + 1] = {
	[ETHTOOL_A_MODULE_HEADER] = NLA_POLICY_NESTED(ethnl_header_policy),
	[ETHTOOL_A_MODULE_POWER_MODE_POLICY] =
		NLA_POLICY_RANGE(NLA_U8, ETHTOOL_MODULE_POWER_MODE_POLICY_HIGH,
				 ETHTOOL_MODULE_POWER_MODE_POLICY_AUTO),
};

static int module_set_power_mode(struct net_device *dev, struct nlattr **tb,
				 bool *p_mod, struct netlink_ext_ack *extack)
{
	struct ethtool_module_power_mode_params power = {};
	struct ethtool_module_power_mode_params power_new;
	const struct ethtool_ops *ops = dev->ethtool_ops;
	int ret;

	if (!tb[ETHTOOL_A_MODULE_POWER_MODE_POLICY])
		return 0;

	if (!ops->get_module_power_mode || !ops->set_module_power_mode) {
		NL_SET_ERR_MSG_ATTR(extack,
				    tb[ETHTOOL_A_MODULE_POWER_MODE_POLICY],
				    "Setting power mode policy is not supported by this device");
		return -EOPNOTSUPP;
	}

	power_new.policy = nla_get_u8(tb[ETHTOOL_A_MODULE_POWER_MODE_POLICY]);
	ret = ops->get_module_power_mode(dev, &power, extack);
	if (ret < 0)
		return ret;

	if (power_new.policy == power.policy)
		return 0;
	*p_mod = true;

	return ops->set_module_power_mode(dev, &power_new, extack);
}

int ethnl_set_module(struct sk_buff *skb, struct genl_info *info)
{
	struct ethnl_req_info req_info = {};
	struct nlattr **tb = info->attrs;
	struct net_device *dev;
	bool mod = false;
	int ret;

	ret = ethnl_parse_header_dev_get(&req_info, tb[ETHTOOL_A_MODULE_HEADER],
					 genl_info_net(info), info->extack,
					 true);
	if (ret < 0)
		return ret;
	dev = req_info.dev;

	rtnl_lock();
	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		goto out_rtnl;

	ret = module_set_power_mode(dev, tb, &mod, info->extack);
	if (ret < 0)
		goto out_ops;

	if (!mod)
		goto out_ops;

	ethtool_notify(dev, ETHTOOL_MSG_MODULE_NTF, NULL);

out_ops:
	ethnl_ops_complete(dev);
out_rtnl:
	rtnl_unlock();
	dev_put(dev);
	return ret;
}

/* MODULE_FW_INFO_GET */

const struct nla_policy ethnl_module_fw_info_get_policy[ETHTOOL_A_MODULE_FW_INFO_HEADER + 1] = {
	[ETHTOOL_A_MODULE_FW_INFO_HEADER] =
		NLA_POLICY_NESTED(ethnl_header_policy),
};

static int module_get_fw_info(struct net_device *dev,
			      struct ethtool_module_fw_info *fw_info,
			      struct netlink_ext_ack *extack)
{
	int ret;

	ret = dev->ethtool_ops->get_module_fw_info(dev, fw_info, extack);
	if (ret < 0)
		return ret;

	if (!fw_info->type) {
		NL_SET_ERR_MSG(extack, "Module firmware info type was not set");
		return -EINVAL;
	}

	return ret;
}

static int module_fw_info_prepare_data(const struct ethnl_req_info *req_base,
				       struct ethnl_reply_data *reply_base,
				       struct genl_info *info)
{
	struct netlink_ext_ack *extack = info ? info->extack : NULL;
	struct net_device *dev = reply_base->dev;
	struct module_fw_info_reply_data *data;
	int ret;

	if (!dev->ethtool_ops->get_module_fw_info)
		return -EOPNOTSUPP;

	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		return ret;

	data = MODULE_FW_INFO_REPDATA(reply_base);
	ret = module_get_fw_info(dev, &data->fw_info, extack);
	if (ret < 0)
		goto out_complete;

out_complete:
	ethnl_ops_complete(dev);
	return ret;
}

static int
module_fw_info_reply_size_image(const struct ethtool_module_fw_info_image *image,
				int name_len)
{
	       /* _MODULE_FW_INFO_IMAGE */
	return nla_total_size(0) +
	       /* _MODULE_FW_INFO_IMAGE_NAME */
	       nla_total_size(name_len + 1) +
	       /* _MODULE_FW_INFO_IMAGE_RUNNING */
	       nla_total_size(sizeof(u8)) +
	       /* _MODULE_FW_INFO_IMAGE_COMMITTED */
	       nla_total_size(sizeof(u8)) +
	       /* _MODULE_FW_INFO_IMAGE_VALID */
	       nla_total_size(sizeof(u8)) +
	       /* _MODULE_FW_INFO_IMAGE_VERSION */
	       nla_total_size(ETH_MODULE_FW_VER_LEN + 1);
}

static int
module_fw_info_reply_size_cmis(const struct ethtool_module_fw_info_cmis *cmis)
{
	int len = 0;

	if (cmis->a_present)
		len += module_fw_info_reply_size_image(&cmis->a, strlen("a"));
	if (cmis->b_present)
		len += module_fw_info_reply_size_image(&cmis->b, strlen("b"));
	if (cmis->factory_present)
		len += module_fw_info_reply_size_image(&cmis->factory,
						       strlen("factory"));

	return len;
}

static int module_fw_info_reply_size(const struct ethnl_req_info *req_base,
				     const struct ethnl_reply_data *reply_base)
{
	struct module_fw_info_reply_data *data;

	data = MODULE_FW_INFO_REPDATA(reply_base);

	switch (data->fw_info.type) {
	case ETHTOOL_MODULE_FW_INFO_TYPE_CMIS:
		return module_fw_info_reply_size_cmis(&data->fw_info.cmis);
	default:
		/* Module firmware information type was already validated to be
		 * set in prepare_data() callback.
		 */
		WARN_ON(1);
		return -EINVAL;
	}
}

static int
module_fw_info_fill_reply_image(struct sk_buff *skb,
				const struct ethtool_module_fw_info_image *image,
				const char *image_name)
{
	char buf[ETH_MODULE_FW_VER_LEN];
	struct nlattr *nest;

	if (strlen(image->ver_extra_str))
		snprintf(buf, ETH_MODULE_FW_VER_LEN, "%d.%d.%d-%s",
			 image->ver_major, image->ver_minor, image->ver_build,
			 image->ver_extra_str);
	else
		snprintf(buf, ETH_MODULE_FW_VER_LEN, "%d.%d.%d",
			 image->ver_major, image->ver_minor, image->ver_build);

	nest = nla_nest_start(skb, ETHTOOL_A_MODULE_FW_INFO_IMAGE);
	if (!nest)
		return -EMSGSIZE;

	if (nla_put_string(skb, ETHTOOL_A_MODULE_FW_INFO_IMAGE_NAME,
			   image_name) ||
	    nla_put_u8(skb, ETHTOOL_A_MODULE_FW_INFO_IMAGE_RUNNING,
		       image->running) ||
	    nla_put_u8(skb, ETHTOOL_A_MODULE_FW_INFO_IMAGE_COMMITTED,
		       image->committed) ||
	    nla_put_u8(skb, ETHTOOL_A_MODULE_FW_INFO_IMAGE_VALID,
		       image->valid) ||
	    nla_put_string(skb, ETHTOOL_A_MODULE_FW_INFO_IMAGE_VERSION, buf))
		goto err_cancel;

	nla_nest_end(skb, nest);

	return 0;

err_cancel:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int
module_fw_info_fill_reply_cmis(struct sk_buff *skb,
			       const struct ethtool_module_fw_info_cmis *cmis)
{
	if (cmis->a_present &&
	    module_fw_info_fill_reply_image(skb, &cmis->a, "a"))
		return -EMSGSIZE;
	if (cmis->b_present &&
	    module_fw_info_fill_reply_image(skb, &cmis->b, "b"))
		return -EMSGSIZE;
	if (cmis->factory_present &&
	    module_fw_info_fill_reply_image(skb, &cmis->factory, "factory"))
		return -EMSGSIZE;

	return 0;
}

static int module_fw_info_fill_reply(struct sk_buff *skb,
				     const struct ethnl_req_info *req_base,
				     const struct ethnl_reply_data *reply_base)
{
	const struct module_fw_info_reply_data *data;

	data = MODULE_FW_INFO_REPDATA(reply_base);

	switch (data->fw_info.type) {
	case ETHTOOL_MODULE_FW_INFO_TYPE_CMIS:
		return module_fw_info_fill_reply_cmis(skb, &data->fw_info.cmis);
	default:
		WARN_ON(1);
		return -EINVAL;
	}
}

const struct ethnl_request_ops ethnl_module_fw_info_request_ops = {
	.request_cmd		= ETHTOOL_MSG_MODULE_FW_INFO_GET,
	.reply_cmd		= ETHTOOL_MSG_MODULE_FW_INFO_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_MODULE_FW_INFO_HEADER,
	.req_info_size		= sizeof(struct module_fw_info_req_info),
	.reply_data_size	= sizeof(struct module_fw_info_reply_data),

	.prepare_data		= module_fw_info_prepare_data,
	.reply_size		= module_fw_info_reply_size,
	.fill_reply		= module_fw_info_fill_reply,
};
