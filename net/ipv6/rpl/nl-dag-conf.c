/*
 *  Netlink inteface
 *	RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
 *	Linux RPL implementation
 *
 *	Authors:
 *	Joao Pedro Taveira	<joao.silva@inov.pt>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License.
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/rpl_nl.h>

#include <net/rpl/rpl_internals.h>
#include <net/rpl/rpl_debug.h>
#include <net/rpl/rpl_dag.h>

#include "nlrpl.h"

/*
 * List DAGs Functions
 */

static int rpl_nl_fill_dag(struct sk_buff *msg, u32 portid,
	u32 seq, int flags, struct rpl_dag *dag)
{
	void *hdr;

	pr_debug("%s\n", __func__);

	hdr = genlmsg_put(msg, 0, seq, &nlrpl_family, flags,
		RPL_LIST_DAG);
	if (!hdr)
		goto out;

	if(nla_put_u8(msg,RPL_ATTR_INSTANCE_ID,dag->instance->instanceID) ||
			nla_put_u16(msg,RPL_ATTR_OCP,dag->instance->of->ocp) ||
			nla_put(msg,RPL_ATTR_DODAG_ID,sizeof(struct in6_addr),&dag->dodagid) ||
			nla_put_u8(msg,RPL_ATTR_VERSION,dag->version) ||
			nla_put_u8(msg,RPL_ATTR_GROUNDED,dag->grounded) ||
			nla_put_u8(msg,RPL_ATTR_MOP,dag->mop) ||
			nla_put_u8(msg,RPL_ATTR_DTSN,dag->DTSN) ||
			nla_put_u16(msg,RPL_ATTR_RANK,dag->rank) ||
			nla_put_u8(msg,RPL_ATTR_DAO_SEQUENCE,dag->DAOSequence) ||
			nla_put_u8(msg,RPL_ATTR_PCS,dag->PCS) ||
			nla_put_u16(msg,RPL_ATTR_MIN_HOP_RANK_INCR,dag->MinHopRankIncrease) ||
			nla_put_u8(msg,RPL_ATTR_IS_ROOT,dag->is_root))
		goto nla_put_failure;

	return genlmsg_end(msg, hdr);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out:
	return -EMSGSIZE;
}

int rpl_list_dag(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net;
	struct sk_buff *msg;
	struct in6_addr dodagid;
	__u8 instanceID;
	struct rpl_dag *dag;
	int rc = -ENOBUFS;

	pr_debug("%s\n", __func__);

	if (!info->attrs[RPL_ATTR_DODAG_ID])
		return -EINVAL;
	if (!info->attrs[RPL_ATTR_INSTANCE_ID])
		return -EINVAL;

	instanceID = nla_get_u8(info->attrs[RPL_ATTR_INSTANCE_ID]);

	nla_memcpy(&dodagid,info->attrs[RPL_ATTR_DODAG_ID],nla_len(info->attrs[RPL_ATTR_DODAG_ID]));

	net = genl_info_net(info);
	dag = rpl_dag_find(net,instanceID,&dodagid);
	if (!dag)
		return -EADDRNOTAVAIL;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		goto out_dag;

	rc = rpl_nl_fill_dag(msg, info->snd_portid, info->snd_seq,
			0, dag);
	if (rc < 0)
		goto out_free;

	rpl_dag_put(dag);

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
out_dag:
	rpl_dag_put(dag);
	return rc;

}

struct dump_dag_data {
	struct sk_buff *skb;
	struct netlink_callback *cb;
	int idx, s_idx;
};

static int rpl_dump_dag_iter(struct rpl_dag *dag, void *_data)
{
	int rc;
	struct dump_dag_data *data = _data;

	pr_debug("%s\n", __func__);

	if (data->idx++ < data->s_idx)
		return 0;

	rc = rpl_nl_fill_dag(data->skb,
			NETLINK_CB(data->cb->skb).portid,
			data->cb->nlh->nlmsg_seq,
			NLM_F_MULTI,
			dag);

	if (rc < 0) {
		data->idx--;
		return rc;
	}

	return 0;
}

int rpl_dump_dag(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct rpl_dag *dag;
	struct dump_dag_data data = {
		.cb = cb,
		.skb = skb,
		.s_idx = cb->args[0],
		.idx = 0,
	};

	pr_debug("%s\n", __func__);

	mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
	list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
		rpl_dump_dag_iter(dag,&data);
	}
	mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);

	cb->args[0] = data.idx;
	return skb->len;
}

/*
 * List Enabled Interfaces Functions
 */

static int rpl_nl_fill_enabled_device(struct sk_buff *msg, u32 portid,
	u32 seq, int flags, struct rpl_enabled_device *enabled_device)
{
	void *hdr;

	pr_debug("%s\n", __func__);

	hdr = genlmsg_put(msg, 0, seq, &nlrpl_family, flags,
		RPL_LIST_IFACE);
	if (!hdr)
		goto out;

	//FIXME we should add RPL_ATTR_DEV_ENABLED and RPL_ATTR_DEV_AUTOGEN
	if(nla_put_string(msg,RPL_ATTR_DEV_NAME,enabled_device->dev->name) ||
		nla_put_u8(msg,RPL_ATTR_DEV_ENABLED,true))
		goto nla_put_failure;

	return genlmsg_end(msg, hdr);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out:
	return -EMSGSIZE;
}

int rpl_list_iface(struct sk_buff *skb,	struct genl_info *info)
{
	struct net *net;
	struct sk_buff *msg;
	int rc = -ENOBUFS;
	const char *dev_name;
	struct rpl_enabled_device *enabled_device;

	pr_debug("%s\n", __func__);

	if (!info->attrs[RPL_ATTR_DEV_NAME])
		return -EINVAL;

	dev_name = nla_data(info->attrs[RPL_ATTR_DEV_NAME]);
	if (dev_name[nla_len(info->attrs[RPL_ATTR_DEV_NAME]) - 1] != '\0')
		return -EINVAL; /* dev name should be null-terminated */

	if (strlen(dev_name) >= IFNAMSIZ)
		return -ENAMETOOLONG;

	net = genl_info_net(info);
	enabled_device = rpl_enabled_device_find_by_name(net,dev_name);
	if (!enabled_device)
		return -ENXIO;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		goto out_dev;

	rc = rpl_nl_fill_enabled_device(msg, info->snd_portid, info->snd_seq,
			0, enabled_device);
	if (rc < 0)
		goto out_free;

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
out_dev:
	return rc;

}

static int rpl_dump_iface_iter(struct rpl_enabled_device *enabled_device, void *_data)
{
	int rc;
	struct dump_dag_data *data = _data;

	pr_debug("%s\n", __func__);

	if (data->idx++ < data->s_idx)
		return 0;

	rc = rpl_nl_fill_enabled_device(data->skb,
			NETLINK_CB(data->cb->skb).portid,
			data->cb->nlh->nlmsg_seq,
			NLM_F_MULTI,
			enabled_device);

	if (rc < 0) {
		data->idx--;
		return rc;
	}

	return 0;
}

int rpl_dump_iface(struct sk_buff *skb,	struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct rpl_enabled_device *enabled_device;
	struct dump_dag_data data = {
		.cb = cb,
		.skb = skb,
		.s_idx = cb->args[0],
		.idx = 0,
	};

	pr_debug("%s\n", __func__);

	mutex_lock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
	list_for_each_entry(enabled_device,&net->ipv6.rpl.rpl_enabled_devices_list_head,enabled_list){
		rpl_dump_iface_iter(enabled_device,&data);
	}
	mutex_unlock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);

	cb->args[0] = data.idx;

	return skb->len;
}

/*
 * Enable interface(s)
 */

int rpl_enable_iface(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	int rc = -ENOBUFS;
	const char *dev_name;
	struct net_device *dev;
	struct net *net;
	struct inet6_dev *idev;
	struct rpl_enabled_device *enabled_device;
	//struct rpl_dag_conf cfg; //FIXME we must populate cfg

	pr_debug("%s\n", __func__);

	if (!info->attrs[RPL_ATTR_DEV_NAME])
		return -EINVAL;

	dev_name = nla_data(info->attrs[RPL_ATTR_DEV_NAME]);
	if (dev_name[nla_len(info->attrs[RPL_ATTR_DEV_NAME]) - 1] != '\0')
		return -EINVAL; /* dev name should be null-terminated */

	if (strlen(dev_name) >= IFNAMSIZ)
		return -ENAMETOOLONG;

	net = genl_info_net(info);
	dev = dev_get_by_name(net, dev_name);
	if(!dev)
		return -ENODEV;

	if (dev->flags & IFF_LOOPBACK){
		dev_put(dev);
		return -EINVAL;
	}

	idev = in6_dev_get(dev);
	if(!idev){
		dev_put(dev);
		return -ENODEV;
	}

	//rc = rpl_start(&cfg,idev);
	rc = rpl_start(NULL,dev);
	if(rc < 0){
		in6_dev_put(idev);
		dev_put(dev);
		goto out_dev;
	}

	in6_dev_put(idev);
	idev = NULL;
	dev_put(dev);
	dev = NULL;

	enabled_device = rpl_enabled_device_find_by_name(net,dev_name);
	if (!enabled_device)
		return -ENXIO;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		goto out_dev;

	rc = rpl_nl_fill_enabled_device(msg, info->snd_portid, info->snd_seq,
			0, enabled_device);
	if (rc < 0)
		goto out_free;

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
out_dev:
	return rc;

}

int rpl_enable_ifaces(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	int h, s_h;
	int idx;
	int s_idx;
	struct net_device *dev;
	struct inet6_dev *idev;
	struct hlist_head *head;
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0))
	struct hlist_node *node;
#endif
	int rc = -ENOBUFS;
	struct rpl_enabled_device *enabled_device;
	//struct rpl_dag_conf cfg; //FIXME we must populate cfg

	pr_debug("%s\n", __func__);

	s_h = cb->args[0];
	s_idx = idx = cb->args[1];

	rcu_read_lock();
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0))
#else
	cb->seq = atomic_read(&net->ipv6.dev_addr_genid) ^ net->dev_base_seq;
#endif

	for (h = s_h; h < NETDEV_HASHENTRIES; h++, s_idx = 0) {
		idx = 0;
		head = &net->dev_index_head[h];
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0))
		hlist_for_each_entry_rcu(dev, node, head, index_hlist) {
#else
		hlist_for_each_entry_rcu(dev, head, index_hlist) {
#endif
			if (idx < s_idx)
				goto cont;
			idev = __in6_dev_get(dev);
			if (!idev)
				goto cont;

			if (dev->flags & IFF_LOOPBACK)
				goto cont;

			//rc = rpl_start(&cfg,idev);
			rc = rpl_start(NULL,dev);
			if(rc < 0){
				pr_debug("%s: error starting RPL on %s\n", __func__,idev->dev->name);
				goto done;
			}

			enabled_device = rpl_enabled_device_get(dev);
			if (!enabled_device){
				pr_debug("%s: enabled device not found %s\n", __func__,idev->dev->name);
				goto done;
			}

			rc = rpl_nl_fill_enabled_device(skb,
					NETLINK_CB(skb).portid, cb->nlh->nlmsg_seq,
					NLM_F_MULTI, enabled_device);
			if (rc < 0){
				pr_debug("%s: error filling enabled device %s\n", __func__,idev->dev->name);
				goto done;
			}
cont:
			idx++;
		}
	}
done:
	rcu_read_unlock();

	cb->args[0] = h;
	cb->args[1] = idx;

	return skb->len;
}

/*
 * Disable interface(s)
 */

int rpl_disable_iface(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net;
	struct sk_buff *msg;
	int rc = -ENOBUFS;
	const char *dev_name;
	struct net_device *dev;
	struct inet6_dev *idev;
	//struct rpl_enabled_device *enabled_device;

	pr_debug("%s\n", __func__);

	if (!info->attrs[RPL_ATTR_DEV_NAME])
		return -EINVAL;

	dev_name = nla_data(info->attrs[RPL_ATTR_DEV_NAME]);
	if (dev_name[nla_len(info->attrs[RPL_ATTR_DEV_NAME]) - 1] != '\0')
		return -EINVAL; /* dev name should be null-terminated */

	if (strlen(dev_name) >= IFNAMSIZ)
		return -ENAMETOOLONG;

	net = genl_info_net(info);
	dev = dev_get_by_name(net, dev_name);
	if(!dev)
		return -ENODEV;

	if (dev->flags & IFF_LOOPBACK){
		dev_put(dev);
		return -EINVAL;
	}

	idev = in6_dev_get(dev);
	if(!idev){
		dev_put(dev);
		return -ENODEV;
	}

	rc = rpl_stop(dev);
	if(rc < 0){
		in6_dev_put(idev);
		dev_put(dev);
		goto out_dev;
	}

	in6_dev_put(idev);
	idev = NULL;
	dev_put(dev);
	dev = NULL;

	msg = rpl_nl_new_reply(info, 0, RPL_LIST_IFACE);
	if (!msg)
		goto out_dev;

	return genlmsg_reply(msg, info);
	nlmsg_free(msg);
out_dev:
	return rc;

}

int rpl_disable_ifaces(struct sk_buff *skb,	struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	int h, s_h;
	int idx;
	int s_idx;
	struct net_device *dev;
	struct inet6_dev *idev;
	struct hlist_head *head;
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0))
	struct hlist_node *node;
#endif
	int rc = -ENOBUFS;
	struct rpl_enabled_device *enabled_device;

	pr_debug("%s\n", __func__);

	//see inet6_dump_addr() on addrconf.c:4000

	s_h = cb->args[0];
	s_idx = idx = cb->args[1];

	rcu_read_lock();
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0))
#else
	cb->seq = atomic_read(&net->ipv6.dev_addr_genid) ^ net->dev_base_seq;
#endif

	for (h = s_h; h < NETDEV_HASHENTRIES; h++, s_idx = 0) {
		idx = 0;
		head = &net->dev_index_head[h];
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0))
		hlist_for_each_entry_rcu(dev, node, head, index_hlist) {
#else
		hlist_for_each_entry_rcu(dev, head, index_hlist) {
#endif
			if (idx < s_idx)
				goto cont;

			if (dev->flags & IFF_LOOPBACK)
				goto cont;

			idev = __in6_dev_get(dev);
			if (!idev)
				goto cont;

			rc = rpl_stop(dev);
			if(rc < 0){
				pr_debug("%s: error starting RPL on %s\n", __func__,idev->dev->name);
				goto done;
			}

			enabled_device = rpl_enabled_device_get(dev);
			if (!enabled_device){
				pr_debug("%s: enabled device not found %s\n", __func__,idev->dev->name);
				goto done;
			}

			rc = rpl_nl_fill_enabled_device(skb,
					NETLINK_CB(skb).portid, cb->nlh->nlmsg_seq,
					NLM_F_MULTI, enabled_device);
			if (rc < 0){
				pr_debug("%s: error filling enabled device %s\n", __func__,idev->dev->name);
				goto done;
			}
cont:
			idx++;
		}
	}
done:
	rcu_read_unlock();

	cb->args[0] = h;
	cb->args[1] = idx;

	return skb->len;
}
