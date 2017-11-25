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

#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/rpl_nl.h>

#include <net/rpl/rpl_debug.h>
#include <net/rpl/rpl_internals.h>
#include <net/rpl/rpl_dag.h>

#include "nlrpl.h"

/*
 * Global Repair
 */

int rpl_dag_global_repair(struct sk_buff *skb, struct genl_info *info)
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

	msg = rpl_nl_new_reply(info, 0, RPL_GLOBAL_REPAIR);
	if (!msg)
		goto out_dag;

	RPL_LOLLIPOP_INCREMENT(dag->version);
	rc = rpl_dag_inconsistent(dag);
	if(rc < 0)
		goto out_free;

	if (nla_put_u8(msg,RPL_ATTR_INSTANCE_ID,dag->instance->instanceID) ||
		nla_put(msg,RPL_ATTR_DODAG_ID,sizeof(struct in6_addr),&dag->dodagid) ||
		nla_put_u8(msg,RPL_ATTR_VERSION,dag->version))
		goto out_free;

	rpl_dag_put(dag);

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
out_dag:
	rpl_dag_put(dag);
	return rc;
}

/*
 * Local Repair
 */

int rpl_dag_local_repair(struct sk_buff *skb, struct genl_info *info)
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

	msg = rpl_nl_new_reply(info, 0, RPL_LOCAL_REPAIR);
	if (!msg)
		goto out_dag;

	rc = rpl_dag_inconsistent(dag);
	if(rc < 0)
		goto out_free;

	if (nla_put_u8(msg,RPL_ATTR_INSTANCE_ID,dag->instance->instanceID) ||
		nla_put(msg,RPL_ATTR_DODAG_ID,sizeof(struct in6_addr),&dag->dodagid) ||
		nla_put_u8(msg,RPL_ATTR_VERSION,dag->version))
		goto out_free;

	rpl_dag_put(dag);

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
out_dag:
	rpl_dag_put(dag);
	return rc;
}

/*
 * DAO Update
 */

int rpl_dag_dao_update(struct sk_buff *skb, struct genl_info *info)
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

	msg = rpl_nl_new_reply(info, 0, RPL_DAO_UPDATE);
	if (!msg)
		goto out_dag;

	RPL_LOLLIPOP_INCREMENT(dag->DTSN);
	rc = rpl_dag_inconsistent(dag);
	if(rc < 0)
		goto out_free;

	if (nla_put_u8(msg,RPL_ATTR_INSTANCE_ID,dag->instance->instanceID) ||
		nla_put(msg,RPL_ATTR_DODAG_ID,sizeof(struct in6_addr),&dag->dodagid) ||
		nla_put_u8(msg,RPL_ATTR_VERSION,dag->version))
		goto out_free;

	rpl_dag_put(dag);

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
out_dag:
	rpl_dag_put(dag);
	return rc;
}
