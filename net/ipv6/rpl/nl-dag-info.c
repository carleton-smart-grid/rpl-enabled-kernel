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
 * Nodes Dump Functions
 */

static int rpl_nl_dag_fill_node(u8 cmd, struct sk_buff *msg, u32 portid,
	u32 seq, int flags, struct rpl_dag *dag, struct rpl_node *node)
{
	void *hdr;

	pr_debug("%s\n", __func__);

	hdr = genlmsg_put(msg, 0, seq, &nlrpl_family, flags,cmd);
	if (!hdr)
		goto out;

	if(nla_put_u8(msg,RPL_ATTR_INSTANCE_ID,dag->instance->instanceID) ||
			nla_put(msg,RPL_ATTR_DODAG_ID,sizeof(struct in6_addr),&dag->dodagid) ||
			nla_put(msg,RPL_ATTR_NODE_ADDR,sizeof(struct in6_addr),&node->addr) ||
			nla_put_string(msg,RPL_ATTR_DEV_NAME,node->dev->name) ||
			nla_put_u8(msg,RPL_ATTR_IS_DODAG_PARENT,node->is_dodag_parent) ||
			nla_put_u8(msg,RPL_ATTR_IS_PREFERRED,node->is_preferred) ||
			nla_put_u8(msg,RPL_ATTR_IS_DAO_PARENT,node->is_dao_parent) ||
			nla_put_u8(msg,RPL_ATTR_DTSN,node->dtsn) ||
			nla_put_u16(msg,RPL_ATTR_RANK,node->rank))
		goto nla_put_failure;

	return genlmsg_end(msg, hdr);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out:
	return -EMSGSIZE;
}

static int rpl_dag_list_nodes(u8 cmd, struct sk_buff *skb,
	struct genl_info *info)
{
	struct net *net;
	struct sk_buff *msg;
	struct in6_addr dodagid;
	__u8 instanceID;
	struct rpl_dag *dag;
	struct rpl_node *node;
	struct list_head *node_list;
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

	if(cmd == RPL_LIST_PARENTS)
		node_list = &dag->dodag_parents;
	else if(cmd == RPL_LIST_NEIGHBORS)
		node_list = &dag->neighbours;
	else
		goto out_free;

	mutex_lock(&dag->parents_lock);
	list_for_each_entry(node,node_list,node_list){
		rc = rpl_nl_dag_fill_node(cmd,msg,info->snd_portid,info->snd_seq,
				NLM_F_MULTI,dag,node);
		if (rc < 0) {
			mutex_unlock(&dag->parents_lock);
			goto out_free;
		}
	}
	mutex_unlock(&dag->parents_lock);

	rpl_dag_put(dag);

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
out_dag:
	rpl_dag_put(dag);
	return rc;

}

int rpl_dag_list_parents(struct sk_buff *skb, struct genl_info *info)
{
	return rpl_dag_list_nodes(RPL_LIST_PARENTS,skb,info);
}

int rpl_dag_list_neighbors(struct sk_buff *skb,	struct genl_info *info)
{
	return rpl_dag_list_nodes(RPL_LIST_NEIGHBORS,skb,info);
}

struct dump_dag_data {
	u8 cmd;
	struct sk_buff *skb;
	struct netlink_callback *cb;
	int idx, s_idx;
};

static int rpl_dag_dump_node_iter(struct rpl_dag *dag, void *_data)
{
	int rc;
	struct dump_dag_data *data = _data;
	struct rpl_node *node;
	struct list_head *node_list;

	pr_debug("%s\n", __func__);

	if (data->idx++ < data->s_idx)
		return 0;

	if(data->cmd == RPL_LIST_PARENTS)
		node_list = &dag->dodag_parents;
	else if(data->cmd == RPL_LIST_NEIGHBORS)
		node_list = &dag->neighbours;
	else
		return -EINVAL;

	mutex_lock(&dag->parents_lock);
	list_for_each_entry(node,node_list,node_list){
		rc = rpl_nl_dag_fill_node(data->cmd,data->skb,
				NETLINK_CB(data->cb->skb).portid,
				data->cb->nlh->nlmsg_seq,
				NLM_F_MULTI,
				dag,node);

		if (rc < 0) {
			data->idx--;
			mutex_unlock(&dag->parents_lock);
			return rc;
		}
	}
	mutex_unlock(&dag->parents_lock);
	return 0;
}

static int rpl_dag_dump_nodes(u8 cmd, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct rpl_dag *dag;
	struct dump_dag_data data = {
		.cmd = cmd,
		.cb = cb,
		.skb = skb,
		.s_idx = cb->args[0],
		.idx = 0,
	};

	pr_debug("%s\n", __func__);

	mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
	list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
		rpl_dag_dump_node_iter(dag,&data);
	}
	mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);

	cb->args[0] = data.idx;

	return skb->len;
}

int rpl_dag_dump_parents(struct sk_buff *skb, struct netlink_callback *cb)
{
	return rpl_dag_dump_nodes(RPL_LIST_PARENTS,skb,cb);
}

int rpl_dag_dump_neighbors(struct sk_buff *skb,	struct netlink_callback *cb)
{
	return rpl_dag_dump_nodes(RPL_LIST_NEIGHBORS,skb,cb);
}

/*
 * Targets/Downward Routes Dump Functions
 */

static int rpl_nl_dag_fill_downward_route(struct sk_buff *msg, u32 portid,
	u32 seq, int flags, struct rpl_dag *dag, struct rpl_target *target)
{
	void *hdr;
	struct rpl_target_transit_info *transit_info;

	pr_debug("%s\n", __func__);

	hdr = genlmsg_put(msg, 0, seq, &nlrpl_family, flags,RPL_LIST_DOWNWARD_ROUTES);
	if (!hdr)
		goto out;

	transit_info = rpl_target_get_installed(target);
	if(!transit_info)
		goto nla_put_failure;

	if(nla_put_u8(msg,RPL_ATTR_INSTANCE_ID,dag->instance->instanceID) ||
			nla_put(msg,RPL_ATTR_DODAG_ID,sizeof(struct in6_addr),&dag->dodagid) ||
			nla_put(msg,RPL_ATTR_PREFIX,sizeof(struct in6_addr),&target->prefix) ||
			nla_put_u8(msg,RPL_ATTR_PREFIX_LEN,target->prefix_len) ||
			nla_put(msg,RPL_ATTR_NEXT_HOP,sizeof(struct in6_addr),&transit_info->next_hop) ||
			nla_put_string(msg,RPL_ATTR_DEV_NAME,transit_info->dev->name) ||
			nla_put_u8(msg,RPL_ATTR_ONE_HOP,transit_info->one_hop))
		goto nla_put_failure;

	return genlmsg_end(msg, hdr);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out:
	return -EMSGSIZE;
}

static int rpl_dag_dump_downward_routes_iter(struct rpl_dag *dag, void *_data)
{
	int rc;
	struct dump_dag_data *data = _data;
	struct rpl_target *target;

	pr_debug("%s\n", __func__);

	if (data->idx++ < data->s_idx)
		return 0;

	list_for_each_entry(target,&dag->targets_head,target_list){
		rc = rpl_nl_dag_fill_downward_route(data->skb,
				NETLINK_CB(data->cb->skb).portid,
				data->cb->nlh->nlmsg_seq,
				NLM_F_MULTI,
				dag,target);

		if (rc < 0) {
			data->idx--;
			return rc;
		}
	}
	return 0;
}

int rpl_dag_list_downward_routes(struct sk_buff *skb,
	struct genl_info *info)
{
	struct net *net;
	struct sk_buff *msg;
	struct in6_addr dodagid;
	__u8 instanceID;
	struct rpl_dag *dag;
	struct rpl_target *target;
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

	list_for_each_entry(target,&dag->targets_head,target_list){
		rc = rpl_nl_dag_fill_downward_route(msg,info->snd_portid,info->snd_seq,
				NLM_F_MULTI,dag,target);
		if (rc < 0) {
			goto out_free;
		}
	}

	rpl_dag_put(dag);

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
out_dag:
	rpl_dag_put(dag);
	return rc;

}

int rpl_dag_dump_downward_routes(struct sk_buff *skb,
	struct netlink_callback *cb)
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
		rpl_dag_dump_downward_routes_iter(dag,&data);
	}
	mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);

	cb->args[0] = data.idx;

	return skb->len;
}
