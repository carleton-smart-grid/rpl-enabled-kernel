/*
 *	RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
 *	Linux RPL implementation
 *
 *	Authors:
 *	Siemens AG (ieee802154)
+ *	Joao Pedro Taveira	<joao.silva@inov.pt>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License.
 */

#ifndef NL_RPL_LOCAL_H
#define NL_RPL_LOCAL_H

int __init rpl_nl_init(void);
void __exit rpl_nl_exit(void);

#define RPL_OP(_cmd, _func)			\
	{						\
		.cmd	= _cmd,				\
		.policy	= rpl_policy,		\
		.doit	= _func,			\
		.dumpit	= NULL,				\
		.flags	= GENL_ADMIN_PERM,		\
	}

#define RPL_DUMP(_cmd, _func, _dump)		\
	{						\
		.cmd	= _cmd,				\
		.policy	= rpl_policy,		\
		.doit	= _func,			\
		.dumpit	= _dump,			\
	}

struct genl_info;

struct sk_buff *rpl_nl_create(int flags, u8 req);
int rpl_nl_mcast(struct sk_buff *msg, unsigned int group);
struct sk_buff *rpl_nl_new_reply(struct genl_info *info,
		int flags, u8 req);
int rpl_nl_reply(struct sk_buff *msg, struct genl_info *info);

extern struct genl_family nlrpl_family;

/* genetlink ops/groups */
int rpl_list_dag(struct sk_buff *skb, struct genl_info *info);
int rpl_dump_dag(struct sk_buff *skb, struct netlink_callback *cb);
int rpl_list_iface(struct sk_buff *skb,	struct genl_info *info);
int rpl_dump_iface(struct sk_buff *skb,	struct netlink_callback *cb);
int rpl_enable_iface(struct sk_buff *skb, struct genl_info *info);
int rpl_enable_ifaces(struct sk_buff *skb, struct netlink_callback *cb);
int rpl_disable_iface(struct sk_buff *skb, struct genl_info *info);
int rpl_disable_ifaces(struct sk_buff *skb,	struct netlink_callback *cb);
int rpl_dag_list_parents(struct sk_buff *skb, struct genl_info *info);
int rpl_dag_dump_parents(struct sk_buff *skb, struct netlink_callback *cb);
int rpl_dag_list_neighbors(struct sk_buff *skb,	struct genl_info *info);
int rpl_dag_dump_neighbors(struct sk_buff *skb,	struct netlink_callback *cb);
int rpl_dag_list_downward_routes(struct sk_buff *skb,
	struct genl_info *info);
int rpl_dag_dump_downward_routes(struct sk_buff *skb,
	struct netlink_callback *cb);
int rpl_dag_global_repair(struct sk_buff *skb, struct genl_info *info);
int rpl_dag_local_repair(struct sk_buff *skb, struct genl_info *info);
int rpl_dag_dao_update(struct sk_buff *skb, struct genl_info *info);

int nlrpl_dag_conf_register(void);
int nlrpl_dag_info_register(void);
int nlrpl_dag_mng_register(void);

#endif /* NL_RPL_LOCAL_H */
