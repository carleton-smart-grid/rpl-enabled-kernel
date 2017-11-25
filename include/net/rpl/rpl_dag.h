/*
 *	RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
 *	Linux RPL implementation
 *
 *	Authors:
 *	Joao Pedro Taveira	<joao.silva@inov.pt>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

/**
 * @file rpl_dag.h
 *
 * @date Jul 31, 2013
 * @author Joao Pedro Taveira
 */

#ifndef RPL_DAG_H_
#define RPL_DAG_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/in6.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <net/rpl/rpl_types.h>

/*
 * RPL Instances List Interface
 */
extern int rpl_instances_list_init(struct netns_rpl *rplns);
extern int rpl_instances_list_cleanup(struct netns_rpl *rplns);

/*
 * RPL Enabled Network Devices
 */
extern int rpl_enabled_devices_list_init(struct netns_rpl *rplns);
extern int rpl_enabled_devices_list_cleanup(struct netns_rpl *rplns);
extern struct rpl_enabled_device *rpl_enabled_devices_list_add(struct net_device *dev, int *err);
extern int rpl_enabled_devices_list_del(struct net_device *dev);
extern struct rpl_enabled_device *rpl_enabled_device_get(struct net_device *dev);
extern struct rpl_enabled_device *rpl_enabled_device_find_by_name(struct net *net, const char name[IFNAMSIZ + 1]);
extern struct net_device *rpl_enabled_device_find_idev_by_name(struct net *net, const char name[IFNAMSIZ + 1]);
extern int rpl_enabled_device_add_dis_timer(struct rpl_enabled_device *enabled);

/*
 * RPL Instance Functions
 */

extern void rpl_instance_free(struct rpl_instance *instance);
static inline void rpl_instance_put(struct rpl_instance *instance)
{
	if (atomic_dec_and_test(&instance->refcnt))
		rpl_instance_free(instance);
}

static inline void __rpl_instance_put(struct rpl_instance *instance)
{
	atomic_dec(&instance->refcnt);
}

static inline void rpl_instance_hold(struct rpl_instance *instance)
{
	atomic_inc(&instance->refcnt);
}

/*
 * RPL Dags Functions
 */
extern int rpl_dags_list_init(struct netns_rpl *rplns);
extern int rpl_dags_list_cleanup(struct netns_rpl *rplns);

extern struct rpl_node *rpl_node_alloc(const struct in6_addr *addr, struct net_device *dev, rpl_rank_t rank, __u8 dtsn, int *err);
extern int rpl_node_free(struct rpl_node *node);

extern int rpl_dags_list_dump(struct net *net);

extern int rpl_dags_list_add(struct net *net, struct rpl_dag *dag);
extern int rpl_dags_list_del(struct net *net, struct rpl_dag *dag);

extern struct rpl_dag *rpl_dag_find(struct net *net, __u8 instanceID, const struct in6_addr *dodagid);

extern int rpl_dag_set_rank(struct rpl_dag *dag, rpl_rank_t rank);

extern void rpl_dag_free(struct rpl_dag *dag);
static inline void rpl_dag_put(struct rpl_dag *dag)
{
	if (atomic_dec_and_test(&dag->refcnt))
		rpl_dag_free(dag);
}

static inline void __rpl_dag_put(struct rpl_dag *dag)
{
	atomic_dec(&dag->refcnt);
}

static inline void rpl_dag_hold(struct rpl_dag *dag)
{
	atomic_inc(&dag->refcnt);
}

extern bool rpl_dag_is_allowed(struct rpl_dag *dag, struct net_device *dev);
extern int rpl_dag_set_allowed(struct rpl_dag *dag, struct net_device *dev,bool enabled, bool auto_gen, bool *should_trigger_dio);
extern int rpl_dag_set_enabled(struct rpl_dag *dag, struct net_device *dev,bool enabled);

extern struct rpl_node *rpl_dag_get_node(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *addr);
extern int rpl_dag_add_node(struct rpl_dag *dag, struct rpl_node *node);
extern int rpl_dag_del_node(struct rpl_node *parent);
extern int rpl_dag_purge_nodes(struct rpl_dag *dag);
extern int rpl_dag_unlink_nodes_by_dev(struct rpl_dag *dag, struct net_device *dev);
extern int rpl_dag_unlink_node(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *addr);
extern int rpl_dag_target_unreachable(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *addr);

extern int rpl_dag_add_target(struct rpl_dag *dag, struct rpl_target *target, bool *updated);

extern struct rpl_target *rpl_dag_get_target(struct rpl_dag *dag, const struct in6_addr *prefix, __u8 prefix_len);

extern void rpl_dag_dbg_dump(struct rpl_dag *dag);

extern struct rpl_dag *rpl_dag_setup_using_conf(struct net *net, struct rpl_dag_conf *cfg, int *perr);
extern void rpl_dag_conf_default_init(struct rpl_dag_conf *cfg);

extern int rpl_dag_start_root(struct net *net, struct rpl_dag_conf *cfg, struct net_device *dev);

extern struct rpl_dag *rpl_dag_new_from_dio(struct net *net, struct net_device *dev, struct sk_buff *skb);

extern int rpl_dag_disjoin(struct rpl_dag *dag, struct net_device *dev);
extern int rpl_dag_inconsistent(struct rpl_dag *dag);
extern int rpl_dag_consistent(struct rpl_dag *dag);

extern int rpl_dag_cleanup_no_path(struct rpl_dag *dag);

extern int rpl_dag_trigger_dao_timer(struct rpl_dag *dag);

extern struct rpl_target *rpl_target_alloc(const struct in6_addr *prefix, __u8 prefix_len, int *err);
extern void rpl_target_free(struct rpl_target *target);
extern struct rpl_target_transit_info *rpl_target_get_installed(struct rpl_target *target);
extern int rpl_target_add_transit_info(struct rpl_target *target, struct rpl_target_transit_info *transit_info,bool *updated);
extern struct rpl_target_transit_info *rpl_target_find_transit_info(struct rpl_target *target, struct net_device *dev, const struct in6_addr *next_hop);
extern int rpl_target_set_no_path(struct net *net, __u8 instanceID, const struct in6_addr *dodagid,
		struct net_device *dev, const struct in6_addr *target_addr,
		__u8 target_addr_len, const struct in6_addr *next_hop);
extern int rpl_target_check_routes(struct rpl_target *target, bool *routes_updated);
extern int rpl_target_merge_transit_info(struct rpl_target *old_target,struct rpl_target *new_target, bool *updated);

extern struct rpl_target_transit_info *rpl_transit_info_alloc(const struct in6_addr *next_hop, struct net_device *dev, bool is_one_hop, int *err);
extern void rpl_transit_info_free(struct rpl_target_transit_info *transit_info);
extern int rpl_transit_info_update(struct rpl_target *target,
		struct rpl_target_transit_info *transit_info, __u8 DAOSequence, __u8 path_sequence,
		__u8 path_lifetime, __u8 path_control, bool *updated);

extern int rpl_dag_update_upward_routes(struct rpl_dag *dag, bool *updated);
extern int rpl_add_route_nexthop(struct net_device *dev, const struct in6_addr *prefix,
		__u8 prefix_len, const struct in6_addr *next_hop);
extern int rpl_dag_purge_targets_by_nexthop(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *addr);
extern int rpl_dag_purge_targets_by_dev(struct rpl_dag *dag, struct net_device *dev);

extern int lollipop_greater_than(int a, int b);
extern int ipv6_get_global_addr(struct net_device *dev, struct in6_addr *addr,
		    unsigned char banned_flags);
#endif /* RPL_DAG_H_ */
