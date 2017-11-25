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
 * @file rpl_types.h
 *
 * @date Aug 20, 2013
 * @author Joao Pedro Taveira
 */

#ifndef RPL_TYPES_H_
#define RPL_TYPES_H_

#include <linux/types.h>
#include <linux/in6.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <net/rpl/rpl_trickle.h>

typedef __u16 rpl_ocp_t;
typedef __u16 rpl_rank_t;

/*
 * Rank Comparison (DAGRank())
 */
#define DAGRank(rank, dag) \
  ((rank) / (dag)->MinHopRankIncrease)

#define RPL_LOLLIPOP_MAX_VALUE				255
#define RPL_LOLLIPOP_CIRCULAR_REGION		127
#define RPL_LOLLIPOP_SEQUENCE_WINDOW		16
#define RPL_LOLLIPOP_INIT                (RPL_LOLLIPOP_MAX_VALUE - RPL_LOLLIPOP_SEQUENCE_WINDOW + 1)
#define RPL_LOLLIPOP_INCREMENT(counter)                                 \
  do {                                                                  \
    if((counter) > RPL_LOLLIPOP_CIRCULAR_REGION) {                      \
      (counter) = ((counter) + 1) & RPL_LOLLIPOP_MAX_VALUE;             \
    } else {                                                            \
      (counter) = ((counter) + 1) & RPL_LOLLIPOP_CIRCULAR_REGION;       \
    }                                                                   \
  } while(0)

#define RPL_LOLLIPOP_IS_INIT(counter)		\
  ((counter) > RPL_LOLLIPOP_CIRCULAR_REGION)

struct rpl_instance {
	/* Instances list_head link */
	struct list_head	instances_list;
	struct net 			*net;

	__u8				instanceID;

	/* Objective Function */
	struct rpl_of		*of;

	/* Automatic generated on operation
	 * otherwise, it means that was created by user configuration
	 * */
	bool				auto_gen;

	atomic_t			refcnt;
};

struct rpl_dag_conf {
	bool use_defaults;
	bool root;
	bool grounded;

	/*
	 * DODAG Root router config
	 */
	__u8 DIOIntDoubl;
	__u8 DIOIntMin;
	__u8 DIORedun;
	__u8 PCS;
	rpl_rank_t MinHopRankIncrease;
	__u8 preference;
	struct in6_addr dodagid;
	//FIXME @see http://tools.ietf.org/html/rfc6550#section-18.2.5

	/*
	 * Every Router config
	 */
	rpl_ocp_t ocp;
	__u8 instanceID;
	__u8 mop;
	struct prefix_info 	prefix_info;

	//FIXME @see http://tools.ietf.org/html/rfc6550#section-18.2.3

	/*
	 * Non-DODAG-Root router config
	 */
	//FIXME @see http://tools.ietf.org/html/rfc6550#section-18.2.4
};

struct rpl_dag {
	/* Dodags list_head link (used by struct instance) */
	struct list_head 	dag_list;

	/* respective instance */
	struct rpl_instance *instance;

	/* DODAG Id */
	struct in6_addr		dodagid;

	__u8				version;
	rpl_rank_t			rank;
	__u8				DAOSequence;

	bool				is_root;

	bool				grounded;
	__u8				mop;
	__u8				preference;
	__u8				DTSN;

	int					unreachable_counter;

	struct trickle_timer	*dio_timer;

	struct timer_list	dao_timer;
	struct workqueue_struct		*dao_tx_wq;

	bool				authenticated;
	__u8				PCS;
	__u8 				DIOIntDoubl;
	__u8				DIOIntMin;
	__u8				DIORedun;
	rpl_rank_t			MaxRankIncrease;
	rpl_rank_t			MinHopRankIncrease;
	__u8				def_lifetime;
	__u16				lifetime_unit;
	struct prefix_info	*prefix_info;

	struct mutex		parents_lock;
	struct list_head	dodag_parents;	// list of rpl_node's
	struct list_head	neighbours;	// list of rpl_node's

	struct list_head	targets_head;

	/* Automatic generated on operation
	 * otherwise, it means that was created by user configuration
	 * */
	bool				auto_gen;

	/* Interfaces allowed to join this dag
	 * */
	struct list_head	allowed_interfaces;	/* list of struct rpl_allowed_if */

	atomic_t			refcnt;
};

struct rpl_allowed_if {
	struct list_head	allowed_if_list;
	//struct inet6_dev	*idev;
	struct net_device	*dev;

	bool				enabled;

	/* Automatic generated on operation
	 * otherwise, it means that was created by user configuration
	 * */
	bool				auto_gen;

	__u8				node_addr_path_sequence;
	struct in6_addr		global_addr;
};

struct rpl_node {
	/* nodes list_head link */
	struct list_head	node_list;

	struct rpl_dag		*dag;

	__u8				metric_link;

	/* storing mode elements */
	struct in6_addr		addr;
	//struct inet6_dev	*idev;
	struct net_device	*dev;

	bool				is_dao_parent;
	bool				is_dodag_parent;
	bool				is_preferred;

	rpl_rank_t			rank;
	__u8				dtsn;
};

struct rpl_target_transit_info {
	struct list_head transit_info_list;
	//struct inet6_dev *idev;
	struct net_device *dev;
	struct in6_addr next_hop;
	bool			installed;
	bool			one_hop;
	__u8 DAOSequence;
	__u8 path_sequence;
	__u8 path_lifetime;
	__u8 path_control;
};

struct rpl_target {
	struct list_head	target_list;
	__u8				prefix_len;
	struct in6_addr		prefix;
	struct list_head	transit_head;
	__u32 target_descriptor;
};

struct rpl_of {
	/* Objective Functions list_head link */
	struct list_head 	of_list;
	rpl_ocp_t 			ocp;
	struct rpl_of_ops	*ops;
};

struct rpl_of_ops {
	struct module	*owner;
	void (*reset)(struct rpl_dag *dag);
	void (*parent_state_callback)(struct rpl_node *parent, void *data);
	struct rpl_node *(*best_parent)(struct rpl_node *parent1, struct rpl_node *parent2);
	int (*compare_nodes)(struct rpl_node *n1, struct rpl_node *n2);
	struct rpl_dag *(*best_dag)(struct rpl_dag *dag1, struct rpl_dag *dag2);
	rpl_rank_t (*calculate_rank)(struct rpl_node *node, rpl_rank_t base);
	void (*update_metric_container)(struct rpl_instance *instance);
};

#endif /* RPL_TYPES_H_ */
