/*
 *	RPL: Objective Function Zero for the Routing Protocol
 *	for Low-Power and Lossy Networks (RFC 6552)
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
 * @file rpl_of_of0.c
 *
 * @date Aug 2, 2013
 * @author Joao Pedro Taveira
 */

#include <linux/module.h>
#include <linux/init.h>

#if IS_ENABLED(CONFIG_IPV6_RPL)
#include <net/rpl/rpl_of.h>
#endif

static void reset(struct rpl_dag *dag)
{

}

static void parent_state_callback(struct rpl_node *node, void *data)
{

}

static int compare_nodes(struct rpl_node *parent1, struct rpl_node *parent2)
{
	rpl_rank_t rank1, rank2;
	if(!parent1)
		return 1;
	if(!parent2)
		return -1;
	if(parent1->dag == parent2->dag &&
			parent1->dag->version != parent2->dag->version)
		return (parent1->dag->version > parent2->dag->version)?-1:(parent1->dag->version < parent2->dag->version)?1:0;
	rank1 = parent1->dag->instance->of->ops->calculate_rank(parent1,0);
	rank2 = parent2->dag->instance->of->ops->calculate_rank(parent2,0);
	if(DAGRank(rank1,parent1->dag) != DAGRank(rank2,parent2->dag))
		return (rank1 < rank2)?-1:(rank1 > rank2)?1:0;

	//printk(KERN_DEBUG "%s(): p1: %pI6 rank: %u %u %u p2: %pI6 rank: %u %u %u\n",__func__,&parent1->addr,parent1->rank,DAGRank(rank1,parent1->dag),rank1,&parent2->addr,parent2->rank,DAGRank(rank2,parent2->dag),rank2);
	return 0;
}

static struct rpl_node *best_parent(struct rpl_node *parent1, struct rpl_node *parent2)
{
	rpl_rank_t rank1, rank2;
	if(!parent1)
		return parent2;
	if(!parent2)
		return parent1;
	if(parent1->dag == parent2->dag &&
			parent1->dag->version != parent2->dag->version)
		return (parent1->dag->version > parent2->dag->version)?parent1:parent2;
	rank1 = parent1->dag->instance->of->ops->calculate_rank(parent1,0);
	rank2 = parent2->dag->instance->of->ops->calculate_rank(parent2,0);
	if(DAGRank(rank1,parent1->dag) != DAGRank(rank2,parent2->dag))
		return (rank1 - rank2 > 0)?parent1:parent2;
	return parent1;
}

static struct rpl_dag *best_dag(struct rpl_dag *dag1, struct rpl_dag *dag2)
{
	if(dag1->grounded) {
		if (!dag2->grounded) {
			return dag1;
		}
	} else if(dag2->grounded) {
		return dag2;
	}

	if(dag1->preference < dag2->preference) {
		return dag2;
	} else {
		if(dag1->preference > dag2->preference) {
			return dag1;
		}
	}

	if(dag2->rank < dag1->rank) {
		return dag2;
	} else {
		return dag1;
	}
}

static rpl_rank_t calculate_rank(struct rpl_node *node, rpl_rank_t base_rank)
{
	rpl_rank_t increment;
	if(base_rank == 0)
	{
		if(!node)
		{
			return RPL_INFINITE_RANK;
		}
		base_rank = node->rank;
	}
	increment = (node != NULL)?node->dag->MinHopRankIncrease:RPL_DEFAULT_MIN_HOP_RANK_INCREASE;
	//printk(KERN_DEBUG "OF0: %s(): increment: %u base_rank: %u\n",__func__,increment,base_rank);
	if((rpl_rank_t)(base_rank + increment) < base_rank)
	{
		return RPL_INFINITE_RANK;
	}
	//printk(KERN_DEBUG "OF0: %s(): increment + base_rank: %d\n",__func__,base_rank + increment);
	return base_rank + increment;
}

static void update_metric_container(struct rpl_instance *instance)
{

}

static struct rpl_of_ops of_of0_ops = {
		.owner = THIS_MODULE,
		.reset = reset,
		.parent_state_callback = parent_state_callback,
		.best_parent = best_parent,
		.compare_nodes = compare_nodes,
		.best_dag = best_dag,
		.calculate_rank = calculate_rank,
		.update_metric_container = update_metric_container,
};

static __init int rpl_of_of0_init(void)
{
	struct rpl_of *of0;
	int err = 0;

	printk(KERN_INFO "RPL: Objective Function Zero (RFC 6552)\n");

	of0 = rpl_of_alloc(RPL_OF_OF0,&of_of0_ops);
	if(!of0)
	{
		printk(KERN_ERR "RPL: %s(): error creating rpl of\n",__func__);
		err = -ENOMEM;
		goto out;
	}
	err = rpl_of_register(of0);
	if(err)
	{
		printk(KERN_ERR "RPL: %s(): error registering rpl of\n",__func__);
		rpl_of_free(of0);
		goto out;
	}
	return 0;
out:
	return err;
}

static __exit void rpl_of_of0_exit(void)
{
	struct rpl_of *of0;
	of0 = rpl_of_get(RPL_OF_OF0);
	if(of0)
	{
		rpl_of_unregister(of0);
		rpl_of_free(of0);
	}
}

module_init(rpl_of_of0_init);
module_exit(rpl_of_of0_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("João Pedro Taveira");
MODULE_DESCRIPTION("RPL: Objective Function Zero (RFC 6552)");
MODULE_ALIAS_RPL_OF(RPL_OF_OF0);

