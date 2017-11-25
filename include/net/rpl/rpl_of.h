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
 * @file rpl_of.h
 *
 * @date Aug 20, 2013
 * @author Joao Pedro Taveira
 */

#ifndef RPL_OF_H_
#define RPL_OF_H_

#include <net/rpl/rpl_constants.h>
#include <net/rpl/rpl_types.h>

/*
 * Objective Function Interface
 */
extern struct rpl_of *rpl_of_alloc(rpl_ocp_t ocp, struct rpl_of_ops *ops);
extern void rpl_of_free(struct rpl_of *of);
extern int rpl_of_register(struct rpl_of *of);
extern void rpl_of_unregister(struct rpl_of *of);
extern struct rpl_of *rpl_of_get(rpl_ocp_t ocp);
extern rpl_rank_t rpl_of_calculate_rank(struct rpl_of *of, struct rpl_node *parent,
		rpl_rank_t base, int *err);
extern int rpl_of_compare_nodes(struct rpl_of *of, struct rpl_node *p1,
		struct rpl_node *p2, int *err);

#endif /* RPL_OF_H_ */
