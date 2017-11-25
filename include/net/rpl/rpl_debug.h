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
 * @file icmpv6_rpl_debug.h
 *
 * @date Jul 23, 2013
 * @author Joao Pedro Taveira
 */

#ifndef ICMPV6_RPL_DEBUG_H_
#define ICMPV6_RPL_DEBUG_H_

#ifdef CONFIG_IPV6_RPL

#include <net/rpl/rpl_internals.h>

//#define RPL_CONFIG_DEBUG_NETDEV

#ifdef RPL_CONFIG_DEBUG_NETDEV
extern int netdev_debug;
extern void __dev_hold(struct net_device *, const char *);
extern void __dev_put(struct net_device *, const char *);

#define dev_hold(dev)	__dev_hold(dev, __FUNCTION__)
#define dev_put(dev)	__dev_put(dev, __FUNCTION__)
#else
#define dev_hold(dev)	dev_hold(dev)
#define dev_put(dev)	dev_put(dev)
#endif


extern void icmpv6_rpl_print_msg(struct rpl_msg *msg, size_t len);

extern ssize_t icmpv6_rpl_print_option(__u8 *offset);

//void rpl_msg_buf_print(struct rpl_msg_buf *rpl_msg_buf);

#endif /* CONFIG_IPV6_RPL */

#endif /* ICMPV6_RPL_DEBUG_H_ */
