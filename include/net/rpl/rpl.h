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
 * @file rpl.h
 *
 * @date Aug 20, 2013
 * @author Joao Pedro Taveira
 */

#ifndef RPL_H_
#define RPL_H_

/*
 *  ICMPv6 message type
 */
#define ICMPV6_RPL 155

extern int rpl_rcv(struct sk_buff *skb);

extern int	rpl_init(void);
extern void	rpl_cleanup(void);

extern int rpl_sysctl_rpl_enabled(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos);

extern int rpl_sysctl_rpl_joined(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos);

extern int rpl_sysctl_rpl_dodag_root(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos);

extern int rpl_sysctl_rpl_icmp_dump(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos);

#endif /* RPL_H_ */
