/*
 *	RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
 *	Linux RPL implementation
 *
 *	Authors:
 *  Sergey Lapin <slapin@ossfans.org>
 *  Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 *  Maxim Osipov <maxim.osipov@siemens.com>
 *	Joao Pedro Taveira	<joao.silva@inov.pt>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License.
 */

#include <linux/kernel.h>
#include <net/netlink.h>
#include <linux/rpl_nl.h>
#include <linux/in6.h>

#define NLA_RPL_RANK NLA_U16

const struct nla_policy rpl_policy[RPL_ATTR_MAX + 1] = {
	[RPL_ATTR_DEV_NAME] = { .type = NLA_STRING, },
	[RPL_ATTR_DEV_INDEX] = { .type = NLA_U32, },
	[RPL_ATTR_DEV_ENABLED] = { .type = NLA_U8, },
	[RPL_ATTR_DEV_AUTOGEN] = { .type = NLA_U8, },

	[RPL_ATTR_OCP] = { .type = NLA_U16, },
	[RPL_ATTR_INSTANCE_ID] = { .type = NLA_U8, },

	[RPL_ATTR_DODAG_ID] = { .len = sizeof(struct in6_addr), },

	[RPL_ATTR_RANK] = { .type = NLA_RPL_RANK, },
	[RPL_ATTR_VERSION] = { .type = NLA_U8, },
	[RPL_ATTR_MOP] = { .type = NLA_U8, },
	[RPL_ATTR_DTSN] = { .type = NLA_U8, },
	[RPL_ATTR_DAO_SEQUENCE] = { .type = NLA_U8, },

	[RPL_ATTR_GROUNDED] = { .type = NLA_U8, },
	[RPL_ATTR_IS_ROOT] = { .type = NLA_U8, },

	[RPL_ATTR_PCS] = { .type = NLA_U8, },
	[RPL_ATTR_DIO_INT_DOUBL] = { .type = NLA_U8, },
	[RPL_ATTR_DIO_INT_MIN] = { .type = NLA_U8, },
	[RPL_ATTR_DIO_REDUN] = { .type = NLA_U8, },
	[RPL_ATTR_MAX_RANK_INCR] = { .type = NLA_RPL_RANK, },
	[RPL_ATTR_MIN_HOP_RANK_INCR] = { .type = NLA_RPL_RANK, },

	[RPL_ATTR_DEF_LIFETIME] = { .type = NLA_U8, },
	[RPL_ATTR_LIFETIME_UNIT] = { .type = NLA_U16, },

	[RPL_ATTR_NODE_ADDR] = { .len = sizeof(struct in6_addr), },
	[RPL_ATTR_IS_DODAG_PARENT] = { .type = NLA_U8, },
	[RPL_ATTR_IS_DAO_PARENT] = { .type = NLA_U8, },
	[RPL_ATTR_IS_PREFERRED] = { .type = NLA_U8, },

	[RPL_ATTR_PREFIX] = { .len = sizeof(struct in6_addr), },
	[RPL_ATTR_PREFIX_LEN] = { .type = NLA_U8, },
	[RPL_ATTR_NEXT_HOP] = { .len = sizeof(struct in6_addr), },
	[RPL_ATTR_ONE_HOP] = { .type = NLA_U8, },

};
