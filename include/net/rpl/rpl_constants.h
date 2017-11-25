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
 * @file rpl_constants.h
 *
 * @date Aug 20, 2013
 * @author Joao Pedro Taveira
 */

#ifndef RPL_CONSTANTS_H_
#define RPL_CONSTANTS_H_

#include <linux/in6.h>

/*
 * RPL Defaults
 */

/*
 * Rank for a virtual root that might be used to coordinate multiple roots
 */
#define RPL_BASE_RANK 0

/*
 * constant maximum for the Rank
 */
#define RPL_INFINITE_RANK 0xffff

/*
 * RPLInstanceID that is used by this protocol by a node without any overriding policy.
 */
#define RPL_DEFAULT_INSTANCE 0

/*
 * default value used to configure PCS in the DODAG Configuration option
 * (dictates the number of significant bits in the Path Control field of the Transit Information option)
 * value 0 means that a router sends a DAO to only one of its parents
 */
#define RPL_DEFAULT_PATH_CONTROL_SIZE 0

/*
 * default value used to configure Imin for the DIO Trickle timer
 */
#define RPL_DEFAULT_DIO_INTERVAL_MIN 3  // 8 ms

/*
 * default value used to configure Imax for the DIO Trickle timer
 */
#define RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS 20  // 2.3 hours

/*
 * default value used to configure k for the DIO Trickle timer
 */
#define RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT 10

/*
 * default value of MinHopRankIncrease
 */
#define RPL_DEFAULT_MIN_HOP_RANK_INCREASE 256

/*
 * default value for the DelayDAO Timer
 */
#define RPL_DEFAULT_DAO_DELAY 1

/*
 * default duration to wait in order to receive a DAO-ACK message
 * (this value is not defined in the RFC)
 */
#define RPL_DEFAULT_DAO_ACK_DELAY 2

/*
 * number of times the node should try to send a DAO message before giving up
 * (this value is not defined in the RFC)
 */
#define RPL_DEFAULT_DAO_MAX_TRANS_RETRY 3

/*
 * number of time a DAO will transmit No-Path that contains information on
 * routes that recently have been deleted
 */
#define RPL_DEFAULT_DAO_NO_PATH_TRANS 3

/*
 * default maximum rank increased (0 means the mechanism is disabled)
 */
#define RPL_DEFAULT_MAX_RANK_INCREASE 3 * RPL_DEFAULT_MIN_HOP_RANK_INCREASE

/*
 * Rank for a DODAG root See Section 17: ROOT_RANK has a value of MinHopRankIncrease
 */
#define RPL_ROOT_RANK RPL_DEFAULT_MIN_HOP_RANK_INCREASE

#define RPL_DIS_INTERVAL 		60 // seconds
#define RPL_DIS_INIT_INTERVAL	5	// seconds

#define RPL_OF_OF0				0
#define RPL_OF_MRHOF			1

#define MODULE_ALIAS_RPL_OF(OCP) \
	MODULE_ALIAS("rpl-of-" __stringify(OCP))

#define RPL_MOP_NO_DOWNWARD_ROUTES		0
#define RPL_MOP_NON_STORING_MODE		1
#define RPL_MOP_STORING_MODE_WITHOUT_MC	2
#define RPL_MOP_STORING_MODE_WITH_MC	3

/*
 * ICMPv6 message codes for RPL messages
 */
#define ICMPV6_RPL_DIS			0x00
#define ICMPV6_RPL_SEC_DIS		0x80

#define ICMPV6_RPL_DIO			0x01
#define ICMPV6_RPL_SEC_DIO		0x81

#define ICMPV6_RPL_DAO			0x02
#define ICMPV6_RPL_SEC_DAO		0x82

#define ICMPV6_RPL_DAO_ACK		0x03
#define ICMPV6_RPL_SEC_DAO_ACK	0x83

#define ICMPV6_RPL_CC			0x8A

/*
 * RPL control message option type
 */
#define ICMPV6_RPL_OPT_Pad1						0x00
#define ICMPV6_RPL_OPT_PadN						0x01
#define ICMPV6_RPL_OPT_DAG_Metric_Container		0x02
#define ICMPV6_RPL_OPT_Route_Information		0x03
#define ICMPV6_RPL_OPT_DODAG_Configuration		0x04
#define ICMPV6_RPL_OPT_RPL_Target				0x05
#define ICMPV6_RPL_OPT_Transit_Information		0x06
#define ICMPV6_RPL_OPT_Solicited_Information	0x07
#define ICMPV6_RPL_OPT_Prefix_Information		0x08
#define ICMPV6_RPL_OPT_RPL_Target_Descriptor	0x09


#ifdef CONFIG_IPV6_RPL
#define IN6ADDR_ALL_RPL_NODES_INIT \
		{ { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0x1a } } }
extern const struct in6_addr in6addr_all_rpl_nodes;
#endif /* CONFIG_IPV6_RPL */

#endif /* RPL_CONSTANTS_H_ */

