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
 * @file rpl_internals.h
 *
 * @date Jul 22, 2013
 * @author Joao Pedro Taveira
 */

#ifndef RPL_INTERNALS_H_
#define RPL_INTERNALS_H_

#ifdef CONFIG_IPV6_RPL

#define RPL_DIO_IS_GROUNDED(x) ((x & 0x80) >> 7)
#define RPL_DIO_MOP(x) ((x & 0x38) >> 3)
#define RPL_DIO_Prf(x) ((x & 0x07) >> 0)

#define RPL_DAO_FLAGS(x) ((x & 0x3F) >> 0)
#define RPL_DAO_K(x) ((x & 0x80) >> 7)
#define RPL_DAO_D(x) ((x & 0x40) >> 6)

#define RPL_DAO_ACK_Reserved(x) ((x & 0x3F) >> 0)
#define RPL_DAO_ACK_D(x) ((x & 0x80) >> 7)

#define RPL_CC_Flags(x) ((x & 0x3F) >> 0)
#define RPL_CC_IS_RESPONSE(x) ((x & 0x80) >> 7)

#define RPL_RIO_Prf(x) ((x & 0x18) >> 3)

#define RPL_TIO_E(x) ((x & 0x80) >> 7)

#define RPL_SIO_V(x) ((x & 0x80) >> 7)
#define RPL_SIO_I(x) ((x & 0x40) >> 6)
#define RPL_SIO_D(x) ((x & 0x20) >> 5)

#define RPL_PIO_L(x) ((x & 0x80) >> 7)
#define RPL_PIO_A(x) ((x & 0x40) >> 6)
#define RPL_PIO_R(x) ((x & 0x20) >> 5)

#define RPL_DCO_Flags(x) ((x & 0xF0) >> 4)
#define RPL_DCO_A(x) ((x & 0x08) >> 3)
#define RPL_DCO_PCS(x) ((x & 0x07) >> 0)

#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/leds.h>
#include <net/rpl/rpl_dag.h>

//extern struct workqueue_struct	*rpl_rx_wq;

//DEFINE_LED_TRIGGER_GLOBAL(ledtrig_rpl_joined);
extern struct led_trigger *ledtrig_rpl_joined;

//extern struct mutex rpl_enabled_devices_list_mutex;
//extern struct list_head rpl_enabled_devices_list_head;
//
//extern struct mutex rpl_dags_list_mutex;
//extern struct list_head rpl_dags_list_head;

#include <net/if_inet6.h>

struct rpl_base_option {
	__u8	type;
	__u8	length;
};

struct rpl_option_pad1 {
	__u8	type;
};

struct rpl_option_padn {
	struct	rpl_base_option	base;
	__u8	zeros[0];
};

struct rpl_option_dag_metric_container {
	struct	rpl_base_option	base;
	__u8	data[0];
};

struct rpl_option_route_information {
	struct	rpl_base_option	base;
	__u8	prefix_length;
	__u8	Resvd_Prf_Resvd;	// prefix flags
	__be32	route_lifetime;
	__u8	prefix[0];
};

struct rpl_option_dodag_configuration {
	struct	rpl_base_option base;
	__u8	flags_A_PCS;
	__u8	DIOIntDoubl;
	__u8	DIOIntMin;
	__u8	DIORedun;
	__be16	MaxRankIncrease;
	__be16	MinHopRankIncrease;
	__be16	OCP;
	__u8	reserved;
	__u8	def_lifetime;
	__be16	lifetime_unit;
};

struct rpl_option_rpl_target {
	struct	rpl_base_option base;
	__u8	reserved;
	__u8	prefix_length;
	__u8	prefix[0];
};

struct rpl_option_transit_information {
	struct	rpl_base_option base;
	__u8	E_flags;
	__u8	path_control;
	__u8	path_sequence;
	__u8	path_lifetime;
	struct	in6_addr	parent;
};

struct rpl_option_solicited_information {
	struct	rpl_base_option base;
	__u8	instanceID;
	__u8	VID_flags;
	struct	in6_addr	dodagid;
	__u8	version;
};

struct rpl_option_prefix_information {
	struct	rpl_base_option base;
	__u8	prefix_length;
	__u8	LAR_reserved1;	// prefix flags
	__be32	valid_lifetime;
	__be32	preferred_lifetime;
	__be32	reserved2;
	union {
		struct	in6_addr address;
		__u8	prefix[0];
	};
};

struct rpl_option_rpl_target_descriptor {
	struct	rpl_base_option base;
	__be32	descriptor;
};

typedef union rpl_option {
	struct rpl_option_pad1 pad1;
	struct rpl_option_padn padn;
	struct rpl_option_dag_metric_container dag_metric_container;
	struct rpl_option_route_information route_information;
	struct rpl_option_dodag_configuration dodag_configuration;
	struct rpl_option_rpl_target rpl_target;
	struct rpl_option_transit_information transit_information;
	struct rpl_option_solicited_information solicited_information;
	struct rpl_option_prefix_information prefix_information;
	struct rpl_option_rpl_target_descriptor rpl_target_descriptor;
} u_rpl_option;

struct rpl_base_dis {
	__u8 flags;
	__u8 reserved;
	u_rpl_option dis_options[0];
};

struct rpl_base_dio {
	__u8	instanceID;
	__u8	version;
	__be16	rank;
	__u8	g_mop_prf;
	__u8	DTSN;
	__u8	flags;
	__u8	reserved;
	struct in6_addr	dodagid;
	u_rpl_option dio_options[0];
};

struct rpl_base_dao {
	__u8	instanceID;
	__u8	KD_flags;
	__u8	reserved;
	__u8	DAOSequence;
	union {
		struct dao_with_dodagid {
			struct in6_addr	dodagid;
			u_rpl_option dao_options[0];
		} u_with_dodagid;
		struct dao_no_dodagid {
			u_rpl_option dao_options[0];
		} u_no_dodagid;
	};
};

struct rpl_base_dao_ack {
	__u8	instanceID;
	__u8	D_reserved;
	__u8	DAOSequence;
	__u8	status;
	union {
		struct doa_ack_with_dodagid {
			struct in6_addr	dodagid;
			u_rpl_option dao_ack_options[0];
		} u_with_dodagid;
		struct doa_ack_no_dodagid {
			u_rpl_option dao_ack_options[0];
		} u_no_dodagid;
	};
};

struct rpl_base_cc {
	__u8	instanceID;
	__u8	R_flags;
	__be16	CCNonce;
	struct	in6_addr	dodagid;
	__be32	dest_counter;
	u_rpl_option cc_options[0];
};

typedef union rpl_base	{
	struct rpl_base_dis 	dis;
	struct rpl_base_dio 	dio;
	struct rpl_base_dao 	dao;
	struct rpl_base_dao_ack	dao_ack;
	struct rpl_base_cc		cc;
} u_icmpv6_rpl_base;

struct rpl_msg {
    __u8	icmp6_type;   /* type field */
    __u8	icmp6_code;   /* code field */
    __sum16	icmp6_cksum;  /* checksum field */

	u_icmpv6_rpl_base	base;
};

struct rpl_enabled_device {
	struct list_head	enabled_list;
	//struct inet6_dev	*idev;
	struct net_device	*dev;
	struct timer_list	dis_timer;
	bool				joined_mc;
	//FIXME how many solicited information could we add to an enabled device??
	struct rpl_option_solicited_information *solicited_information;
};

struct sk_buff *icmpv6_rpl_dis_new(struct net_device *dev);
struct sk_buff *icmpv6_rpl_dio_new(
		struct net_device *dev,
		__u8 instanceID,
		__u8 version,
		rpl_rank_t rank,
		bool g,
		__u8 mop,
		__u8 prf,
		__u8 DTSN,
		struct in6_addr *dodagid);
struct sk_buff *icmpv6_rpl_dao_new(
		struct net_device *dev,
		__u8 instanceID,
		__u8 expect_DAO_ACK,
		__u8 DAOSequence,
		struct in6_addr *dodagid);
struct sk_buff *icmpv6_rpl_dao_ack_new(
		struct net_device *dev,
		__u8 instanceID,
		__u8 DAOSequence,
		__u8 status,
		const struct in6_addr *dodagid);
struct sk_buff *icmpv6_rpl_cc_new(
		struct net_device *dev,
		__u8 instanceID,
		__u8 is_response,
		__u16 CCNonce,
		struct in6_addr *dodagid,
		__u32 dest_counter);

struct sk_buff *icmpv6_rpl_add_option_pad1(struct sk_buff *rpl_msg_buf);
struct sk_buff *icmpv6_rpl_add_option_padn(struct sk_buff *rpl_msg_buf, __u8 n);
struct sk_buff *icmpv6_rpl_add_option_dag_metric_container(struct sk_buff *rpl_msg_buf, __u8 *metric_data, __u8 metric_data_len);
struct sk_buff *icmpv6_rpl_add_option_route_information(struct sk_buff *rpl_msg_buf, __u8 prefix_length, __u8 prf, __u32 route_lifetime, __u8 prefix[16]);
struct sk_buff *icmpv6_rpl_add_option_dodag_configuration(
		struct sk_buff *rpl_msg_buf,
		bool auth,
		__u8 PCS,
		__u8 DIOIntDoubl,
		__u8 DIOIntMin,
		__u8 DIORedun,
		rpl_rank_t MaxRankIncrease,
		rpl_rank_t MinHopRankIncrease,
		rpl_ocp_t OCP,
		__u8 def_lifetime,
		__u16 lifetime_unit);
struct sk_buff *icmpv6_rpl_add_option_rpl_target(struct sk_buff *rpl_msg_buf,__u8 prefix_length,__u8 target_prefix[16]);
struct sk_buff *icmpv6_rpl_add_option_transit_information(struct sk_buff *rpl_msg_buf,__u8 external, __u8 path_control, __u8 path_sequence, __u8 path_lifetime, struct in6_addr *parent_address);
struct sk_buff *icmpv6_rpl_add_option_solicited_information(
		struct sk_buff *rpl_msg_buf,
		__u8 instanceID,
		__u8 version_predicate,
		__u8 instanceID_predicate,
		__u8 DODAGID_predicate,
		struct in6_addr *dodagid,
		__u8 version);
struct sk_buff *icmpv6_rpl_add_option_prefix_information(
		struct sk_buff *rpl_msg_buf,
		__u8 prefix_length,
		__u8 on_link,
		__u8 autonomous,
		__u8 router_address,
		__u32	valid_lifetime,
		__u32	preferred_lifetime,
		__u8 prefix[16]);
struct sk_buff *icmpv6_rpl_add_option_rpl_target_descriptor(struct sk_buff *rpl_msg_buf,__u32 descriptor);

int icmpv6_rpl_is_option_allowed(__u8 message_type, __u8 option_type);

extern u_rpl_option *icmpv6_rpl_option_get_next(u_rpl_option *first, u_rpl_option *current_option, size_t len);

extern __u8 icmpv6_rpl_option_get_code(u_rpl_option *option);

extern __u8 icmpv6_rpl_option_get_length(u_rpl_option *option);

extern u_rpl_option *icmpv6_rpl_find_option(struct sk_buff *skb, __u8 req_type);

extern int rpl_start(struct rpl_dag_conf *cfg, struct net_device *dev);

extern int rpl_stop(struct net_device *dev);

extern int rpl_send_dis(struct rpl_enabled_device *enabled_device);

extern int rpl_send_dio(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *daddr, bool add_dodag_conf_option, bool poison);

extern int rpl_send_dao(struct rpl_dag *dag, struct net_device *dev, bool allnodes, bool no_path);

extern int rpl_recv_dis(struct net_device *dev,struct sk_buff *skb);

extern int rpl_recv_dio(struct net_device *dev,struct sk_buff *skb);

extern int rpl_recv_dao(struct net_device *dev,struct sk_buff *skb);

#endif /* CONFIG_IPV6_RPL */

#endif /* RPL_INTERNALS_H_ */
