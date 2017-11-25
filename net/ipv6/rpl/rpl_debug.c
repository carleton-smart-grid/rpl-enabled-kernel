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
 * @file rpl_debug.c
 *
 * @date Jul 23, 2013
 * @author Joao Pedro Taveira
 */

#define DEBUG 1

#ifdef __KERNEL__
#include <linux/inet.h>
#include <net/sock.h>
#include <net/rpl/rpl_debug.h>
#include <net/rpl/rpl_constants.h>
#else
#include <stdio.h>
#include <arpa/inet.h>
#endif /* __KERNEL__ */

#ifdef RPL_CONFIG_DEBUG_NETDEV
/* This is for debugging reference counting of devices */
int netdev_debug __read_mostly = 1;

void __dev_hold(struct net_device *dev, const char *func)
{
	this_cpu_inc(*dev->pcpu_refcnt);
	if (unlikely(netdev_debug))
		printk(KERN_DEBUG "%s(%X): dev_hold %d %s\n",dev->name, dev, netdev_refcnt_read(dev), func);
}
EXPORT_SYMBOL(__dev_hold);

void __dev_put(struct net_device *dev, const char *func)
{
	BUG_ON(netdev_refcnt_read(dev) == 0);
	if (unlikely(netdev_debug))
		printk(KERN_DEBUG "%s(%X): dev_put %d %s\n",dev->name, dev, netdev_refcnt_read(dev), func);
	this_cpu_dec(*dev->pcpu_refcnt);
}
EXPORT_SYMBOL(__dev_put);
#endif

ssize_t icmpv6_rpl_print_option(__u8 *offset)
{
	int i = 0;
	__u8 type = 0;
	__u8 len = 0;
	u_rpl_option *option = NULL;
#ifndef __KERNEL__
	char s_in6_addr[INET6_ADDRSTRLEN] = {};
#endif
	if(!offset)
		return -1;
	type = *(offset);

	printk(KERN_DEBUG "%s(): ___________________________________\n", __func__);
	/*
	 * NOTE!  The format of the Pad1 option is a special case,
	 * it has neither Option Length nor Option Data fields.
	 */
	if(type == ICMPV6_RPL_OPT_Pad1)
	{
		printk(KERN_DEBUG "%s(): Type: Pad1\n", __func__);
		return 1;
	}

	len = *(offset+1);

	printk(KERN_DEBUG "%s(): Length: %u\n", __func__,len);

	option = (u_rpl_option *) offset;

	switch(type){
	case ICMPV6_RPL_OPT_PadN:
		printk(KERN_DEBUG "%s(): Type: PadN\n", __func__);
		break;
	case ICMPV6_RPL_OPT_DAG_Metric_Container:
		printk(KERN_DEBUG "%s(): Type: DAG Metric Container\n", __func__);
		printk(KERN_DEBUG "%s(): Data: ", __func__);
		for(i=0;i<len;i++){
			printk("%02X ",option->dag_metric_container.data[i]);
		}
		printk("\n");
		break;
	case ICMPV6_RPL_OPT_Route_Information:
		printk(KERN_DEBUG "%s(): Type: Route Information\n", __func__);
		printk(KERN_DEBUG "%s(): Prefix Length: %d\n", __func__,option->route_information.prefix_length);
		printk(KERN_DEBUG "%s(): Preference: %d\n", __func__,RPL_RIO_Prf(option->route_information.Resvd_Prf_Resvd));
		printk(KERN_DEBUG "%s(): Route Lifetime: %d\n", __func__,be32_to_cpu(option->route_information.route_lifetime));
		printk(KERN_DEBUG "%s(): Prefix: ", __func__);
		for(i=0;i<option->route_information.prefix_length/8;i++){
			printk("%02X ",option->route_information.prefix[i]);
		}
		printk("\n");
		break;
	case ICMPV6_RPL_OPT_DODAG_Configuration:
		printk(KERN_DEBUG "%s(): Type: DODAG Configuration\n", __func__);
		if(RPL_DCO_A(option->dodag_configuration.flags_A_PCS))
		{
			printk(KERN_DEBUG "%s(): Authentication Enabled: Yes\n", __func__);
		}
		else
		{
			printk(KERN_DEBUG "%s(): Authentication Enabled: NO\n", __func__);
		}
		printk(KERN_DEBUG "%s(): Path Control Size(PCS): %d\n", __func__,RPL_DCO_PCS(option->dodag_configuration.flags_A_PCS));
		printk(KERN_DEBUG "%s(): Flags: %d\n", __func__,RPL_DCO_Flags(option->dodag_configuration.flags_A_PCS));

		printk(KERN_DEBUG "%s(): DIOIntDoubl: %d\n", __func__,option->dodag_configuration.DIOIntDoubl);
		printk(KERN_DEBUG "%s(): DIOIntMin: %d\n", __func__,option->dodag_configuration.DIOIntMin);
		printk(KERN_DEBUG "%s(): DIORedun: %d\n", __func__,option->dodag_configuration.DIORedun);

		printk(KERN_DEBUG "%s(): MaxRankIncrease: %u\n", __func__,be16_to_cpu(option->dodag_configuration.MaxRankIncrease));
		printk(KERN_DEBUG "%s(): MinHopRankIncrease: %u\n", __func__,be16_to_cpu(option->dodag_configuration.MinHopRankIncrease));

		printk(KERN_DEBUG "%s(): OCP: %d\n", __func__,be16_to_cpu(option->dodag_configuration.OCP));
		printk(KERN_DEBUG "%s(): Default Lifetime: %d\n", __func__,option->dodag_configuration.def_lifetime);
		printk(KERN_DEBUG "%s(): Lifetime Unit: %u\n", __func__,be16_to_cpu(option->dodag_configuration.lifetime_unit));
		break;
	case ICMPV6_RPL_OPT_RPL_Target:
		printk(KERN_DEBUG "%s(): Type: RPL Target\n", __func__);
		printk(KERN_DEBUG "%s(): Prefix Length: %d\n", __func__,option->rpl_target.prefix_length);
		if(option->rpl_target.prefix_length == 128)
		{
#ifdef __KERNEL__
			printk(KERN_DEBUG "%s(): Prefix: %pI6\n",__func__,&option->rpl_target.prefix);
#else
			inet_ntop(AF_INET6, &option->rpl_target.prefix, s_in6_addr, INET6_ADDRSTRLEN);
			printk(KERN_DEBUG "%s(): Prefix: %s\n", __func__,s_in6_addr);
#endif /* __KERNEL__*/
		}
		else
		{
			printk(KERN_DEBUG "%s(): Prefix: ", __func__);
			for(i=0;i<option->rpl_target.prefix_length/8;i++){
				printk("%02X ",option->rpl_target.prefix[i]);
			}
			printk("\n");
		}
		break;
	case ICMPV6_RPL_OPT_Transit_Information:
		printk(KERN_DEBUG "%s(): Type: Transit Information\n", __func__);
		if(RPL_TIO_E(option->transit_information.E_flags))
		{
			printk(KERN_DEBUG "%s(): External: Yes\n", __func__);
		}
		else
		{
			printk(KERN_DEBUG "%s(): External: NO\n", __func__);
		}
		printk(KERN_DEBUG "%s(): PathControl: 0x%02X\n", __func__,option->transit_information.path_control);
		printk(KERN_DEBUG "%s(): PathSequence: %d\n", __func__,option->transit_information.path_sequence);
		printk(KERN_DEBUG "%s(): PathLifetime: %d\n", __func__,option->transit_information.path_lifetime);
		if(len > 4)
		{
#ifdef __KERNEL__
			printk(KERN_DEBUG "%s(): Parent: %pI6\n",__func__,&option->transit_information.parent);
#else
			inet_ntop(AF_INET6, &option->transit_information.parent, s_in6_addr, INET6_ADDRSTRLEN);
			printk(KERN_DEBUG "%s(): Parent: %s\n", __func__,s_in6_addr);
#endif /* __KERNEL__*/
		}
		break;
	case ICMPV6_RPL_OPT_Solicited_Information:
		printk(KERN_DEBUG "%s(): Type: Solicited Information\n", __func__);
		printk(KERN_DEBUG "%s(): InstanceID: %d\n", __func__,option->solicited_information.instanceID);

		if(RPL_SIO_V(option->solicited_information.VID_flags))
		{
			printk(KERN_DEBUG "%s(): Version Predicate: Yes\n", __func__);
		}
		else
		{
			printk(KERN_DEBUG "%s(): Version Predicate: NO\n", __func__);
		}

		if(RPL_SIO_I(option->solicited_information.VID_flags))
		{
			printk(KERN_DEBUG "%s(): InstanceID Predicate: Yes\n", __func__);
		}
		else
		{
			printk(KERN_DEBUG "%s(): InstanceID Predicate: NO\n", __func__);
		}

		if(RPL_SIO_D(option->solicited_information.VID_flags))
		{
			printk(KERN_DEBUG "%s(): DodagID Predicate: Yes\n", __func__);
		}
		else
		{
			printk(KERN_DEBUG "%s(): DodagID Predicate: NO\n", __func__);
		}
#ifdef __KERNEL__
		printk(KERN_DEBUG "%s(): DodagID: %pI6\n",__func__,&option->solicited_information.dodagid);
#else
		inet_ntop(AF_INET6, &option->solicited_information.dodagid, s_in6_addr, INET6_ADDRSTRLEN);
		printk(KERN_DEBUG "%s(): DodagID: %s\n", __func__,s_in6_addr);
#endif /* __KERNEL__*/

		printk(KERN_DEBUG "%s(): Version: %d\n", __func__,option->solicited_information.version);
		break;
	case ICMPV6_RPL_OPT_Prefix_Information:
		printk(KERN_DEBUG "%s(): Type: Prefix Information\n", __func__);
		printk(KERN_DEBUG "%s(): Prefix Length: %d\n", __func__,option->prefix_information.prefix_length);
		if(RPL_PIO_L(option->prefix_information.LAR_reserved1))
		{
			printk(KERN_DEBUG "%s(): On-Link Flag: Yes\n", __func__);
		}
		else
		{
			printk(KERN_DEBUG "%s(): On-Link Flag: NO\n", __func__);
		}
		if(RPL_PIO_A(option->prefix_information.LAR_reserved1))
		{
			printk(KERN_DEBUG "%s(): Autonomous Address-Configuration: Yes\n", __func__);
		}
		else
		{
			printk(KERN_DEBUG "%s(): Autonomous Address-Configuration: NO\n", __func__);
		}
		if(RPL_PIO_R(option->prefix_information.LAR_reserved1))
		{
			printk(KERN_DEBUG "%s(): Router Address: Yes\n", __func__);
		}
		else
		{
			printk(KERN_DEBUG "%s(): Router Address: NO\n", __func__);
		}
		printk(KERN_DEBUG "%s(): Valid Lifetime: %u\n", __func__,be32_to_cpu(option->prefix_information.valid_lifetime));
		printk(KERN_DEBUG "%s(): Preferred Lifetime: %u\n", __func__,be32_to_cpu(option->prefix_information.preferred_lifetime));
		if(option->prefix_information.prefix_length == 128)
		{
#ifdef __KERNEL__
			printk(KERN_DEBUG "%s(): Prefix: %pI6\n",__func__,&option->prefix_information.prefix);
#else
			inet_ntop(AF_INET6, &option->prefix_information.prefix, s_in6_addr, INET6_ADDRSTRLEN);
			printk(KERN_DEBUG "%s(): Prefix: %s\n", __func__,s_in6_addr);
#endif /* __KERNEL__*/
		}
		else
		{
			printk(KERN_DEBUG "%s(): Prefix: ", __func__);
			for(i=0;i<option->prefix_information.prefix_length/8;i++){
				printk("%02X ",option->prefix_information.prefix[i]);
			}
			printk("\n");
		}
		break;
	case ICMPV6_RPL_OPT_RPL_Target_Descriptor:
		printk(KERN_DEBUG "%s(): Type: Target Descriptor\n", __func__);
		printk(KERN_DEBUG "%s(): Descriptor: %u\n", __func__,be32_to_cpu(option->rpl_target_descriptor.descriptor));
		break;
	default:
		printk(KERN_DEBUG "%s(): Type: Unknown (0x%02X)\n", __func__,type);
	}
	return len+2;
}

void icmpv6_rpl_print_options(__u8 *offset, size_t len)
{
	size_t len_printed = 0;
	ssize_t option_len = 0;
	while(len_printed<len){
		if((option_len = icmpv6_rpl_print_option(offset+len_printed))<0)
			break;
		len_printed += option_len;
	}
}

void icmpv6_rpl_print_msg(struct rpl_msg *msg, size_t len)
{
	size_t non_options_len = 4;
#ifndef __KERNEL__
	char s_in6_addr[INET6_ADDRSTRLEN] = {};
#endif
	if(msg)
	{
		if(msg->icmp6_type != ICMPV6_RPL){
			pr_debug("%s: not RPL message\n",__func__);
			return;
		}
		printk(KERN_DEBUG "%s(): ______________________________________________________\n", __func__);
		switch (msg->icmp6_code) {
			case ICMPV6_RPL_DIS:
				printk(KERN_DEBUG "%s(): Code: DIS\n", __func__);
				printk(KERN_DEBUG "%s(): Flags: 0x%02X\n", __func__,msg->base.dis.flags);
				printk(KERN_DEBUG "%s(): Reserved: 0x%02X\n", __func__,msg->base.dis.reserved);
				non_options_len += 2;
				icmpv6_rpl_print_options((__u8 *)msg->base.dis.dis_options,len-non_options_len);
				break;
			case ICMPV6_RPL_DIO:
				printk(KERN_DEBUG "%s(): Code: DIO\n", __func__);
				printk(KERN_DEBUG "%s(): InstanceID: %d\n", __func__,msg->base.dio.instanceID);
				printk(KERN_DEBUG "%s(): Version: %d\n", __func__,msg->base.dio.version);
				printk(KERN_DEBUG "%s(): Rank: %u\n", __func__,be16_to_cpu(msg->base.dio.rank));
				if(RPL_DIO_IS_GROUNDED(msg->base.dio.g_mop_prf))
				{
					printk(KERN_DEBUG "%s(): Grounded: Yes\n", __func__);
				}
				else
				{
					printk(KERN_DEBUG "%s(): Grounded: No, floating\n", __func__);
				}
				printk(KERN_DEBUG "%s(): MOP: %d\n", __func__,RPL_DIO_MOP(msg->base.dio.g_mop_prf));
				switch(RPL_DIO_MOP(msg->base.dio.g_mop_prf))
				{
				case 0:
					printk(KERN_DEBUG "%s(): MOP: 0: No Downward routes maintained by RPL\n",__func__);
					break;
				case 1:
					printk(KERN_DEBUG "%s(): MOP: 1: Non-Storing Mode of Operation\n",__func__);
					break;
				case 2:
					printk(KERN_DEBUG "%s(): MOP: 2: Storing Mode of Operation with no multicast support\n",__func__);
					break;
				case 3:
					printk(KERN_DEBUG "%s(): MOP: 3: Storing Mode of Operation with multicast support\n",__func__);
					break;
				default:
					printk(KERN_DEBUG "%s(): MOP: %d: unassigned\n",__func__,RPL_DIO_MOP(msg->base.dio.g_mop_prf));
				}
				printk(KERN_DEBUG "%s(): Prf: %d\n", __func__,RPL_DIO_Prf(msg->base.dio.g_mop_prf));
				printk(KERN_DEBUG "%s(): DTSN: %d\n", __func__,msg->base.dio.DTSN);
				printk(KERN_DEBUG "%s(): Flags: 0x%02X\n", __func__,msg->base.dio.flags);
				printk(KERN_DEBUG "%s(): Reserved: 0x%02X\n", __func__,msg->base.dio.reserved);
#ifdef __KERNEL__
				printk(KERN_DEBUG "%s(): DodagID: %pI6\n",__func__,&msg->base.dio.dodagid);
#else
				inet_ntop(AF_INET6, &msg->base.dio.dodagid, s_in6_addr, INET6_ADDRSTRLEN);
				printk(KERN_DEBUG "%s(): DodagID: %s\n", __func__,s_in6_addr);
#endif /* __KERNEL__*/
				non_options_len += 24;
				icmpv6_rpl_print_options((__u8 *)msg->base.dio.dio_options,len-non_options_len);
				break;
			case ICMPV6_RPL_DAO:
				printk(KERN_DEBUG "%s(): Code: DAO\n", __func__);
				printk(KERN_DEBUG "%s(): InstanceID: %d\n", __func__,msg->base.dao.instanceID);
				printk(KERN_DEBUG "%s(): DAOSequence: %d\n", __func__,msg->base.dao.DAOSequence);
				if(RPL_DAO_K(msg->base.dao.KD_flags))
				{
					printk(KERN_DEBUG "%s(): DAO-ACK: Expected\n", __func__);
				}
				else
				{
					printk(KERN_DEBUG "%s(): DAO-ACK: Not expected\n", __func__);
				}
				printk(KERN_DEBUG "%s(): Flags: 0x%02X\n", __func__,RPL_DAO_FLAGS(msg->base.dao.KD_flags));
				printk(KERN_DEBUG "%s(): Reserved: 0x%02X\n", __func__,msg->base.dao.reserved);
				if(RPL_DAO_D(msg->base.dao.KD_flags))
				{
					// the DODAGID field is present
#ifdef __KERNEL__
					printk(KERN_DEBUG "%s(): DodagID: %pI6\n",__func__,&msg->base.dao.u_with_dodagid.dodagid);
#else
					inet_ntop(AF_INET6, &msg->base.dao.u_with_dodagid.dodagid, s_in6_addr, INET6_ADDRSTRLEN);
					printk(KERN_DEBUG "%s(): DodagID: %s\n", __func__,s_in6_addr);
#endif /* __KERNEL__*/

					non_options_len  += 20;
					icmpv6_rpl_print_options((__u8 *)msg->base.dao.u_with_dodagid.dao_options,len-non_options_len);
				}
				else
				{
					non_options_len += 4;
					// the DODAGID field is NOT present
					icmpv6_rpl_print_options((__u8 *)msg->base.dao.u_no_dodagid.dao_options,len-non_options_len);
				}
				break;
			case ICMPV6_RPL_DAO_ACK:
				printk(KERN_DEBUG "%s(): Code: DAO_ACK\n", __func__);
				printk(KERN_DEBUG "%s(): InstanceID: %d\n", __func__,msg->base.dao_ack.instanceID);
				printk(KERN_DEBUG "%s(): DAOSequence: %d\n", __func__,msg->base.dao_ack.DAOSequence);
				printk(KERN_DEBUG "%s(): Reserved: 0x%02X\n", __func__,RPL_DAO_ACK_Reserved(msg->base.dao_ack.D_reserved));
				if(msg->base.dao_ack.status == 0)
				{
					printk(KERN_DEBUG "%s(): Status: 0: Unqualified acceptance\n", __func__);
				}
				else if( msg->base.dao_ack.status < 128)
				{
					printk(KERN_DEBUG "%s(): Status: %d: Not an outright rejection\n", __func__,msg->base.dao_ack.status);
				}
				else
				{
					printk(KERN_DEBUG "%s(): Status: %d: Rejection\n", __func__,msg->base.dao_ack.status);
				}
				if(RPL_DAO_ACK_D(msg->base.dao_ack.D_reserved))
				{
					non_options_len += 20;
					// the DODAGID field is present
#ifdef __KERNEL__
					printk(KERN_DEBUG "%s(): DodagID: %pI6\n",__func__,&msg->base.dao_ack.u_with_dodagid.dodagid);
#else
					inet_ntop(AF_INET6, &msg->base.dao_ack.u_with_dodagid.dodagid, s_in6_addr, INET6_ADDRSTRLEN);
					printk(KERN_DEBUG "%s(): DodagID: %s\n", __func__,s_in6_addr);
#endif /* __KERNEL__*/
					icmpv6_rpl_print_options((__u8 *)msg->base.dao_ack.u_with_dodagid.dao_ack_options,len-non_options_len);
				}
				else
				{
					non_options_len += 4;
					// the DODAGID field is NOT present
					icmpv6_rpl_print_options((__u8 *)msg->base.dao_ack.u_no_dodagid.dao_ack_options,len-non_options_len);
				}
				break;
			case ICMPV6_RPL_SEC_DIS:
				printk(KERN_DEBUG "%s(): Code: SEC_DIS\n", __func__);
				break;
			case ICMPV6_RPL_SEC_DIO:
				printk(KERN_DEBUG "%s(): Code: SEC_DIO\n", __func__);
				break;
			case ICMPV6_RPL_SEC_DAO:
				printk(KERN_DEBUG "%s(): Code: SEC_DAO\n", __func__);
				break;
			case ICMPV6_RPL_SEC_DAO_ACK:
				printk(KERN_DEBUG "%s(): Code: SEC_DAO_ACK\n", __func__);
				break;
			case ICMPV6_RPL_CC:
				printk(KERN_DEBUG "%s(): Code: CC\n", __func__);
				printk(KERN_DEBUG "%s(): InstanceID: %d\n", __func__,msg->base.cc.instanceID);
				if(RPL_CC_IS_RESPONSE(msg->base.cc.R_flags))
				{
					printk(KERN_DEBUG "%s(): Is Response: Yes\n", __func__);
				}
				else
				{
					printk(KERN_DEBUG "%s(): Is Response: NO\n", __func__);
				}
				printk(KERN_DEBUG "%s(): Flags: 0x%02X\n", __func__,RPL_CC_Flags(msg->base.cc.R_flags));
				printk(KERN_DEBUG "%s(): Nonce: %d\n", __func__,msg->base.cc.CCNonce);
#ifdef __KERNEL__
				printk(KERN_DEBUG "%s(): DodagID: %pI6\n",__func__,&msg->base.cc.dodagid);
#else
				inet_ntop(AF_INET6, &msg->base.cc.dodagid, s_in6_addr, INET6_ADDRSTRLEN);
				printk(KERN_DEBUG "%s(): DodagID: %s\n", __func__,s_in6_addr);
#endif /* __KERNEL__*/
				printk(KERN_DEBUG "%s(): Destination Counter: %u\n", __func__,be32_to_cpu(msg->base.cc.dest_counter));
				non_options_len += 24;
				// TODO print options
				break;
			default:
				printk(KERN_DEBUG "%s(): Code: Unknown (0x%02X)\n", __func__,msg->icmp6_code);
				break;
		}
	} else {
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
	}
}
/*
void rpl_msg_buf_print(struct rpl_msg_buf *rpl_msg_buf)
{
	if(rpl_msg_buf)
	{
		printk(KERN_DEBUG "%s(): buf len: %d\n", __func__,rpl_msg_buf->len);
		icmpv6_rpl_print_msg(rpl_msg_buf->rpl_msg,rpl_msg_buf->len);
	} else {
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
	}
}
*/
