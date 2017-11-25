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
 * @file rpl_icmp6.c
 *
 * @date Aug 3, 2013
 * @author Joao Pedro Taveira
 */

#define pr_fmt(fmt) "ICMPv6: " fmt

#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <net/if_inet6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/rpl/rpl_constants.h>
#include <net/rpl/rpl_internals.h>
#include <net/rpl/rpl_debug.h>

#define RPL_DEBUG 3

#define RPL_PRINTK(val, level, fmt, ...)				\
do {								\
	if (val <= RPL_DEBUG)					\
		net_##level##_ratelimited(fmt, ##__VA_ARGS__);	\
} while (0)

static void ip6_rpl_hdr(struct sk_buff *skb,
		       const struct in6_addr *saddr,
		       const struct in6_addr *daddr,
		       int hop_limit, int len)
{
	struct ipv6hdr *hdr;

	skb_push(skb, sizeof(*hdr));
	skb_reset_network_header(skb);
	hdr = ipv6_hdr(skb);

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0))
	*(__be32 *)hdr = htonl(0x60000000 | (0 << 20)) | 0;
#else
	ip6_flow_hdr(hdr, 0, 0);
#endif

	hdr->payload_len = htons(len);
	hdr->nexthdr = IPPROTO_ICMPV6;
	hdr->hop_limit = hop_limit;

	hdr->saddr = *saddr;
	hdr->daddr = *daddr;
}

static void rpl_send_skb(struct sk_buff *skb, const struct in6_addr *daddr,
		const struct in6_addr *saddr) {
	struct dst_entry *dst = skb_dst(skb);
	struct net *net = dev_net(skb->dev);
	struct sock *sk = net->ipv6.rpl.rpl_sk;
	struct inet6_dev *idev;
	int err;
	struct icmp6hdr *icmp6h = icmp6_hdr(skb);
	u8 type;

	type = icmp6h->icmp6_type;

	if (!dst) {
		struct sock *sk = net->ipv6.rpl.rpl_sk;
		struct flowi6 fl6;

		icmpv6_flow_init(sk, &fl6, type, saddr, daddr, skb->dev->ifindex);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0))
		dst = icmp6_dst_alloc(skb->dev, NULL, &fl6);
#else
		dst = icmp6_dst_alloc(skb->dev, &fl6);
#endif
		if (IS_ERR(dst)) {
			kfree_skb(skb);
			return;
		}

		skb_dst_set(skb, dst);
	}
	icmp6h->icmp6_cksum = 0;

	icmp6h->icmp6_cksum = csum_ipv6_magic(saddr, daddr, skb->len,
			IPPROTO_ICMPV6, csum_partial(icmp6h, skb->len, 0));

	ip6_rpl_hdr(skb, saddr, daddr, inet6_sk(sk)->hop_limit, skb->len);

	rcu_read_lock();
	idev = __in6_dev_get(dst->dev);
	IP6_UPD_PO_STATS(net, idev, IPSTATS_MIB_OUT, skb->len);

	err = NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_OUT, skb, NULL, dst->dev,
			dst_output);
	if (!err) {
		ICMP6MSGOUT_INC_STATS(net, idev, type);
		ICMP6_INC_STATS(net, idev, ICMP6_MIB_OUTMSGS);
	}

	rcu_read_unlock();
}

int rpl_send_dis(struct rpl_enabled_device *enabled_device) {
	int err = 0;
	struct sk_buff *skb;
	struct in6_addr addr_buf;
	struct in6_addr *saddr;

	if ((err = ipv6_get_lladdr(enabled_device->dev, &addr_buf,
			(IFA_F_TENTATIVE | IFA_F_OPTIMISTIC))) != 0) {
		RPL_PRINTK(0, err, "rpl: %s: failed calling ipv6_get_lladdr, err=%d\n",
				__func__, err);
		goto out;
	}
	saddr = &addr_buf;
	skb = icmpv6_rpl_dis_new(enabled_device->dev);
	if (!skb) {
		err = -ENOMEM;
		goto out;
	}

	if(enabled_device->solicited_information){
		icmpv6_rpl_add_option_solicited_information(
				skb,
				enabled_device->solicited_information->instanceID,
				RPL_SIO_V(enabled_device->solicited_information->VID_flags),
				RPL_SIO_I(enabled_device->solicited_information->VID_flags),
				RPL_SIO_D(enabled_device->solicited_information->VID_flags),
				&enabled_device->solicited_information->dodagid,
				enabled_device->solicited_information->version);
	}

	rpl_send_skb(skb, &in6addr_all_rpl_nodes, saddr);
out:
	return err;
}

static int _rpl_send_dio(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *daddr, bool add_dodag_conf_option, bool poison){
	int err = 0;
	struct sk_buff *skb;
	struct in6_addr addr_buf;
	struct in6_addr *saddr;

	if ((err = ipv6_get_lladdr(dev, &addr_buf, (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC))) != 0)
	{
		RPL_PRINTK(0, err, "rpl: %s: failed calling ipv6_get_lladdr, err=%d\n",
			  __func__, err);
		goto out;
	}

	saddr = &addr_buf;
	skb = icmpv6_rpl_dio_new(dev, dag->instance->instanceID,
			dag->version, (poison)?RPL_INFINITE_RANK:dag->rank, dag->grounded, dag->mop, dag->preference,
			dag->DTSN, &dag->dodagid);
	if (!skb)
	{
		err = -ENOMEM;
		goto out;
	}

	if((daddr == NULL || add_dodag_conf_option) && !poison)
	{
		icmpv6_rpl_add_option_dodag_configuration(skb, dag->authenticated,
				dag->PCS, dag->DIOIntDoubl, dag->DIOIntMin, dag->DIORedun,
				dag->MaxRankIncrease, dag->MinHopRankIncrease,
				dag->instance->of->ocp, dag->def_lifetime, dag->lifetime_unit);
	}
	if((daddr == NULL && dag->prefix_info) && !poison)
	{
		icmpv6_rpl_add_option_prefix_information(skb,
				dag->prefix_info->prefix_len, dag->prefix_info->onlink,
				dag->prefix_info->autoconf, 0, be32_to_cpu(dag->prefix_info->valid),
				be32_to_cpu(dag->prefix_info->prefered), (__u8*)&dag->prefix_info->prefix);
	}

	if(!daddr)
	{
		daddr = &in6addr_all_rpl_nodes;
	}
	rpl_send_skb(skb, daddr, saddr);

	err = 0;
out:
	return err;
}

int rpl_send_dio(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *daddr, bool add_dodag_conf_option, bool poison){
	int err = 0;
	struct rpl_allowed_if *allowed_if = NULL;

	if(!dag)
	{
		RPL_PRINTK(0, err, "rpl: %s: dag is NULL\n",__func__);
		goto out;
	}

	if(dev){
		if(rpl_dag_is_allowed(dag,dev)){
			err = _rpl_send_dio(dag,dev,daddr,add_dodag_conf_option,poison);
			if (err){
				RPL_PRINTK(0, err, "%s: failed send dio, err=%d\n",__func__, err);
				goto out;
			}
		}
	} else {
		list_for_each_entry(allowed_if, &dag->allowed_interfaces,allowed_if_list){
			if(allowed_if->enabled){
				err = _rpl_send_dio(dag,allowed_if->dev,daddr,add_dodag_conf_option,poison);
				if (err){
					RPL_PRINTK(0, err, "%s: failed send dio, err=%d\n",__func__, err);
					break;
				}
			}
		}
	}
out:
	return err;
}

/*
 * RESET DAO Timer: When send DAOs:
 * 1. the Path Lifetime is to be updated 										(check rpl_transit update) #1 DONE
 * 3. when it receives DAO messages 											(on changes after rpl_recv_dao) #2
 * 4. changes in its DAO parent set 											(on update upward routes) #3 DONE
 * 5. expiry of a related prefix lifetime ???
 * 6. it matters whether the DAO message is "new" or contains new information
 * 		Storing Mode, DAO message is "new" if a target:
 * 		6.1. it has a newer Path Sequence number								(on rpl_target_add and/or merge with new path_sequence) #4 DONE
 * 		6.2. it has additional Path Control bits ???
 * 		6.3. it is a No-Path DAO message 										(on rpl_target_set_no_path) #5 DONE
 * 7. receiving a unicast DAO can trigger sending a unicast DAO to a DAO parent (same as 3.)
 * 8. On receiving a unicast DAO message with updated information, such as
 * 		containing a Transit Information option with a new Path Sequence		(same as 6.1)
 * 9. When a node adds a node to its DAO parent set								(same as 4)
 * 10. If a node hears one of its DAO parents increment its DTSN,				(on rpl_recv_dio new DTSN) #7
 * 		the node MUST schedule a DAO message
 * 11. as part of routine routing table updates and maintenance,
 * 		a storing node MAY increment DTSN
 * 12. 9.8 2) On receiving a unicast DAO, a node MUST compute if the DAO would	(same as 6.1, 6.3)
       change the set of prefixes that the node itself advertises.  This
       computation SHOULD include consultation of the Path Sequence
       information in the Transit Information options associated with
       the DAO, to determine if the DAO message contains newer
       information that supersedes the information already stored at the
       node.  If so, the node MUST generate a new DAO message and
       transmit it, following the rules in Section 9.5.  Such a change
       includes receiving a No-Path DAO
 * 14. When a node removes a node from its DAO parent set, it SHOULD			(same as 4.)
       send a No-Path DAO message (Section 6.4.3) to that removed DAO
       parent to invalidate the existing route
 */

/* FIXME beaglebone black kernel 3.8.13
 * [   54.238605] BUG: scheduling while atomic: swapper/0/0/0x40000100
[   54.244889] Modules linked in: rpl_of_of0 g_multi libcomposite rfcomm ircomm_tty ircomm irda ipv6 hidp bluetooth rfkill autofs4
[   54.257041] [<c001051d>] (unwind_backtrace+0x1/0x8c) from [<c03740b3>] (__schedule_bug+0x33/0x48)
[   54.266315] [<c03740b3>] (__schedule_bug+0x33/0x48) from [<c0377573>] (__schedule+0x47/0x4c4)
[   54.275230] [<c0377573>] (__schedule+0x47/0x4c4) from [<c0043727>] (__cond_resched+0x1b/0x24)
[   54.284136] [<c0043727>] (__cond_resched+0x1b/0x24) from [<c0377a4d>] (_cond_resched+0x25/0x28)
[   54.293228] [<c0377a4d>] (_cond_resched+0x25/0x28) from [<c000ec93>] (dump_mem+0x53/0xbc)
[   54.301776] [<c000ec93>] (dump_mem+0x53/0xbc) from [<c0010599>] (unwind_backtrace+0x7d/0x8c)
[   54.310602] [<c0010599>] (unwind_backtrace+0x7d/0x8c) from [<c002b51f>] (warn_slowpath_common+0x33/0x48)
[   54.320513] [<c002b51f>] (warn_slowpath_common+0x33/0x48) from [<c002b543>] (warn_slowpath_null+0xf/0x10)
[   54.330507] [<c002b543>] (warn_slowpath_null+0xf/0x10) from [<c0376ed1>] (__mutex_lock_slowpath+0x39/0x204)
[   54.340698] [<c0376ed1>] (__mutex_lock_slowpath+0x39/0x204) from [<c03770ab>] (mutex_lock+0xf/0x20)
[   54.350408] [<c03770ab>] (mutex_lock+0xf/0x20) from [<bf871edb>] (rpl_send_dao+0x36/0x308 [ipv6])
[   54.359906] [<bf871edb>] (rpl_send_dao+0x36/0x308 [ipv6]) from [<bf86eb35>] (rpl_dag_dao_timer_handler+0x14/0x54 [ipv6])
[   54.371380] [<bf86eb35>] (rpl_dag_dao_timer_handler+0x14/0x54 [ipv6]) from [<c0032ffd>] (call_timer_fn.isra.24+0x15/0x54)
[   54.382833] [<c0032ffd>] (call_timer_fn.isra.24+0x15/0x54) from [<c0033141>] (run_timer_softirq+0x105/0x138)
[   54.393109] [<c0033141>] (run_timer_softirq+0x105/0x138) from [<c002ff39>] (__do_softirq+0x95/0x124)
[   54.402649] [<c002ff39>] (__do_softirq+0x95/0x124) from [<c0030197>] (irq_exit+0x2d/0x56)
[   54.411197] [<c0030197>] (irq_exit+0x2d/0x56) from [<c000cefb>] (handle_IRQ+0x3f/0x5c)
[   54.419470] [<c000cefb>] (handle_IRQ+0x3f/0x5c) from [<c0008565>] (omap3_intc_handle_irq+0x39/0x5c)
[   54.428919] [<c0008565>] (omap3_intc_handle_irq+0x39/0x5c) from [<c000c1db>] (__irq_svc+0x3b/0x5c)
[   54.438281] Exception stack(0xc0627f68 to 0xc0627fb0)
[   54.443563] 7f60:                   ffffffed 00000000 004df000 00000000 c0626000 c037d1e8
[   54.452107] 7f80: c0698288 c0afec80 80004059 413fc082 00000000 00000000 00000000 c0627fb0
[   54.460642] 7fa0: c000d047 c000d048 60000033 ffffffff
[   54.465927] [<c000c1db>] (__irq_svc+0x3b/0x5c) from [<c000d048>] (default_idle+0x12/0x1a)
[   54.474472] [<c000d048>] (default_idle+0x12/0x1a) from [<c000d15b>] (cpu_idle+0x63/0xa0)
[   54.482934] [<c000d15b>] (cpu_idle+0x63/0xa0) from [<c05ef583>] (start_kernel+0x1ff/0x254)
[   54.498502] 7f80: c0698288 c0afec80 80004059 413fc082 00000000 00000000 00000000 c0627fb0
 *
 */

int rpl_send_dao(struct rpl_dag *dag, struct net_device *dev, bool allnodes, bool no_path){
	int err = -EINVAL;
	struct rpl_allowed_if *allowed_if = NULL;

	struct in6_addr saddr_global_tmp;

	struct rpl_node *dao_parent;
	struct in6_addr *dao_parent_addr;

	struct in6_addr *saddr;
	struct in6_addr addr_buf;

	int addr_scope = 0;
	struct sk_buff *skb;

	struct rpl_target_transit_info *transit_info = NULL;
	struct rpl_target *target;

	bool add_transit_info_active_targets = false;
	bool add_transit_info_no_path = false;

	if(!dag){
		RPL_PRINTK(0, err, "rpl: %s: dag is NULL\n",__func__);
		goto out;
	}

	if(allnodes){
		list_for_each_entry(allowed_if,&dag->allowed_interfaces,allowed_if_list){

			// If device set, only send to the given device
			if(dev && allowed_if->dev != dev)
				continue;

			// Ignore disabled devices
			if(!allowed_if->enabled)
				continue;

			ipv6_dev_get_saddr(dev_net(allowed_if->dev),NULL,&dag->dodagid,0,&saddr_global_tmp);
			addr_scope = ipv6_addr_src_scope(&saddr_global_tmp);

			if(addr_scope != IPV6_ADDR_SCOPE_GLOBAL) {
				printk(KERN_DEBUG "rpl: %s: ignoring non global address: %pI6 dag: %pI6 scope: %X\n",__func__,&saddr_global_tmp,&dag->dodagid,addr_scope);

				rpl_dag_trigger_dao_timer(dag);
				continue;
			}
			else{printk(KERN_DEBUG "rpl: %s: using global address: %pI6 scope: %X\n",__func__,&saddr_global_tmp,addr_scope);}

			if(!ipv6_addr_equal(&allowed_if->global_addr,&saddr_global_tmp))
			{
				RPL_LOLLIPOP_INCREMENT(allowed_if->node_addr_path_sequence);
				memcpy(&allowed_if->global_addr,&saddr_global_tmp,16);

				/*
				 * FIXME here, we only increment DAOSequence if global address changes,
				 * but we MUST check if transit information is different. If it does, we
				 * must increment DAO sequence even if global address keeps the same
				 */
				RPL_LOLLIPOP_INCREMENT(dag->DAOSequence);
			}

			skb = icmpv6_rpl_dao_new(allowed_if->dev,
					dag->instance->instanceID,
					0,
					dag->DAOSequence,
					NULL);
			if (!skb)
			{
				err = -ENOMEM;
				break;
			}

			printk(KERN_DEBUG "%s(): global address of %s: %pI6, %X\n",__func__,allowed_if->dev->name,&saddr_global_tmp,addr_scope);

			icmpv6_rpl_add_option_rpl_target(skb,128,(__u8*) &saddr_global_tmp);
			//FIXME specify path control: http://tools.ietf.org/html/rfc6550#section-9.9
			icmpv6_rpl_add_option_transit_information(skb,0,0,allowed_if->node_addr_path_sequence,(no_path || dag->rank == RPL_INFINITE_RANK)?0:0xFF,NULL);

			// getting scope link source address
			if ((err = ipv6_get_lladdr(allowed_if->dev, &addr_buf, (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC))) != 0)
			{
				printk(KERN_ERR "rpl: %s: failed calling ipv6_get_lladdr, err=%d\n",
					  __func__, err);
				break;
			}
			saddr = &addr_buf;

			// sending DAO message
			rpl_send_skb(skb, &in6addr_all_rpl_nodes, saddr);
		}
		err = 0;
	} else {
		printk(KERN_DEBUG "rpl: %s: sending data to DAO Parent here...\n",__func__);

		/*
		 * for each DAO parent, lets send a DAO message
		 */

		if(!mutex_trylock(&dag->parents_lock))
		{
			rpl_dag_trigger_dao_timer(dag);
			goto out;
		}

		list_for_each_entry(dao_parent,&dag->dodag_parents,node_list){

			// If device set, only send to the given device
			if(dev && dao_parent->dev != dev)
				continue;

			if(!dao_parent->is_dao_parent)
				continue;

			// Ignore disabled devices
			if(!rpl_dag_is_allowed(dag,dao_parent->dev))
				continue;

			add_transit_info_active_targets = false;
			add_transit_info_no_path = false;

			RPL_LOLLIPOP_INCREMENT(dag->DAOSequence);

			skb = icmpv6_rpl_dao_new(dao_parent->dev,
					dag->instance->instanceID,
					0,
					dag->DAOSequence,
					NULL);
			if (!skb)
			{
				err = -ENOMEM;
				continue;
			}

			saddr = &addr_buf;
			dao_parent_addr = &dao_parent->addr;

			// lets create active targets options
			list_for_each_entry(target,&dag->targets_head,target_list){
				transit_info =
						(!list_empty(&target->transit_head)) ?
								list_first_entry(&target->transit_head,struct rpl_target_transit_info,transit_info_list) :
								NULL;
				if(transit_info && transit_info->path_lifetime > 0x00)
				{
					if(!ipv6_addr_equal(dao_parent_addr,&transit_info->next_hop)){
						// active target with transit_info
						icmpv6_rpl_add_option_rpl_target(skb,target->prefix_len,(__u8*) &target->prefix);
						add_transit_info_active_targets = true;
					}
				}
			}
			if(add_transit_info_active_targets && transit_info)
			{
				icmpv6_rpl_add_option_transit_information(skb,0,0,transit_info->path_sequence,(no_path || dag->rank == RPL_INFINITE_RANK)?0:0xFF,NULL);
			}

			transit_info = NULL;

			// lets create no-path targets options
			list_for_each_entry(target,&dag->targets_head,target_list){
				transit_info =
						(!list_empty(&target->transit_head)) ?
								list_first_entry(&target->transit_head,struct rpl_target_transit_info,transit_info_list) :
								NULL;
				if(transit_info && transit_info->path_lifetime == 0x00)
				{
					if(!ipv6_addr_equal(dao_parent_addr,&transit_info->next_hop)){
						// no-path target with transit_info
						icmpv6_rpl_add_option_rpl_target(skb,target->prefix_len,(__u8*) &target->prefix);
						add_transit_info_no_path = true;
					}
				}
			}
			if(add_transit_info_no_path && transit_info)
			{
				icmpv6_rpl_add_option_transit_information(skb,0,0,transit_info->path_sequence,0x00,NULL);
			}

			// getting scope link source address
			if ((err = ipv6_get_lladdr(dao_parent->dev, &addr_buf, (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC))) != 0)
			{
				printk(KERN_ERR "rpl: %s: failed calling ipv6_get_lladdr, err=%d\n",
					  __func__, err);
				kfree_skb(skb);
				continue;
			}

			rpl_send_skb(skb, dao_parent_addr, saddr);

		}
		mutex_unlock(&dag->parents_lock);

		err = rpl_dag_cleanup_no_path(dag);
		if(err){
			RPL_PRINTK(2,err,"%s: some error occur cleaning no_path targets: %d\n",__func__,err);
		}

		err = 0;
	}
out:
	return err;
}

int rpl_send_dao_ack(struct net_device *dev, __u8 instanceID, const struct in6_addr *daddr, __u8 DAOSequence, const struct in6_addr *dodagid, __u8 status)
{
	int err = -EINVAL;
	struct in6_addr *saddr;
	struct in6_addr addr_buf;
	struct sk_buff *skb;

	if(!dev){
		RPL_PRINTK(0, err, "rpl: %s dev is NULL, err=%d\n", __func__, err);
		goto out;
	}

	skb = icmpv6_rpl_dao_ack_new(dev,instanceID,DAOSequence,status,dodagid);
	if (!skb)
	{
		err = -ENOMEM;
		goto out;
	}

	// getting scope link source address
	if ((err = ipv6_get_lladdr(dev, &addr_buf,
			(IFA_F_TENTATIVE | IFA_F_OPTIMISTIC))) != 0) {
		printk(KERN_ERR "rpl: %s: failed calling ipv6_get_lladdr, err=%d\n",
				__func__, err);
		kfree_skb(skb);
		goto out;
	}
	saddr = &addr_buf;

	// sending DAO message
	rpl_send_skb(skb, daddr, saddr);

	err = 0;
out:
	return err;
}


static struct sk_buff *rpl_alloc_skb(struct net_device *dev, int len)
{
	int hlen = LL_RESERVED_SPACE(dev);
//	int tlen = dev->needed_tailroom;
	struct sock *sk = dev_net(dev)->ipv6.rpl.rpl_sk;
	struct sk_buff *skb;
	int err;

	skb = sock_alloc_send_skb(sk,
				  dev->mtu, //FIXME we shouldnt use mtu
				  1, &err);
//	skb = sock_alloc_send_skb(sk,
//				  hlen + sizeof(struct ipv6hdr) + len + tlen,
//				  1, &err);
	if (!skb) {
		RPL_PRINTK(0, err, "rpl: %s failed to allocate an skb, err=%d\n",
			  __func__, err);
		return NULL;
	}

	skb->protocol = htons(ETH_P_IPV6);
	skb->dev = dev;

	skb_reserve(skb, hlen + sizeof(struct ipv6hdr));
	skb_reset_transport_header(skb);

	return skb;
}

int rpl_recv_dis(struct net_device *dev, struct sk_buff *skb)
{
	/*
	 * http://tools.ietf.org/html/rfc6550#section-8
	 * */
/**
 * DIS receive
 *
 * Upon receiving a DIS, a node creates a DIO containing
 * DODAG Configuration option and sends it back. This also
 * triggers a trickle timer reset (if active). The trickle timer is
 * used to send periodic, unsolicited, DIOs.
 *
 * The DIS source node is also added to the neighbors set as
 * ’NEIGHBOR NOT IN DODAG’ and a temporary route is
 * created. The route will be discarded as soon as the DIO is
 * sent.
 */
	struct net *net = dev_net(dev);
	struct rpl_dag *dag;
	u_rpl_option *option;
	struct rpl_msg *msg;
	const struct in6_addr *saddr, *daddr;
	msg = (struct rpl_msg *)skb_transport_header(skb);

	saddr = &ipv6_hdr(skb)->saddr;
	daddr = &ipv6_hdr(skb)->daddr;

	option = icmpv6_rpl_find_option(skb,ICMPV6_RPL_OPT_Solicited_Information);

	if(option)
	{
		RPL_PRINTK(1,dbg,"%s(): Solicited Information Option found\n",__func__);
		icmpv6_rpl_print_option((__u8*)option);
		if (ipv6_addr_equal(daddr,&in6addr_all_rpl_nodes)) {
			 /* multicast all-RPL-nodes */
			// TODO: Check if node match all predicates in option

			//rpl_ipv6_signal_inconsistency(idev);
		}

	} else if(ipv6_addr_equal(daddr,&in6addr_all_rpl_nodes)){
		 /* multicast all-RPL-nodes */
		mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
		list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
			if(rpl_dag_is_allowed(dag,dev)){
				rpl_dag_inconsistent(dag);
			}
		}
		mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
	}
	return 0;
}

int rpl_recv_dio(struct net_device *dev, struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	int err = 0;
	struct rpl_dag *dag;
	struct rpl_node *neighbor;
	struct rpl_msg *msg;
	const struct in6_addr *saddr, *daddr;
	bool updated = false;
	bool check_prefix = false;
	struct in6_addr global_addr;
	u_rpl_option *prefix_info_option;
	struct prefix_info *prefix_option;
	struct inet6_dev *idev;

	idev = __in6_dev_get(dev);
	if(!idev){
		err = -ENOTSUPP;
		goto out;
	}

	msg = (struct rpl_msg *)skb_transport_header(skb);

	saddr = &ipv6_hdr(skb)->saddr;
	daddr = &ipv6_hdr(skb)->daddr;

	if(idev->cnf.rpl_dodag_root)
	{
		dag = rpl_dag_find(net,msg->base.dio.instanceID,&msg->base.dio.dodagid);
		if(dag){
			if(lollipop_greater_than(msg->base.dio.version,dag->version)){
				dag->version = msg->base.dio.version;
				RPL_LOLLIPOP_INCREMENT(dag->version);
				rpl_dag_inconsistent(dag);
			}
			rpl_dag_put(dag);
		}
		if(idev->cnf.rpl_icmp_dump)
			printk(KERN_DEBUG "RPL: DODAG Root received a DIO. Ignoring\n");
		err = 0;
		goto out;
	}
/*
 * DIO receive
 *
 * The actions that follow the receipt of a DIO are different
 * according to the state of the node. For convenience, given
 * the considerable length of the diagram, we decided to omit
 * it and insert just the description.
 *
 * The node can be in one of these two states:
 * 	(1) it is not yet joined to a DODAG or
 * 	(2) it is already joined to one.
 */
	dag = rpl_dag_find(net,msg->base.dio.instanceID,&msg->base.dio.dodagid);
	if(!dag){
		/*
		 * 1) This case is the consequence of a DODAG join attempt.
		 * Hence, the node will copy the values contained in the DIO
		 * in his DODAG attributes, his rank will be calculated, its
		 * status updated and, if it is a ’ROUTER’, the trickle timer
		 * is launched. The DIO sender will be stored in the neighbors
		 * set with type ’DODAG PARENT ONLY PRF’. The sender,
		 * of course, will be automatically selected as the preferred
		 * DODAG parent. The routing table is updated accordingly.
		 */
		dag = rpl_dag_new_from_dio(net,dev,skb);
		if(!dag){
			RPL_PRINTK(1,dbg,"%s(): Error creating new DAG\n",__func__);
			goto out;
		}
		updated = true;
	} else {
		if(dag->auto_gen){
			rpl_dag_set_allowed(dag,dev,true,true,&updated);
			check_prefix = true;
		} else if(!rpl_dag_is_allowed(dag,dev)){
			goto discard_it;
		} else {
			check_prefix = true;
		}
	}

	if(check_prefix){
		if(ipv6_get_global_addr(dev,&global_addr,0)){
			prefix_info_option = icmpv6_rpl_find_option(skb, ICMPV6_RPL_OPT_Prefix_Information);
			if(prefix_info_option){
				prefix_option = (struct prefix_info *) prefix_info_option;
				addrconf_prefix_rcv(skb->dev,(u8 *)prefix_option,sizeof(struct prefix_info),0);

				if(dag->prefix_info)
					kfree(dag->prefix_info);
				dag->prefix_info = kmalloc(sizeof(struct prefix_info),GFP_ATOMIC);
				if(!dag->prefix_info){
					RPL_PRINTK(1, err,"%s(): Error creating prefix_info\n",__func__);
				} else {
					memcpy(dag->prefix_info, prefix_option, sizeof(struct prefix_info));
				}
			}
		}
	}

	/*
	 * 2) In the second case we have two more possibilities:
	 * 	(a) the DIO is a poisoning one or
	 * 	(b) it is a periodic DIO sent to maintain the upward routes.
	 */

	if(msg->base.dio.rank == RPL_INFINITE_RANK) {
		 /* a) In this first case the node will need to delete all the
		 * sender’s entry and all the routes that have the sender as
		 * next hop from the routing table. The sender is also removed
		 * from the neighbors set . If the sender was a preferred parent,
		 * another parent is searched in the neighbor set. If no parent
		 * is found, the node will disjoin himself from the DODAG.
		 */

		printk(KERN_DEBUG "%s(): DIO received INFINITE_RANK..!!\n",__func__);

		err = rpl_dag_unlink_node(dag,dev,saddr);
		if(err)
		{
			printk(KERN_ERR "%s(): Error unlinking node: %d\n",__func__,err);
			goto put_dag;
		}
	} else {
		/* 1)
		 * b) In the event that the DIO is a periodic message then the
		 * node will check if the version of DODAG has been increased
		 * or not.
		 */
		if(lollipop_greater_than(msg->base.dio.version,dag->version)){
			printk(KERN_DEBUG "%s(): New DAG Version!!\n",__func__);

			/*
			 * i) If so the node will join the new version of DODAG, so
			 * it will reset the routing table, the neighbors set and, if it is
			 * active, the trickle timer. This is an implementation choice,
			 * as the standard does not suggest anything about this point.
			 * Better choices could be tested in the future.
			 */

			dag->version = msg->base.dio.version;
			RPL_LOLLIPOP_INCREMENT(dag->DTSN);

			// TODO update dag version
			// TODO increment DTSN
			// TODO delete all neighbors with old version
			// TODO update parents set

			err = rpl_dag_purge_nodes(dag);
			if(err){
				RPL_PRINTK(1, err,"%s(): Error resetting neighbors set: %d\n",__func__,err);
				err = 0;
			}

		}
		//else
		{
			if(idev->cnf.rpl_icmp_dump)
				printk(KERN_DEBUG "%s(): DAG Version Unchanged!!\n",__func__);
			/*
			 * ii) If the DODAG version is unchanged, then the ’DTSN’
			 * field is checked. If it is different from the last one that the
			 * sending node sent, a DAO will be scheduled. Then, if the
			 * rank of the sender node is lesser than the one of the current
			 * node, the sender will be stored in neighbors set, checking if
			 * the new node is to become the preferred parent and, as a
			 * consequence, to update the node’s rank. The sender node is
			 * in any case stored in the neighbor set and the routing table
			 * is updated accordingly.
			 */

			neighbor = rpl_dag_get_node(dag,dev,saddr);
			if(!neighbor)
			{
				RPL_PRINTK(1, dbg, "%s(): Unknown Neighbor!!\n",__func__);

				neighbor = rpl_node_alloc(saddr,dev,be16_to_cpu(msg->base.dio.rank),msg->base.dio.DTSN,&err);
				if(!neighbor)
				{
					RPL_PRINTK(1, err,
							"%s(): Error allocating neighbor: %d\n",
							__func__,err);
					goto put_dag;
				}
				err = rpl_dag_add_node(dag,neighbor);
				if(err)
				{
					RPL_PRINTK(1, err,
							"%s(): Error adding neighbor to dag: %d\n",
							__func__, err);
					rpl_node_free(neighbor);
					goto put_dag;
				}
			} else {
				if(neighbor->is_dao_parent && lollipop_greater_than(msg->base.dio.DTSN,neighbor->dtsn))
				{
					neighbor->dtsn = msg->base.dio.DTSN;
					rpl_dag_trigger_dao_timer(dag);
				}
				neighbor->rank = be16_to_cpu(msg->base.dio.rank);
			}

			err = rpl_dag_update_upward_routes(dag,&updated);
			if(err)
			{
				printk(KERN_ERR "%s(): error updating upward routes: %d\n",__func__,err);
				goto put_dag;
			}

			if(list_empty(&dag->dodag_parents))
			{
				printk(KERN_ERR "%s(): dodag parents list is empty!!!\n",__func__);
				rpl_dag_set_rank(dag,RPL_INFINITE_RANK);
				updated = true;
			}

			if(updated)
			{
				rpl_dag_inconsistent(dag);
				rpl_dag_trigger_dao_timer(dag);
			}
		}
	}

// FIXME when will we call rpl_dag_consistent???

discard_it:
put_dag:
	if(dag)
		rpl_dag_put(dag);
out:
	return err;
}

__u8 *icmpv6_rpl_get_options(struct sk_buff *skb, size_t *p_non_options_len);

int rpl_recv_dao(struct net_device *dev, struct sk_buff *skb){
	int err = 0;

	struct net *net = dev_net(dev);

	struct rpl_msg *msg;
	struct list_head *target_ptr,*target_next;
	const struct in6_addr *saddr, *daddr;
	const struct in6_addr *dodagid = NULL;
	size_t non_options_len = 0;
	size_t options_len = 0;
	size_t option_len = 0;

	struct rpl_dag *dag;

	u_rpl_option *first,*option = NULL;

	struct rpl_node *dao_parent;

	struct rpl_target_transit_info *transit_info;
	struct rpl_target *target_copy;
	struct rpl_target *target;
	bool target_updated = false;
	bool trigger_dao = false;
	bool is_one_hop = false; // see 9.10.  Multicast Destination Advertisement Messages

	struct list_head targets; // struct rpl_target list
	bool is_transit_info_last_opt = false;
	INIT_LIST_HEAD(&targets);

	msg = (struct rpl_msg *)skb_transport_header(skb);

	saddr = &ipv6_hdr(skb)->saddr;
	daddr = &ipv6_hdr(skb)->daddr;

	first = (u_rpl_option *)icmpv6_rpl_get_options(skb,&non_options_len);
	option = first;
	options_len = skb->len-non_options_len;

	if (RPL_DAO_K(msg->base.dao.KD_flags) &&
			ipv6_addr_equal(daddr, &in6addr_all_rpl_nodes)) {
		RPL_PRINTK(1,dbg,"%s(): Error: can't send ACK from multicast DAO\n",__func__);
		return 0;
	}

	if(ipv6_addr_equal(daddr, &in6addr_all_rpl_nodes))
		is_one_hop = true;

	if(RPL_DAO_D(msg->base.dao.KD_flags))
	{
		dodagid = &msg->base.dao.u_with_dodagid.dodagid;
	}else{
		dodagid = NULL;
	}

	while(option && options_len > 0){
		//icmpv6_rpl_print_option((__u8*)option);

		if(icmpv6_rpl_option_get_code(option) == ICMPV6_RPL_OPT_RPL_Target)
		{
			if(is_transit_info_last_opt)
			{
				if(!list_empty(&targets)){
					RPL_PRINTK(1,dbg,"%s(): Targets list should be empty at this point.\n",__func__);
					list_for_each_safe(target_ptr,target_next,&targets)
					{
						target = list_entry(target_ptr,struct rpl_target,target_list);
						list_del(&target->target_list);
						rpl_target_free(target);
					}
					target = NULL;
				}
				is_transit_info_last_opt = false;
			}
			target = rpl_target_alloc(
					(const struct in6_addr *)option->rpl_target.prefix,
					option->rpl_target.prefix_length,&err);
			if(!target)
			{
				RPL_PRINTK(1,dbg,"%s(): Error allocating new target: %d\n",__func__,err);
			} else {
				list_add(&target->target_list,&targets);
			}
		} else if(icmpv6_rpl_option_get_code(option) == ICMPV6_RPL_OPT_RPL_Target_Descriptor)
		{
			if(target)
			{
				/*
				 * At most, there can be one descriptor per target.  The descriptor is
				 * set by the node that injects the Target in the RPL network.  It MUST
				 * be copied but not modified by routers that propagate the Target Up
				 * the DODAG in DAO messages.
				 */
				target->target_descriptor = be32_to_cpu(option->rpl_target_descriptor.descriptor);
				target = NULL;
			}
		} else if(icmpv6_rpl_option_get_code(option) == ICMPV6_RPL_OPT_Transit_Information)
		{
			is_transit_info_last_opt = true;

			if(RPL_TIO_E(option->transit_information.E_flags))
			{

			}

			if(option->transit_information.path_control == 0)
			{
				// 9.9.  Path Control
			}

			if(option->transit_information.path_lifetime == 0)
			{
				list_for_each_safe(target_ptr,target_next,&targets)
				{
					target = list_entry(target_ptr,struct rpl_target,target_list);
					rpl_target_set_no_path(net,msg->base.dao.instanceID,dodagid,dev,&target->prefix,target->prefix_len,saddr);
					list_del(&target->target_list);
					rpl_target_free(target);
				}
				target = NULL;
			}else if(option->transit_information.path_lifetime == 0xff)
			{
				//for each target in targets
				list_for_each_safe(target_ptr,target_next,&targets)
				{
					target = list_entry(target_ptr,struct rpl_target,target_list);
					// add target to dodagid or to all dags in idev

					// ... for all dags, if idev allowed && enabled
					list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
						if(rpl_dag_is_allowed(dag,dev)) {
							trigger_dao = false;
							target_updated = false;

							if(is_one_hop /* multicast DAO */) {
								dao_parent = rpl_dag_get_node(dag,dev,saddr);
								if(dao_parent && dao_parent->is_dao_parent)
								{
									/*
									 *  DAO Parent found on this DAG via this interface.
									 *  Since it's a mcast DAO, we must ignore it
									 */
									break;
								}
							}

							target_copy = rpl_target_alloc(&target->prefix,target->prefix_len,&err);
							if(target_copy){
								transit_info = rpl_transit_info_alloc(saddr,dev,is_one_hop,&err);
								transit_info->DAOSequence = msg->base.dao.DAOSequence;
								transit_info->path_control = option->transit_information.path_control;
								transit_info->path_lifetime = option->transit_information.path_lifetime;
								transit_info->path_sequence = option->transit_information.path_sequence;
								rpl_target_add_transit_info(target_copy,transit_info,NULL);
								if(dodagid){
									if(msg->base.dao.instanceID == dag->instance->instanceID &&
											ipv6_addr_equal(dodagid,&dag->dodagid)){
										rpl_dag_add_target(dag,target_copy,&target_updated);
									} else {
										rpl_target_free(target_copy);
									}
								} else if(msg->base.dao.instanceID == dag->instance->instanceID){
									rpl_dag_add_target(dag,target_copy,&target_updated);
								} else {
									rpl_target_free(target_copy);
								}
							}
							trigger_dao |= target_updated;

							/*
							 * If target processing result in targets updates, lets trigger DAO for this DAG
							 */
							if(trigger_dao){
								rpl_dag_trigger_dao_timer(dag);
							}
						}
					}
					list_del(&target->target_list);
					rpl_target_free(target);
				}
				target = NULL;
			} else
			{
				// ?? path_lifetime not 0 (zero) nor 0xFF (infinite)
			}

			// TODO: compute best routes to each known neighbour based on DAOs //FIXME trigger DAO

		}
		target = NULL;

		//FIXME option = icmpv6_rpl_option_get_next(first,option,skb->len-non_options_len);
		option_len = icmpv6_rpl_option_get_length(option);
		if(option_len){
			option = (u_rpl_option*) (((__u8*)option)+option_len);
			options_len -= option_len;
		} else {
			option = NULL;
		}
	}

	// TODO add a "send_ack" bool after check that instanceID exists
	if(!is_one_hop && RPL_DAO_K(msg->base.dao.KD_flags))
	{
		err = rpl_send_dao_ack(dev,msg->base.dao.instanceID, saddr,msg->base.dao.DAOSequence,dodagid, 0 /* status */);
		if(err)
		{
			RPL_PRINTK(1,dbg,"%s(): Error: sending DAO_ACK: %d\n",__func__,err);
		}
	}

/**
 * DAO receive
 *
 * DAO messages are used to inform the nodes about the
 * downward routes. A DAO might require an acknowledge-
 * ment; in this case a DAO-ACK is sent.
 * The DAO message is then processed and, for each entry
 * contained in it (the exact DAO message structure is too
 * complex to be described here) the routing table is updated
 * accordingly, adding (or updating) each entry and setting the
 * DAO sender as next hop.
 * After the update, the changed entries are stored in a new
 * DAO message and this is immediately sent to the Dao par-
 * ments. Usually the DAO parent is just the preferred parent,
 * but the standard allows multiple DAO parents in order to
 * optimize routes and/or have fallback downward paths. This
 * immediate send is important to quickly update the down-
 * ward routes of the upper nodes, i.e., the ones along the path
 * towards the root.
 *
 */
	return err;
}

struct sk_buff *icmpv6_rpl_dis_new(struct net_device *dev)
{
	struct sk_buff *skb = NULL;
	struct rpl_msg *rpl_msg = NULL;
	size_t msg_length = 0;
	msg_length += 1 /* icmp type */ + 1 /* icmp code */ + 2 /* icmp chksum */;
	msg_length += 2 /* flags + reserved */;
	if((skb = rpl_alloc_skb(dev,msg_length)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating buf\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_put(skb, msg_length);

	rpl_msg->icmp6_type = ICMPV6_RPL;
	rpl_msg->icmp6_code = ICMPV6_RPL_DIS;
	rpl_msg->base.dis.flags = 0;
	rpl_msg->base.dis.reserved = 0;
	return skb;
}

struct sk_buff *icmpv6_rpl_dio_new(
		struct net_device *dev,
		__u8 instanceID,
		__u8 version,
		rpl_rank_t rank,
		bool grounded,
		__u8 mop,
		__u8 prf,
		__u8 DTSN,
		struct in6_addr *dodagid)
{
	struct sk_buff *skb = NULL;
	struct rpl_msg *rpl_msg = NULL;
	size_t msg_length = 0;
	if(!dodagid)
	{
		printk(KERN_ERR "%s(): dodagID NULL pointer\n", __func__);
		return NULL;
	}
	msg_length += 1 /* icmp type */ + 1 /* icmp code */ + 2 /* icmp chksum */;
	msg_length += 1 /* instance */ + 1 /* version */ + 2 /* rank */;
	msg_length += 1 /* G0_MOP_Prf */ + 1 /* DTSN  */ + 1 /* Flags */ + 1 /* reserved */;
	msg_length += 16 /* dodagID */;
	if((skb = rpl_alloc_skb(dev,msg_length)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating buf\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_put(skb, msg_length);
	rpl_msg->icmp6_type = ICMPV6_RPL;
	rpl_msg->icmp6_code = ICMPV6_RPL_DIO;
	rpl_msg->base.dio.instanceID = instanceID;
	rpl_msg->base.dio.version = version;
	rpl_msg->base.dio.rank = cpu_to_be16(rank);
	rpl_msg->base.dio.DTSN = DTSN;
	rpl_msg->base.dio.g_mop_prf = 0;
	rpl_msg->base.dio.g_mop_prf |= ((((grounded)?1:0) & 0x01) << 7);
	rpl_msg->base.dio.g_mop_prf |= ((mop & 0x07) << 3);
	rpl_msg->base.dio.g_mop_prf |= ((prf & 0x07) << 0);
	rpl_msg->base.dio.flags = 0;
	rpl_msg->base.dio.reserved = 0;
	memcpy(&rpl_msg->base.dio.dodagid,dodagid,16);
	return skb;
}

struct sk_buff *icmpv6_rpl_dao_new(
		struct net_device *dev,
		__u8 instanceID,
		__u8 expect_DAO_ACK,
		__u8 DAOSequence,
		struct in6_addr *dodagid)
{
	struct sk_buff *skb = NULL;
	struct rpl_msg *rpl_msg = NULL;
	size_t msg_length = 0;
	msg_length += 1 /* icmp type */ + 1 /* icmp code */ + 2 /* icmp chksum */;
	msg_length += 1 /* instanceID */ + 1 /* KD_flags */ + 1 /* reserved */ + 1 /* DAOSequence */;
	if(dodagid)
		msg_length += 16 /* dodagID */;
	if((skb = rpl_alloc_skb(dev,msg_length)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating buf\n", __func__);
		return NULL;
	}

	rpl_msg = (struct rpl_msg *)skb_put(skb, msg_length);
	rpl_msg->icmp6_type = ICMPV6_RPL;
	rpl_msg->icmp6_code = ICMPV6_RPL_DAO;

	rpl_msg->base.dao.instanceID = instanceID;
	rpl_msg->base.dao.KD_flags = 0;
	rpl_msg->base.dao.KD_flags |= ((expect_DAO_ACK & 0x01) << 7);
	rpl_msg->base.dao.reserved = 0;
	rpl_msg->base.dao.DAOSequence = DAOSequence;
	if(dodagid)
	{
		rpl_msg->base.dao.KD_flags |= (1 << 6);
		memcpy(&rpl_msg->base.dao.u_with_dodagid.dodagid,dodagid,16);
	}
	return skb;
}

struct sk_buff *icmpv6_rpl_dao_ack_new(
		struct net_device *dev,
		__u8 instanceID,
		__u8 DAOSequence,
		__u8 status,
		const struct in6_addr *dodagid)
{
	struct sk_buff *skb = NULL;
	struct rpl_msg *rpl_msg = NULL;
	size_t msg_length = 0;
	msg_length += 1 /* icmp type */ + 1 /* icmp code */ + 2 /* icmp chksum */;
	msg_length += 1 /* instanceID */ + 1 /* D_reserved */ + 1 /* DAOSequence */ + 1 /* status */;
	if(dodagid)
		msg_length += 16 /* dodagID */;
	if((skb = rpl_alloc_skb(dev,msg_length)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating buf\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_put(skb, msg_length);
	rpl_msg->icmp6_type = ICMPV6_RPL;
	rpl_msg->icmp6_code = ICMPV6_RPL_DAO_ACK;

	rpl_msg->base.dao_ack.instanceID = instanceID;
	rpl_msg->base.dao_ack.D_reserved = 0;
	rpl_msg->base.dao_ack.DAOSequence = DAOSequence;
	rpl_msg->base.dao_ack.status = status;
	if(dodagid)
	{
		rpl_msg->base.dao_ack.D_reserved |= (1 << 7);
		memcpy(&rpl_msg->base.dao_ack.u_with_dodagid.dodagid,dodagid,16);
	}
	return skb;
}

struct sk_buff *icmpv6_rpl_cc_new(
		struct net_device *dev,
		__u8 instanceID,
		__u8 is_response,
		__u16 CCNonce,
		struct in6_addr *dodagid,
		__u32 dest_counter
		)
{
	struct sk_buff *skb = NULL;
	struct rpl_msg *rpl_msg = NULL;
	size_t msg_length = 0;
	msg_length += 1 /* icmp type */ + 1 /* icmp code */ + 2 /* icmp chksum */;
	msg_length += 1 /* instanceID */ + 1 /* R_flags */ + 2 /* CCNonce */;
	msg_length += 16 /* dodagID */;
	msg_length += 4 /* destination counter */;
	if(!dodagid)
	{
		printk(KERN_ERR "%s(): dodagID NULL pointer\n", __func__);
		return NULL;
	}
	if((skb = rpl_alloc_skb(dev,msg_length)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating buf\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_put(skb, msg_length);
	rpl_msg->icmp6_type = ICMPV6_RPL;
	rpl_msg->icmp6_code = ICMPV6_RPL_CC;
	rpl_msg->base.cc.instanceID = instanceID;
	rpl_msg->base.cc.R_flags = 0;
	rpl_msg->base.cc.R_flags |= ((is_response & 0x01) << 7);
	rpl_msg->base.cc.CCNonce = cpu_to_be16(CCNonce);
	memcpy(&rpl_msg->base.cc.dodagid,dodagid,16);
	rpl_msg->base.cc.dest_counter = cpu_to_be32(dest_counter);
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_pad1(struct sk_buff *skb)
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_Pad1))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	if((option = (u_rpl_option *) skb_put(skb,1)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->pad1.type = ICMPV6_RPL_OPT_Pad1;
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_padn(struct sk_buff *skb, __u8 n)
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	__u8 i = 0;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_PadN))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	if((option = (u_rpl_option *) skb_put(skb,n-2)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->padn.base.type = ICMPV6_RPL_OPT_PadN;
	option->padn.base.length = n - 2;
	for(i=0;i<n-2;option->padn.zeros[i++]=0);
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_dag_metric_container(struct sk_buff *skb, __u8 *metric_data, __u8 metric_data_len)
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_DAG_Metric_Container))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	if((option = (u_rpl_option *) skb_put(skb,metric_data_len+2)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->dag_metric_container.base.type = ICMPV6_RPL_OPT_DAG_Metric_Container;
	option->dag_metric_container.base.length = metric_data_len;
	memcpy(option->dag_metric_container.data,metric_data,metric_data_len);
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_route_information(
		struct sk_buff *skb,
		__u8 prefix_length,
		__u8 prf,
		__u32 route_lifetime,
		__u8 prefix[16])
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	__u8 option_length = 0;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_Route_Information))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	option_length += 1 /* prefix len */;
	option_length += 1 /* resvd + prf + resvd */;
	option_length += 4 /* route lifetime */;

	/*
	 * Prefix Length: 8-bit unsigned integer.  The number of leading bits in
	 * the prefix that are valid.  The value ranges from 0 to 128.
	 * The Prefix field has the number of bytes inferred from the
	 * Option Length field, that must be at least the Prefix Length.
	 * Note that in RPL, this means that the Prefix field may have
	 * lengths other than 0, 8, or 16.
	 */
	option_length += prefix_length/8+((prefix_length%8)?1:0) /* prefix (variable length) */;
	if((option = (u_rpl_option *) skb_put(skb,option_length+2)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->route_information.base.type = ICMPV6_RPL_OPT_Route_Information;
	option->route_information.base.length = option_length;
	option->route_information.prefix_length = prefix_length;
	option->route_information.Resvd_Prf_Resvd = 0;
	option->route_information.Resvd_Prf_Resvd |= ((prf & 0x03) << 3);
	option->route_information.route_lifetime = cpu_to_be32(route_lifetime);
	memcpy(option->route_information.prefix,prefix,prefix_length/8+((prefix_length%8)?1:0));
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_dodag_configuration(
		struct sk_buff *skb,
		bool auth,
		__u8 PCS,
		__u8 DIOIntDoubl,
		__u8 DIOIntMin,
		__u8 DIORedun,
		rpl_rank_t MaxRankIncrease,
		rpl_rank_t MinHopRankIncrease,
		rpl_ocp_t OCP,
		__u8 def_lifetime,
		__u16 lifetime_unit)
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_DODAG_Configuration))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	if((option = (u_rpl_option *) skb_put(skb,16)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->dodag_configuration.base.type = ICMPV6_RPL_OPT_DODAG_Configuration;
	option->dodag_configuration.base.length = 14;
	option->dodag_configuration.flags_A_PCS = 0;
	option->dodag_configuration.flags_A_PCS |= ((auth & 0x01) << 3);
	option->dodag_configuration.flags_A_PCS |= ((PCS & 0x07) << 0);
	option->dodag_configuration.DIOIntDoubl = DIOIntDoubl;
	option->dodag_configuration.DIOIntMin = DIOIntMin;
	option->dodag_configuration.DIORedun = DIORedun;
	option->dodag_configuration.MaxRankIncrease = cpu_to_be16(MaxRankIncrease);
	option->dodag_configuration.MinHopRankIncrease = cpu_to_be16(MinHopRankIncrease);
	option->dodag_configuration.OCP = cpu_to_be16(OCP);
	option->dodag_configuration.reserved = 0;
	option->dodag_configuration.def_lifetime = def_lifetime;
	option->dodag_configuration.lifetime_unit = cpu_to_be16(lifetime_unit);
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_rpl_target(
		struct sk_buff *skb,
		__u8 prefix_length,
		__u8 target_prefix[16])
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	__u8 option_length = 0;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_RPL_Target))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	option_length += 1 /* flags */;
	option_length += 1 /* prefix len */;

	/*
	 * Prefix Length: 8-bit unsigned integer.  The number of leading bits in
	 * the prefix that are valid.  The value ranges from 0 to 128.
	 * The Prefix field has the number of bytes inferred from the
	 * Option Length field, that must be at least the Prefix Length.
	 * Note that in RPL, this means that the Prefix field may have
	 * lengths other than 0, 8, or 16.
	 */
	option_length += prefix_length/8+((prefix_length%8)?1:0) /* prefix (variable length) */;
	if((option = (u_rpl_option *) skb_put(skb,option_length+2)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->rpl_target.base.type = ICMPV6_RPL_OPT_RPL_Target;
	option->rpl_target.base.length = option_length;
	option->rpl_target.prefix_length = prefix_length;
	memcpy(option->rpl_target.prefix,target_prefix,prefix_length/8+((prefix_length%8)?1:0));
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_transit_information(
		struct sk_buff *skb,
		__u8 external,
		__u8 path_control,
		__u8 path_sequence,
		__u8 path_lifetime,
		struct in6_addr *parent_address)
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	__u8 option_length = 0;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	option_length += 1 /* E_flags */;
	option_length += 3 /* path_control + path_sequence + path_lifetime */;
	if(parent_address)
	{
		option_length += 16; /* parent address if present */
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_Transit_Information))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	if((option = (u_rpl_option *) skb_put(skb,option_length+2)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->transit_information.base.type = ICMPV6_RPL_OPT_Transit_Information;
	option->transit_information.base.length = option_length;
	option->transit_information.E_flags = 0;
	option->transit_information.E_flags |= ((external & 0x01) << 7);
	option->transit_information.path_control = path_control;
	option->transit_information.path_sequence = path_sequence;
	option->transit_information.path_lifetime = path_lifetime;
	if(parent_address)
	{
		memcpy(&option->transit_information.parent,parent_address,16);
	}
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_solicited_information(
		struct sk_buff *skb,
		__u8 instanceID,
		__u8 version_predicate,
		__u8 instanceID_predicate,
		__u8 DODAGID_predicate,
		struct in6_addr *dodagid,
		__u8 version)
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	if(!skb)
	{
		printk(KERN_ERR "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_Solicited_Information))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	if((option = (u_rpl_option *) skb_put(skb,21)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->solicited_information.base.type = ICMPV6_RPL_OPT_Solicited_Information;
	option->solicited_information.base.length = 19;
	option->solicited_information.instanceID = instanceID;
	option->solicited_information.VID_flags = 0;
	option->solicited_information.VID_flags |= ((version_predicate & 0x01) << 7);
	option->solicited_information.VID_flags |= ((instanceID_predicate & 0x01) << 6);
	option->solicited_information.VID_flags |= ((DODAGID_predicate & 0x01) << 5);
	memcpy(&option->solicited_information.dodagid,dodagid,16);
	option->solicited_information.version = version;
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_prefix_information(
		struct sk_buff *skb,
		__u8 prefix_length,
		__u8 on_link,
		__u8 autonomous,
		__u8 router_address,
		__u32	valid_lifetime,
		__u32	preferred_lifetime,
		__u8 prefix[16])
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_Prefix_Information))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	if((option = (u_rpl_option *) skb_put(skb,32)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->prefix_information.base.type = ICMPV6_RPL_OPT_Prefix_Information;
	option->prefix_information.base.length = 30;
	option->prefix_information.prefix_length = prefix_length;
	option->prefix_information.LAR_reserved1 = 0;
	option->prefix_information.LAR_reserved1 |= ((on_link & 0x01) << 7);
	option->prefix_information.LAR_reserved1 |= ((autonomous & 0x01) << 6);
	option->prefix_information.LAR_reserved1 |= ((router_address & 0x01) << 5);
	option->prefix_information.valid_lifetime = cpu_to_be32(valid_lifetime);
	option->prefix_information.preferred_lifetime = cpu_to_be32(preferred_lifetime);
	option->prefix_information.reserved2 = 0;
	memcpy(&option->prefix_information.prefix,prefix,16);
	return skb;
}

struct sk_buff *icmpv6_rpl_add_option_rpl_target_descriptor(
		struct sk_buff *skb,
		__u32 descriptor)
{
	struct rpl_msg *rpl_msg = NULL;
	u_rpl_option *option = NULL;
	if(!skb)
	{
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
		return NULL;
	}
	rpl_msg = (struct rpl_msg *)skb_transport_header(skb);
	if(!icmpv6_rpl_is_option_allowed(rpl_msg->icmp6_code,ICMPV6_RPL_OPT_RPL_Target_Descriptor))
	{
		printk(KERN_ERR "%s(): option not allowed to message: 0x%02X\n", __func__,rpl_msg->icmp6_code);
		return NULL;
	}
	if((option = (u_rpl_option *) skb_put(skb,6)) == NULL)
	{
		printk(KERN_ERR "%s(): error allocating memory to option\n", __func__);
		return NULL;
	}
	option->rpl_target_descriptor.base.type = ICMPV6_RPL_OPT_RPL_Target_Descriptor;
	option->rpl_target_descriptor.base.length = 4;
	option->rpl_target_descriptor.descriptor = cpu_to_be32(descriptor);
	return skb;
}

__u8 *icmpv6_rpl_get_options(struct sk_buff *skb, size_t *p_non_options_len)
{
	size_t non_options_len = 4;
	struct rpl_msg *msg;
	__u8 *options = NULL;
	msg = (struct rpl_msg *)skb_transport_header(skb);
	if(msg)
	{
		if(msg->icmp6_type != ICMPV6_RPL){
			goto out;
		}
		switch (msg->icmp6_code) {
			case ICMPV6_RPL_DIS:
				non_options_len += 2;
				options = (__u8 *)msg->base.dis.dis_options;
				goto out;
				break;
			case ICMPV6_RPL_DIO:
				non_options_len += 24;
				options = (__u8 *)msg->base.dio.dio_options;
				goto out;
				break;
			case ICMPV6_RPL_DAO:
				if(RPL_DAO_D(msg->base.dao.KD_flags))
				{
					// the DODAGID field is present
					non_options_len  += 20;
					options = (__u8 *)msg->base.dao.u_with_dodagid.dao_options;
					goto out;
				}
				else
				{
					non_options_len += 4;
					// the DODAGID field is NOT present
					options = (__u8 *)msg->base.dao.u_no_dodagid.dao_options;
					goto out;
				}
				break;
			case ICMPV6_RPL_DAO_ACK:
				if(RPL_DAO_ACK_D(msg->base.dao_ack.D_reserved))
				{
					non_options_len += 20;
					// the DODAGID field is present
					options = (__u8 *)msg->base.dao_ack.u_with_dodagid.dao_ack_options;
					goto out;
				}
				else
				{
					non_options_len += 4;
					// the DODAGID field is NOT present
					options = (__u8 *)msg->base.dao_ack.u_no_dodagid.dao_ack_options;
					goto out;
				}
				break;
			case ICMPV6_RPL_SEC_DIS:
				break;
			case ICMPV6_RPL_SEC_DIO:
				break;
			case ICMPV6_RPL_SEC_DAO:
				break;
			case ICMPV6_RPL_SEC_DAO_ACK:
				break;
			case ICMPV6_RPL_CC:
				non_options_len += 24;
				options = (__u8 *)msg->base.cc.cc_options;
				goto out;
				break;
			default:
				printk(KERN_DEBUG "%s(): Code: Unknown (0x%02X)\n", __func__,msg->icmp6_code);
				break;
		}
	} else {
		printk(KERN_DEBUG "%s(): null pointer\n", __func__);
	}
out:
	*p_non_options_len=non_options_len;
	return options;
}

__u8 icmpv6_rpl_option_get_length(u_rpl_option *option)
{
	if(option){
		if(*((__u8*)option) == ICMPV6_RPL_OPT_Pad1)
			return 1;
		else
			return *((__u8*)option + 1) + 2;
	}
	return 0;
}

__u8 icmpv6_rpl_option_get_code(u_rpl_option *option)
{
	if(option)
		return *((__u8*)option);
	return 0;
}

u_rpl_option *icmpv6_rpl_option_get_next(u_rpl_option *first, u_rpl_option *current_option, size_t len)
{
	__u8 type = 0;
	__u8 option_len = 0;

	if(!first)
		return NULL;
	if(!current_option)
		return NULL;
	if(current_option >= first+len)
		return NULL;

	type = *((__u8*)current_option);

	if(type == ICMPV6_RPL_OPT_Pad1)
	{
		return (u_rpl_option *) (current_option+1);
	}

	option_len = *((__u8*)current_option+1);

	/* last one */
	if(current_option+option_len >= first+len)
		return NULL;

	return (u_rpl_option *) (current_option+option_len+2);
}

u_rpl_option *icmpv6_rpl_find_option(struct sk_buff *skb, __u8 req_type)
{
	u_rpl_option *option = NULL;
	__u8 type = 0;
	__u8 len = 0;
	__u8 *offset = NULL;
	size_t non_options_len = 0;
	unsigned int options_len = 0;
	struct rpl_msg *msg;
	msg = (struct rpl_msg *)skb_transport_header(skb);
	offset = icmpv6_rpl_get_options(skb,&non_options_len);

	if(!offset)
		return NULL;

	options_len = non_options_len;
	while(options_len<skb->len)
	{
		type = *(offset);
		if(type == ICMPV6_RPL_OPT_Pad1)
		{
			len = 1;
		} else {
			len = *(offset+1);
		}
		option = (u_rpl_option *) offset;
		if(type == req_type)
			goto out;
		if(type == ICMPV6_RPL_OPT_Pad1)
		{
			offset += 1;
			options_len += 1;
		} else {
			offset += len+2;
			options_len += len+2;
		}
	}
	option = NULL;
out:
	return option;
}

int icmpv6_rpl_is_option_allowed(__u8 message_type, __u8 option_type)
{
	switch (message_type) {
		case ICMPV6_RPL_DIS:
		case ICMPV6_RPL_SEC_DIS:
			switch(option_type){
			case ICMPV6_RPL_OPT_Pad1:
			case ICMPV6_RPL_OPT_PadN:
			case ICMPV6_RPL_OPT_Solicited_Information:
				return 1;
				break;
			default:
				return 0;
				break;
			}
			break;
		case ICMPV6_RPL_DIO:
		case ICMPV6_RPL_SEC_DIO:
			switch(option_type){
			case ICMPV6_RPL_OPT_Pad1:
			case ICMPV6_RPL_OPT_PadN:
			case ICMPV6_RPL_OPT_DAG_Metric_Container:
			case ICMPV6_RPL_OPT_Route_Information:
			case ICMPV6_RPL_OPT_DODAG_Configuration:
			case ICMPV6_RPL_OPT_Prefix_Information:
				return 1;
				break;
			default:
				return 0;
				break;
			}
			break;
		case ICMPV6_RPL_DAO:
		case ICMPV6_RPL_SEC_DAO:
			switch(option_type){
			case ICMPV6_RPL_OPT_Pad1:
			case ICMPV6_RPL_OPT_PadN:
			case ICMPV6_RPL_OPT_RPL_Target:
			case ICMPV6_RPL_OPT_Transit_Information:
			case ICMPV6_RPL_OPT_RPL_Target_Descriptor:
				return 1;
				break;
			default:
				return 0;
				break;
			}
			break;
		case ICMPV6_RPL_DAO_ACK:
		case ICMPV6_RPL_SEC_DAO_ACK:
			return 0;
			break;
		case ICMPV6_RPL_CC:
			switch(option_type){
			case ICMPV6_RPL_OPT_Pad1:
			case ICMPV6_RPL_OPT_PadN:
				return 1;
				break;
			default:
				return 0;
				break;
			}
			break;
		default:
			return 1;
			break;
	}
	return 1;
}
