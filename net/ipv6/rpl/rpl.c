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

/*
 * @file rpl.c
 *
 * @date Jul 25, 2013
 * @author Joao Pedro Taveira
 */

#define pr_fmt(fmt) "ICMPv6: " fmt

#include <stddef.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <linux/timer.h>

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/addrconf.h>
#include <net/if_inet6.h>
#include "nlrpl.h"
#include <net/rpl/rpl_constants.h>
#include <net/rpl/rpl_internals.h>
#include <net/rpl/rpl_debug.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/inet_common.h>
#include <net/netevent.h>

#define RPL_DEBUG 3

#define RPL_PRINTK(val, level, fmt, ...)				\
do {								\
	if (val <= RPL_DEBUG)					\
		net_##level##_ratelimited(fmt, ##__VA_ARGS__);	\
} while (0)

DEFINE_LED_TRIGGER_GLOBAL(ledtrig_rpl_joined);

/*
 * Join inet6_dev to a DODAG as non-root
 */
int rpl_ipv6_join(struct net *net, struct rpl_dag_conf *cfg, struct rpl_enabled_device *enabled_device){
	int err = -EINVAL;
	struct rpl_dag *dag;
	bool trigger_dio = false;

	if(enabled_device){
		if(cfg && !cfg->use_defaults){
			dag = rpl_dag_setup_using_conf(net,cfg,&err);
			if(!dag){
				RPL_PRINTK(1, err,"%s(): Error configuring dag: %d\n",__func__,err);
				goto out;
			}
			rpl_dag_set_allowed(dag,enabled_device->dev,true,false,&trigger_dio);
			//FIXME add Solicited Information option to enabled device

			if(dag)
				rpl_dag_put(dag);
		} else {
			mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
			list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
				if(dag && dag->auto_gen){
					rpl_dag_set_allowed(dag,enabled_device->dev,true,true,&trigger_dio);
					if(trigger_dio){
						rpl_dag_inconsistent(dag);
					}
					trigger_dio = false;
				}
			}
			mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
		}
		err = rpl_enabled_device_add_dis_timer(enabled_device);
	}
out:
	return err;
}

/*
 * Disjoin inet6_dev from all DODAG as non-root
 */
int rpl_ipv6_disjoin(struct net_device *dev)
{
	struct net *net = dev_net(dev);
	int err = 0;
	struct rpl_dag *dag;
	struct list_head *dag_ptr,*dag_next;

	mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
	list_for_each_safe(dag_ptr,dag_next,&net->ipv6.rpl.rpl_dags_list_head){
		dag = list_entry(dag_ptr,struct rpl_dag,dag_list);
		//printk(KERN_DEBUG "%s(): REMOVEME checking dag %pI6 on device: %s\n",__func__,&dag->dodagid,idev->dev->name);
		if(rpl_dag_is_allowed(dag,dev)){
			//printk(KERN_DEBUG "%s(): REMOVEME before call dag_disjoin: %s\n",__func__,idev->dev->name);
			err = rpl_dag_disjoin(dag,dev);
			if(err) {
				RPL_PRINTK(1, err,"%s(): Error poisoning dag: %d\n",__func__,err);
			}
		}
	}
	mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
	return err;
}

/*
 * setup dodag root parameters in inet6_dev
 */

struct rpl_start_root_work {
	struct net_device 	*dev;
	struct work_struct 	work;
	struct rpl_dag_conf cfg;
};

static void rpl_start_root_worker(struct work_struct *work)
{
	int err = 0;
	struct rpl_start_root_work *rw = container_of(work, struct rpl_start_root_work, work);
	if (rw->dev == NULL) {
		RPL_PRINTK(2, warn, "%s(): dev is null\n",__func__);
		goto out;
	}
	err = rpl_dag_start_root(dev_net(rw->dev),&rw->cfg,rw->dev);
	if(err)
	{
		RPL_PRINTK(0,err,"%s: error starting root: %d",__func__,err);
	}
out:
	dev_put(rw->dev);
	kfree(rw);
}

int rpl_setup_dodag_root(struct net *net, struct rpl_dag_conf *cfg, struct rpl_enabled_device *enabled_device)
{
	int err = 0;
	struct rpl_start_root_work *work;
	struct in6_addr dodagid;

	/*
	 * This function must check user defined ipv6 address from dev
	 * and start a RPL Root DODAG using such addr as DODAG ID
	 */

	err = ipv6_get_global_addr(enabled_device->dev,&dodagid,0);
	if(err)
	{
		printk(KERN_DEBUG "rpl: %s: Global address not found\n",__func__);
		goto out;
	}

	work = kzalloc(sizeof(struct rpl_start_root_work), GFP_ATOMIC);
	if (!work)
	{
		err = -ENOMEM;
		goto out;
	}

	INIT_WORK(&work->work, rpl_start_root_worker);
	work->dev = enabled_device->dev;
	dev_hold(enabled_device->dev);
	if(cfg){
		memcpy(&work->cfg,cfg,sizeof(*cfg));
	} else {
		rpl_dag_conf_default_init(&work->cfg);
		work->cfg.root = true;
		work->cfg.use_defaults = false;
		memcpy(&work->cfg.dodagid,&dodagid,sizeof(struct in6_addr));

		ipv6_addr_prefix(&work->cfg.prefix_info.prefix,&dodagid,64);
		work->cfg.prefix_info.prefix_len = 64;
		work->cfg.prefix_info.autoconf = true;
		work->cfg.prefix_info.valid = 0xffffffff;
		work->cfg.prefix_info.prefered = 0xffffffff;
	}
	queue_work(net->ipv6.rpl.rpl_rx_wq, &work->work);
out:
	return err;
}

/*
 * Start RPL Protocol in INET6 Device
 */
int rpl_start(struct rpl_dag_conf *cfg, struct net_device *dev)
{
	struct rpl_enabled_device *enabled_device;
	struct inet6_dev *idev;

	int err = 0;
	if(!dev)
	{
		RPL_PRINTK(0,err,"%s: device is NULL",__func__);
		err = -EINVAL;
		goto out;
	}

	idev = __in6_dev_get(dev);
	if(!idev){
		RPL_PRINTK(3,dbg,"%s: IPv6 is disabled",__func__);
		err = -EINVAL;
		goto out;
	}

	if(idev->cnf.disable_ipv6)
	{
		RPL_PRINTK(3,dbg,"%s: IPv6 is disabled",__func__);
		err = -EINVAL;
		goto out;
	}

	enabled_device = rpl_enabled_devices_list_add(dev,&err);
	if(err || !enabled_device)
	{
		RPL_PRINTK(2,err,"%s: error adding dev to enabled devices list",__func__);
		goto out;
	}

	if(!enabled_device->joined_mc){
		RPL_PRINTK(1,dbg, "RPL: Join interface-local all-RPL-node multicast group\n");
		err = ipv6_dev_mc_inc(dev, &in6addr_all_rpl_nodes);
		if(err)
		{
			RPL_PRINTK(2,warn,"RPL: error joining interface-local all-RPL-node multicast group\n");
			goto out;
		}
		enabled_device->joined_mc = true;
	}

	//TODO: should we add a "enabled" to enabled_device flag?
	if(!idev->cnf.rpl_dodag_root){
		err = rpl_ipv6_join(dev_net(dev),cfg,enabled_device);
		if(err)
		{
			RPL_PRINTK(2,warn,"%s: error joining rpl",__func__);
			goto out_mc_dec;
		}
	}
	else if(idev->cnf.rpl_dodag_root){
		err = rpl_setup_dodag_root(dev_net(dev),cfg,enabled_device);
		if(err){
			RPL_PRINTK(2,err,"%s: error setting up dodag root",__func__);
			goto out_mc_dec;
		}
	}

	idev->cnf.rpl_joined = 1;

out:
	return err;

out_mc_dec:
	if(enabled_device->joined_mc){
		RPL_PRINTK(1,dbg, "RPL: Leaving interface-local all-RPL-node multicast group\n");
		//if(__ipv6_dev_mc_dec(idev, &in6addr_all_rpl_nodes)){
		if(ipv6_dev_mc_dec(dev, &in6addr_all_rpl_nodes)){
			RPL_PRINTK(2,warn,"RPL: Error leaving interface-local all-RPL-node multicast group\n");
		}
		enabled_device->joined_mc = false;
	}

	rpl_enabled_devices_list_del(dev);

	goto out;
	return err;
}

/* FIXME when echo 0 > rpl_enabled on a interface and there's some other interface joined in same DAG
 * dCPU: 0 PID: 2105 Comm: kworker/u2:2 Tainted: G           O 3.10.3+ #81
dWorkqueue: eth0 rpl_rx_worker [ipv6]
dtask: da9e8280 ti: da846000 task.ti: da846000
PC is at __mutex_lock_slowpath+0x4c/0x144
LR is at trickle_hear_inconsistent+0x10/0xd8 [ipv6]
pc : [<c03e62b8>]    lr : [<bf087180>]    psr: a0000013
sp : da847e90  ip : 00000000  fp : da814000
r10: 0001e5dc  r9 : 00000000  r8 : d9a08a40
r7 : da9e8280  r6 : d98f4a00  r5 : 0001e5d8  r4 : da846000
r3 : e28ccaab  r2 : da847e94  r1 : 00000000  r0 : 0001e5d8
Flags: NzCv  IRQs on  FIQs on  Mode SVC_32  ISA ARM  Segment kernel
Control: 00c5387d  Table: 18944008  DAC: 00000017
dCPU: 0 PID: 2105 Comm: kworker/u2:2 Tainted: G           O 3.10.3+ #81
dWorkqueue: eth0 rpl_rx_worker [ipv6]
[<c00136f0>] (unwind_backtrace+0x0/0xf0) from [<c0010b4c>] (show_stack+0x10/0x14)
[<c0010b4c>] (show_stack+0x10/0x14) from [<c0075ce8>] (kdb_dumpregs+0x28/0x50)
[<c0075ce8>] (kdb_dumpregs+0x28/0x50) from [<c0077f54>] (kdb_main_loop+0x3c0/0x6c0)
[<c0077f54>] (kdb_main_loop+0x3c0/0x6c0) from [<c007a648>] (kdb_stub+0x154/0x380)
[<c007a648>] (kdb_stub+0x154/0x380) from [<c0071818>] (kgdb_handle_exception+0x32c/0x6c0)
[<c0071818>] (kgdb_handle_exception+0x32c/0x6c0) from [<c0012e70>] (kgdb_notify+0x24/0x40)
[<c0012e70>] (kgdb_notify+0x24/0x40) from [<c03ea0e4>] (notifier_call_chain+0x44/0x84)
[<c03ea0e4>] (notifier_call_chain+0x44/0x84) from [<c03ea15c>] (__atomic_notifier_call_chain+0x38/0x4c)
[<c03ea15c>] (__atomic_notifier_call_chain+0x38/0x4c) from [<c03ea188>] (atomic_notifier_call_chain+0x18/0x20)
[<c03ea188>] (atomic_notifier_call_chain+0x18/0x20) from [<c03ea1c8>] (notify_die+0x38/0x44)
[<c03ea1c8>] (notify_die+0x38/0x44) from [<c0010c14>] (die+0xc4/0x3a8)
[<c0010c14>] (die+0xc4/0x3a8) from [<c03e2ad8>] (__do_kernel_fault.part.9+0x54/0x74)
[<c03e2ad8>] (__do_kernel_fault.part.9+0x54/0x74) from [<c0017344>] (do_bad_area+0x80/0x84)
[<c0017344>] (do_bad_area+0x80/0x84) from [<c03ea058>] (do_translation_fault+0x60/0xa8)
[<c03ea058>] (do_translation_fault+0x60/0xa8) from [<c000834c>] (do_DataAbort+0x34/0x98)
[<c000834c>] (do_DataAbort+0x34/0x98) from [<c03e85f8>] (__dabt_svc+0x38/0x60)
Exception stack(0xda847e48 to 0xda847e90)
7e40:                   0001e5d8 00000000 da847e94 e28ccaab da846000 0001e5d8
7e60: d98f4a00 da9e8280 d9a08a40 00000000 0001e5dc da814000 00000000 da847e90
7e80: bf087180 c03e62b8 a0000013 ffffffff
[<c03e85f8>] (__dabt_svc+0x38/0x60) from [<c03e62b8>] (__mutex_lock_slowpath+0x4c/0x144)
[<c03e62b8>] (__mutex_lock_slowpath+0x4c/0x144) from [<bf087180>] (trickle_hear_inconsistent+0x10/0xd8 [ipv6])
[<bf087180>] (trickle_hear_inconsistent+0x10/0xd8 [ipv6]) from [<bf08f128>] (rpl_ipv6_signal_inconsistency+0x1c/0x2c [ipv6])
[<bf08f128>] (rpl_ipv6_signal_inconsistency+0x1c/0x2c [ipv6]) from [<bf08cdfc>] (rpl_recv_dis+0x88/0xac [ipv6])
[<bf08cdfc>] (rpl_recv_dis+0x88/0xac [ipv6]) from [<bf08e408>] (rpl_rx_worker+0xcc/0x180 [ipv6])
[<bf08e408>] (rpl_rx_worker+0xcc/0x180 [ipv6]) from [<c00364c0>] (process_one_work+0x10c/0x35c)
[<c00364c0>] (process_one_work+0x10c/0x35c) from [<c0036b68>] (worker_thread+0x130/0x3b0)
[<c0036b68>] (worker_thread+0x130/0x3b0) from [<c003c260>] (kthread+0xa4/0xb0)
[<c003c260>] (kthread+0xa4/0xb0) from [<c000dad8>] (ret_from_fork+0x14/0x3c)
 */

/*
 * Stop RPL Protocol in INET6 Device
 */
int rpl_stop(struct net_device *dev)
{
	int err = 0;
	struct inet6_dev *idev;

	printk(KERN_DEBUG "%s(): stoping...\n",__func__);

	idev = __in6_dev_get(dev);
	if(!idev){
		RPL_PRINTK(3,dbg,"%s: IPv6 is disabled",__func__);
		err = -EINVAL;
		goto out;
	}

	err = rpl_ipv6_disjoin(dev);
	if(err)
	{
		RPL_PRINTK(2,warn,"%s: error leaving rpl",__func__);
		goto out;
	}

	err = rpl_enabled_devices_list_del(dev);

	if(err)
	{
		RPL_PRINTK(2,err,"%s: error removing dev to enabled devices list",__func__);
		goto out;
	}

	RPL_PRINTK(1,dbg, "RPL: Leaving interface-local all-RPL-node multicast group\n");
	//if(__ipv6_dev_mc_dec(idev, &in6addr_all_rpl_nodes))
	if(ipv6_dev_mc_dec(dev, &in6addr_all_rpl_nodes))
	{
		RPL_PRINTK(2,warn,"RPL: Error leaving interface-local all-RPL-node multicast group\n");
	}

	idev->cnf.rpl_joined = 0;
out:
	return err;
}

/**
 * @see @file ndisc.c ndisc_rcv
 * */
static int _rpl_rcv(struct net_device *dev, struct sk_buff *skb)
{
	struct rpl_msg *msg;

	struct inet6_dev *idev;

	msg = (struct rpl_msg *)skb_transport_header(skb);

	__skb_push(skb, skb->data - skb_transport_header(skb));

	if (dev == NULL) {
		RPL_PRINTK(2, warn, "%s(): idev is NULL\n",
			  __func__);
		return 0;
	}

	idev = __in6_dev_get(dev);
	if(idev){
		if(msg && idev->cnf.rpl_icmp_dump)
			icmpv6_rpl_print_msg(msg,skb->len);
	}

	switch(msg->icmp6_code){
	case ICMPV6_RPL_DIS:
		rpl_recv_dis(dev,skb);
		break;
	case ICMPV6_RPL_DIO:
		rpl_recv_dio(dev,skb);
		break;
	case ICMPV6_RPL_DAO:
		rpl_recv_dao(dev,skb);
		break;
	case ICMPV6_RPL_DAO_ACK:
		//rpl_recv_dao_ack();
		break;
	case ICMPV6_RPL_CC:
		//rpl_recv_cc();
		break;
	case ICMPV6_RPL_SEC_DIS:
	case ICMPV6_RPL_SEC_DIO:
	case ICMPV6_RPL_SEC_DAO:
	case ICMPV6_RPL_SEC_DAO_ACK:
	default:
		printk(KERN_DEBUG "icmpv6: msg of unknown type (0x%02X)\n",msg->icmp6_type);
	}
	return 0;
}

struct rpl_rx_work {
	struct sk_buff *skb;
	struct work_struct work;
	struct net_device *dev;
};

struct rpl_neigh_check_work {
	struct net_device	*dev;
	struct work_struct 	work;
	struct in6_addr 	neigh_addr;
	__u8				nud_state;
};

static void rpl_rx_worker(struct work_struct *work)
{
	struct rpl_rx_work *rw = container_of(work, struct rpl_rx_work, work);
	struct sk_buff *skb = rw->skb;
	if (rw->dev == NULL) {
		RPL_PRINTK(2, warn, "%s(): idev is null\n",
			  __func__);
	}
	_rpl_rcv(rw->dev,skb);
	dev_put(rw->dev);
	kfree_skb(skb);
	kfree(rw);
}

int rpl_rcv(struct sk_buff *skb)
{
	struct sk_buff *sskb;
	struct rpl_rx_work *work = NULL;
	//struct inet6_dev *idev;
	struct net_device *dev;
	struct net *net;

	if (skb_linearize(skb))
		return 0;

	//idev = in6_dev_get(skb->dev);
	dev = skb->dev;
	net = dev_net(dev);
	if (dev == NULL) {
		RPL_PRINTK(2, warn, "%s(): idev is null\n",
			  __func__);
		return -EINVAL;
	}

	sskb = skb_clone(skb, GFP_ATOMIC);

	work = kzalloc(sizeof(struct rpl_rx_work), GFP_ATOMIC);
	if (!work)
	{
		kfree_skb(sskb);
		return -ENOMEM;
	}

	INIT_WORK(&work->work, rpl_rx_worker);
	work->skb = sskb;

	dev_hold(dev);
	work->dev = dev;

	queue_work(net->ipv6.rpl.rpl_rx_wq, &work->work);

	return 0;
}

static void rpl_neigh_check_worker(struct work_struct *work)
{
	int err = 0;
	struct rpl_dag *dag;
	struct net *net;
	struct rpl_neigh_check_work *rw = container_of(work, struct rpl_neigh_check_work, work);
	if (rw->dev == NULL) {
		RPL_PRINTK(2, warn, "%s(): idev is null\n",__func__);
	}
	net = dev_net(rw->dev);
	printk(KERN_DEBUG "RPL: call unlink: key: %pI6%%%s nud_state: 0x%02X (0x20 == NUD_FAILED)\n",&rw->neigh_addr,rw->dev->name,rw->nud_state);

	mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
	list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
		if(rpl_dag_is_allowed(dag,rw->dev)){
			err = rpl_dag_unlink_node(dag,rw->dev,&rw->neigh_addr);
			if(err){
				printk(KERN_ERR "RPL: error unlinking node (err %d)\n",err);
			}

			rpl_dag_dbg_dump(dag);

			err = rpl_dag_target_unreachable(dag,rw->dev,&rw->neigh_addr);
			if(err){
				printk(KERN_ERR "RPL: error marking target unreachable (err %d)\n",err);
			}
		}
	}
	mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
	dev_put(rw->dev);
	kfree(rw);
}

static int rpl_netevent_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct neighbour *neigh;
	struct rpl_neigh_check_work *work = NULL;
	//struct inet6_dev *idev;
	struct net_device *dev;
	struct net *net;

	switch(event)
	{
	case NETEVENT_NEIGH_UPDATE:
		neigh = (struct neighbour *) ptr;
		if(neigh && neigh->tbl && neigh->tbl->family == AF_INET6)
		{
			if(neigh->nud_state & NUD_FAILED){
				// idev = in6_dev_get(neigh->dev);
				dev = neigh->dev;
				net = dev_net(dev);
				if (dev == NULL) {
					RPL_PRINTK(2, warn, "%s(): dev is null\n",__func__);
					goto out;
				}
				dev_hold(dev);
				work = kzalloc(sizeof(struct rpl_neigh_check_work), GFP_ATOMIC);
				if (!work)
				{
					dev_put(dev);
					goto out;
				}

				INIT_WORK(&work->work, rpl_neigh_check_worker);
				work->dev = dev;
				memcpy(&work->neigh_addr,neigh->primary_key,neigh->tbl->key_len);
				work->nud_state = neigh->nud_state;

				queue_work(net->ipv6.rpl.rpl_rx_wq, &work->work);
			}
		}
		break;
	default:

		break;
	}

out:
	return NOTIFY_DONE;
}

static int rpl_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0))
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
#else
	struct net_device *dev = ptr;
#endif
	struct inet6_dev *idev;

	printk(KERN_DEBUG "%s: received event: %lu\n",__func__,event);
	printk(KERN_DEBUG "%s: refcnt %d %s\n",dev->name, netdev_refcnt_read(dev), __FUNCTION__);

	switch (event) {
	case NETDEV_UP:
	case NETDEV_CHANGE:
		idev = in6_dev_get(dev);
		if (!idev)
			break;
		printk(KERN_DEBUG "%s(): REMOVEME calling in6_dev_get: %s\n",__func__,dev->name);
		if (idev->cnf.rpl_enabled && !idev->cnf.rpl_joined && (idev->if_flags & IF_READY)){
			printk(KERN_DEBUG "%s: REMOVEME rpl_start(%s) here\n",__func__,dev->name);
			if (rpl_start(NULL,dev)) {
				printk(KERN_WARNING "RPL: error starting RPL on %s\n",dev->name);
			}
		}
		printk(KERN_DEBUG "%s(): REMOVEME calling in6_dev_put: %s\n",__func__,dev->name);
		in6_dev_put(idev);
		break;
	case NETDEV_DOWN:
		//FIXME we should call rpl_stop
		printk(KERN_DEBUG "%s(): NETDEV_DOWN: dev: %s\n",__func__,dev->name);
		break;
	case NETDEV_GOING_DOWN:
		printk(KERN_DEBUG "%s(): NETDEV_GOING_DOWN: before get dev: %s\n",__func__,dev->name);
		printk(KERN_DEBUG "%s(): REMOVEME calling in6_dev_get: %s\n",__func__,dev->name);
		idev = in6_dev_get(dev);
		if (!idev){
			printk(KERN_DEBUG "%s(): dev is NULL: %s\n",__func__,dev->name);
			break;
		}
		printk(KERN_DEBUG "%s(): before joined\n",__func__);
		if (idev->cnf.rpl_joined){ //FIXME ...
			printk(KERN_DEBUG "%s(): joined\n",__func__);
			if (rpl_stop(dev)) {
				printk(KERN_WARNING "RPL: error stopping RPL on %s\n",dev->name);
			}
		}
		printk(KERN_DEBUG "%s(): REMOVEME calling in6_dev_put: %s\n",__func__,idev->dev->name);
		if(idev)
			in6_dev_put(idev);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static int rpl_inet6addr_event(struct notifier_block *this,
			   unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifa = ptr;


	printk(KERN_DEBUG "%s: received event: %lu %pI6%%%s\n",__func__,event,&ifa->addr,ifa->idev->dev->name);

	//return masq_device_event(this, event, ifa->idev->dev);

	// FIXME do we want to return DONE?
	return NOTIFY_DONE;
}

//FIXME we must detect that interface will be down

static struct notifier_block rpl_netdev_notifier = {
	.notifier_call = rpl_netdev_event,
};

static struct notifier_block rpl_netevent_notifier = {
	.notifier_call = rpl_netevent_event,
};

static struct notifier_block rpl_inet6addr_notifier = {
	.notifier_call	= rpl_inet6addr_event,
};

const struct in6_addr in6addr_all_rpl_nodes = IN6ADDR_ALL_RPL_NODES_INIT;

int rpl_sysctl_rpl_enabled(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	struct inet6_dev *idev = NULL;
	int old = 0;

	if(write)
	{
		if(!ctl)
		{
			printk(KERN_WARNING "RPL: ctl is NULL\n");
			return 0;
		}
		idev = (struct inet6_dev *)ctl->extra1;
		if(!idev)
		{
			printk(KERN_WARNING "RPL: dev is NULL\n");
			return 0;
		}
		old = idev->cnf.rpl_enabled;
	}

	if(!ctl)
	{
		printk(KERN_WARNING "RPL: ctl is NULL\n");
	} else {
		idev = (struct inet6_dev *)ctl->extra1;
		if(!idev)
		{
			printk(KERN_WARNING "RPL: dev is NULL\n");
		} else {
			printk(KERN_DEBUG "RPL: %s(): called on %s\n",__func__,(idev && idev->dev)?idev->dev->name:"unknown");
		}
	}

	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	if(ret)
		return ret;

	if(write && (idev->if_flags & IF_READY)){
		if(old != idev->cnf.rpl_enabled)
		{
			if(idev->cnf.rpl_enabled && !idev->cnf.rpl_joined)
			{
				if (rpl_start(NULL,idev->dev)) {
					printk(KERN_WARNING "RPL: error starting RPL\n");
					ret = -EINVAL;
					idev->cnf.rpl_enabled = old;
				}
			}else if(!idev->cnf.rpl_enabled && idev->cnf.rpl_joined) {
				if (rpl_stop(idev->dev)) {
					printk(KERN_WARNING "RPL: error stop RPL\n");
					ret = -EINVAL;
					idev->cnf.rpl_enabled = old;
				}
			}
		} else {
			rpl_dags_list_dump(dev_net(idev->dev));
		}
	}
	return ret;
}

int rpl_sysctl_rpl_joined(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	if(!write){
		ret = proc_dointvec(ctl, 0, buffer, lenp, ppos);
	} else {
		ret = -EPERM;
	}
	return ret;
}

int rpl_sysctl_rpl_dodag_root(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	return ret;
}

int rpl_sysctl_rpl_icmp_dump(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	return ret;
}

static int __net_init rpl_net_init(struct net *net)
{
	struct ipv6_pinfo *np;
	struct sock *sk;
	int err = 0;

	err = rpl_enabled_devices_list_init(&net->ipv6.rpl);
	if(err)
		goto out;
	err = rpl_instances_list_init(&net->ipv6.rpl);
	if(err)
		goto out_free_devices_list;
	err = rpl_dags_list_init(&net->ipv6.rpl);
	if(err)
		goto out_free_instances;

	err = inet_ctl_sock_create(&sk, PF_INET6,
				   SOCK_RAW, IPPROTO_ICMPV6, net);
	if (err < 0) {
		RPL_PRINTK(0, err,
			  "RPL: Failed to initialize the control socket (err %d)\n",
			  err);
		goto out_free_dags;
	}

	net->ipv6.rpl.rpl_sk = sk;

	np = inet6_sk(sk);
	np->hop_limit = 255;
	/* Do not loopback ndisc messages */
	np->mc_loop = 0;
	goto out;

out_free_dags:
	rpl_dags_list_cleanup(&net->ipv6.rpl);
out_free_instances:
	rpl_instances_list_cleanup(&net->ipv6.rpl);
out_free_devices_list:
	rpl_enabled_devices_list_cleanup(&net->ipv6.rpl);
out:
	return err;
}

static void __net_exit rpl_net_exit(struct net *net)
{
	// FIXME destroy RPL netns structure
	inet_ctl_sock_destroy(net->ipv6.rpl.rpl_sk);
	net->ipv6.rpl.rpl_sk = NULL;

	rpl_dags_list_cleanup(&net->ipv6.rpl);
	rpl_instances_list_cleanup(&net->ipv6.rpl);
	rpl_enabled_devices_list_cleanup(&net->ipv6.rpl);
}

static struct pernet_operations rpl_net_ops = {
	.init = rpl_net_init,
	.exit = rpl_net_exit,
};

extern int rpl_of_list_init(void);
extern int rpl_of_list_cleanup(void);

int __init rpl_init(void)
{
	int err;

	pr_info("RPL IPv6\n");

	err = rpl_of_list_init();
	if(err)
		goto out;
	err = register_pernet_subsys(&rpl_net_ops);
	if (err)
		goto out_free_of_list;
	err = register_netdevice_notifier(&rpl_netdev_notifier);
	if (err)
		goto out_unregister_pernet;
	err = register_netevent_notifier(&rpl_netevent_notifier);
	if (err)
		goto out_unregister_netdev;
	err = register_inet6addr_notifier(&rpl_inet6addr_notifier);
	if (err)
		goto out_unregister_netevent;
	err = rpl_nl_init();
	if(err)
		goto out_unregister_inet6addr;
	led_trigger_register_simple("rpl",&ledtrig_rpl_joined);
out:
	return err;
out_unregister_inet6addr:
	unregister_inet6addr_notifier(&rpl_inet6addr_notifier);
out_unregister_netevent:
	unregister_netevent_notifier(&rpl_netevent_notifier);
out_unregister_netdev:
	unregister_netdevice_notifier(&rpl_netdev_notifier);
out_unregister_pernet:
	unregister_pernet_subsys(&rpl_net_ops);
out_free_of_list:
	rpl_of_list_cleanup();
goto out;
	return err;
}

void rpl_cleanup(void){
	printk(KERN_DEBUG "%s: ...\n",__func__);
	led_trigger_unregister_simple(ledtrig_rpl_joined);
	rpl_nl_exit();
	unregister_inet6addr_notifier(&rpl_inet6addr_notifier);
	unregister_netevent_notifier(&rpl_netevent_notifier);
	unregister_netdevice_notifier(&rpl_netdev_notifier);
	unregister_pernet_subsys(&rpl_net_ops);
	rpl_of_list_cleanup();
}
