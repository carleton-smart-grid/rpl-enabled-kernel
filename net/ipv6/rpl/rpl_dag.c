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
 * @file rpl_dag.c
 *
 * @date Aug 1, 2013
 * @author Joao Pedro Taveira
 */

#define pr_fmt(fmt) "RPL: " fmt

#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/list_sort.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/rpl/rpl_debug.h>
#include <net/rpl/rpl_constants.h>
#include <net/rpl/rpl_internals.h>
#include <net/rpl/rpl_dag.h>
#include <net/rpl/rpl_trickle.h>

#define RPL_DEBUG 3

#define RPL_PRINTK(val, level, fmt, ...)				\
do {								\
	if (val <= RPL_DEBUG)					\
		net_##level##_ratelimited(fmt, ##__VA_ARGS__);	\
} while (0)

static struct mutex of_list_mutex;
static struct list_head of_list_head;

/*
 * Lollipop compare (from contiki rpl-dag.c)
 */
int lollipop_greater_than(int a, int b) {
	/* Check if we are comparing an initial value with an old value */
	if (a > RPL_LOLLIPOP_CIRCULAR_REGION && b <= RPL_LOLLIPOP_CIRCULAR_REGION) {
		return (RPL_LOLLIPOP_MAX_VALUE + 1 + b - a)
				> RPL_LOLLIPOP_SEQUENCE_WINDOW;
	}
	/* Otherwise check if a > b and comparable => ok, or
	 if they have wrapped and are still comparable */
	return (a > b && (a - b) < RPL_LOLLIPOP_SEQUENCE_WINDOW)
			|| (a < b && (b - a) > (RPL_LOLLIPOP_CIRCULAR_REGION + 1 -
			RPL_LOLLIPOP_SEQUENCE_WINDOW));
}

/*
 * Objective Function Interface
 */
struct rpl_of *rpl_of_alloc(rpl_ocp_t ocp, struct rpl_of_ops *ops)
{
	struct rpl_of *of;
	if(	!ops || !ops->reset || !ops->parent_state_callback ||
		!ops->best_parent || !ops->best_dag || !ops->calculate_rank ||
		!ops->update_metric_container){
		RPL_PRINTK(2, err,
				"%s: undefined RPL Objective Function operations\n",__func__);
		goto out;
	}
	of = kzalloc(sizeof(struct rpl_of), GFP_KERNEL);
	if(!of)
		goto out;
	INIT_LIST_HEAD(&of->of_list);
	of->ocp = ocp;
	of->ops = ops;
	return of;
out:
	return NULL;
}
EXPORT_SYMBOL(rpl_of_alloc);

void rpl_of_free(struct rpl_of *of)
{
	if(of)
		kfree(of);
}
EXPORT_SYMBOL(rpl_of_free);

int rpl_of_register(struct rpl_of *of)
{
	if(of){
		mutex_lock(&of_list_mutex);
		list_add(&of->of_list,&of_list_head);
		mutex_unlock(&of_list_mutex);
	}
	return 0;
}
EXPORT_SYMBOL(rpl_of_register);

void rpl_of_unregister(struct rpl_of *of)
{
	if(of){
		mutex_lock(&of_list_mutex);
		list_del(&of->of_list);
		mutex_unlock(&of_list_mutex);
	}
}
EXPORT_SYMBOL(rpl_of_unregister);

struct rpl_of *rpl_of_get(rpl_ocp_t ocp)
{
	struct list_head *ptr;
	struct rpl_of *entry;
	mutex_lock(&of_list_mutex);
	list_for_each(ptr, &of_list_head)
	{
		entry = list_entry(ptr,struct rpl_of,of_list);
		if (entry->ocp == ocp) {
			mutex_unlock(&of_list_mutex);
			return entry;
		}
	}
	mutex_unlock(&of_list_mutex);
	request_module("rpl-of-%d",ocp);
	mutex_lock(&of_list_mutex);
	list_for_each(ptr, &of_list_head)
	{
		entry = list_entry(ptr,struct rpl_of,of_list);
		if (entry->ocp == ocp) {
			mutex_unlock(&of_list_mutex);
			return entry;
		}
	}
	mutex_unlock(&of_list_mutex);
	return NULL;
}
EXPORT_SYMBOL(rpl_of_get);

rpl_rank_t rpl_of_calculate_rank(struct rpl_of *of, struct rpl_node *parent, rpl_rank_t base, int *err)
{
	rpl_rank_t new_rank = RPL_INFINITE_RANK;
	if(of && of->ops && of->ops->calculate_rank)
	{
		new_rank = of->ops->calculate_rank(parent,base);
	}
	return new_rank;
}
EXPORT_SYMBOL(rpl_of_calculate_rank);

int rpl_of_compare_nodes(struct rpl_of *of, struct rpl_node *p1, struct rpl_node *p2, int *err)
{
	int res = 0;
	if(of && of->ops && of->ops->compare_nodes)
	{
		res = of->ops->compare_nodes(p1,p2);
	}
	return res;
}
EXPORT_SYMBOL(rpl_of_compare_nodes);

/*
 * RPL Instances List Interface
 */
int rpl_instances_list_init(struct netns_rpl *rplns)
{
	INIT_LIST_HEAD(&rplns->rpl_instances_list_head);
	mutex_init(&rplns->rpl_instances_list_mutex);
	return 0;
}

int rpl_instances_list_cleanup(struct netns_rpl *rplns)
{
	BUG_ON(!list_empty(&rplns->rpl_instances_list_head));
	mutex_destroy(&rplns->rpl_instances_list_mutex);
	return 0;
}

struct rpl_instance *rpl_instances_find(struct net *net, __u8 instanceID)
{
	struct list_head *ptr;
	struct rpl_instance *entry;
	mutex_lock(&net->ipv6.rpl.rpl_instances_list_mutex);
	list_for_each(ptr, &net->ipv6.rpl.rpl_instances_list_head)
	{
		entry = list_entry(ptr,struct rpl_instance,instances_list);
		if (entry->instanceID == instanceID) {
			mutex_unlock(&net->ipv6.rpl.rpl_instances_list_mutex);
			rpl_instance_hold(entry);
			return entry;
		}
	}
	mutex_unlock(&net->ipv6.rpl.rpl_instances_list_mutex);
	return NULL;
}

/*
 * RPL Enabled Network Devices
 */

int rpl_enabled_devices_list_init(struct netns_rpl *rplns){
	int ret = 0;
	INIT_LIST_HEAD(&rplns->rpl_enabled_devices_list_head);
	mutex_init(&rplns->rpl_enabled_devices_list_mutex);

	rplns->rpl_rx_wq = create_singlethread_workqueue("rpl_rx");
	if (!rplns->rpl_rx_wq)
		ret = -ENOMEM;

	return ret;
}

int rpl_enabled_devices_list_cleanup(struct netns_rpl *rplns)
{
	flush_workqueue(rplns->rpl_rx_wq);
	destroy_workqueue(rplns->rpl_rx_wq);

	BUG_ON(!list_empty(&rplns->rpl_enabled_devices_list_head));
	mutex_destroy(&rplns->rpl_enabled_devices_list_mutex);
	return 0;
}

static void rpl_dis_timer_handler(unsigned long arg){
	int err = 0;
	struct rpl_enabled_device *enabled = (struct rpl_enabled_device *)arg;

	err = rpl_send_dis(enabled);
	if(err){
		RPL_PRINTK(1,err,"RPL: Error sending DIS: %d\n",err);
	}
	mod_timer(&enabled->dis_timer,jiffies + RPL_DIS_INTERVAL*HZ);
}

int rpl_enabled_device_del_dis_timer(struct rpl_enabled_device *enabled){
	int err = 0;
	if(timer_pending(&enabled->dis_timer)){
		if((err = try_to_del_timer_sync(&enabled->dis_timer))<0){
			RPL_PRINTK(0, err,"RPL: Failed to del dis timer (err %d)\n",err);
		}
	}
	return err;
}

struct rpl_enabled_device *_rpl_enabled_device_get(struct net_device *dev){
	struct list_head *ptr;
	struct rpl_enabled_device *entry;
	struct net *net;
	if(dev){
		net = dev_net(dev);
		list_for_each(ptr, &net->ipv6.rpl.rpl_enabled_devices_list_head){
			entry = list_entry(ptr,struct rpl_enabled_device,enabled_list);
			if (entry && dev == entry->dev) {
				return entry;
			}
		}
	}
	return NULL;
}

struct rpl_enabled_device *rpl_enabled_device_get(struct net_device *dev){
	struct rpl_enabled_device *entry = NULL;
	struct net *net;
	if(dev){
		net = dev_net(dev);
		mutex_lock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
		entry = _rpl_enabled_device_get(dev);
		mutex_unlock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
	}
	return entry;
}

struct rpl_enabled_device *_rpl_enabled_device_find_by_name(struct net *net,const char name[IFNAMSIZ + 1]){
	struct list_head *ptr;
	struct rpl_enabled_device *entry;
	if(name){
		list_for_each(ptr, &net->ipv6.rpl.rpl_enabled_devices_list_head){
			entry = list_entry(ptr,struct rpl_enabled_device,enabled_list);
			if (entry && entry->dev && !strcmp(entry->dev->name,name)) {
				return entry;
			}
		}
	}
	return NULL;
}

struct rpl_enabled_device *rpl_enabled_device_find_by_name(struct net *net, const char name[IFNAMSIZ + 1]){
	struct rpl_enabled_device *entry = NULL;
	if(name){
		mutex_lock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
		entry = _rpl_enabled_device_find_by_name(net,name);
		mutex_unlock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
	}
	return entry;
}

struct net_device *rpl_enabled_device_find_idev_by_name(struct net *net, const char name[IFNAMSIZ + 1]){
	struct rpl_enabled_device *entry = NULL;
	struct net_device *dev = NULL;
	if(name){
		mutex_lock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
		entry = _rpl_enabled_device_find_by_name(net,name);
		if(entry){
			dev = entry->dev;
			dev_hold(dev);
		}
		mutex_unlock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
	}
	return dev;
}

int rpl_enabled_device_add_dis_timer(struct rpl_enabled_device *enabled){
	int err = 0;
	if (unlikely(mod_timer(&enabled->dis_timer, jiffies + RPL_DIS_INIT_INTERVAL*HZ))) {
		printk("RPL: BUG, double timer add\n");
		dump_stack();
	}
	return err;
}

struct rpl_enabled_device *rpl_enabled_devices_list_add(struct net_device *dev, int *err){
	int ret = -EINVAL;
	struct rpl_enabled_device *enabled = NULL;
	struct inet6_dev *idev;
	struct net *net;
	if(dev){
		net = dev_net(dev);
		mutex_lock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
		enabled = _rpl_enabled_device_get(dev);

		if(!enabled){
			enabled = kmalloc(sizeof(struct rpl_enabled_device), GFP_KERNEL);
			if(!enabled)
			{
				RPL_PRINTK(0, err,
						"%s(): Error allocating memory to enabled device\n",
						__func__);
				ret = -ENOMEM;
				mutex_unlock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
				goto out;
			}
			INIT_LIST_HEAD(&enabled->enabled_list);
			enabled->dev = dev;

			printk(KERN_DEBUG "%s(): REMOVEME calling in6_dev_get: %s\n",__func__,dev->name);
			idev = in6_dev_get(dev);
			if(!idev){
				kfree(enabled);

				mutex_unlock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
				ret = -ENOTSUPP;
				goto out;
			}
			idev->cnf.rpl_enabled = 1;
			printk(KERN_DEBUG "%s(): REMOVEME calling in6_dev_put: %s\n",__func__,dev->name);
			in6_dev_put(idev);

			enabled->joined_mc = false;
			enabled->solicited_information = NULL;
			dev_hold(dev);

			setup_timer(&enabled->dis_timer, rpl_dis_timer_handler, (unsigned long) enabled);

			list_add(&enabled->enabled_list,&net->ipv6.rpl.rpl_enabled_devices_list_head);
		}
		mutex_unlock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
		ret = 0;
	}
out:
	if(err)
		*err = ret;
	return enabled;
}

int rpl_enabled_devices_list_del(struct net_device *dev){
	int err = -EINVAL;
	struct list_head *ptr,*next;
	struct rpl_enabled_device *entry;
	struct inet6_dev *idev;
	struct net *net;
	if(dev){
		net = dev_net(dev);
		mutex_lock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
		list_for_each_safe(ptr, next, &net->ipv6.rpl.rpl_enabled_devices_list_head){
			entry = list_entry(ptr,struct rpl_enabled_device,enabled_list);
			if (entry && dev == entry->dev) {
				printk(KERN_DEBUG "%s(): REMOVEME calling in6_dev_get: %s\n",__func__,dev->name);
				idev = in6_dev_get(entry->dev);
				if(idev){
					idev->cnf.rpl_enabled = 0;
					printk(KERN_DEBUG "%s(): REMOVEME calling in6_dev_put: %s\n",__func__,dev->name);
					in6_dev_put(idev);
				}
				list_del(&entry->enabled_list);
				rpl_enabled_device_del_dis_timer(entry);
				dev_put(entry->dev);
				if(entry->solicited_information)
					kfree(entry->solicited_information);
				kfree(entry);
				break;
			}
		}
		mutex_unlock(&net->ipv6.rpl.rpl_enabled_devices_list_mutex);
		err = 0;
	}
	return err;
}

/*
 * RPL Objective Functions List
 */
int rpl_of_list_init(void)
{
	INIT_LIST_HEAD(&of_list_head);
	mutex_init(&of_list_mutex);
	return 0;
}

int rpl_of_list_cleanup(void)
{
	BUG_ON(!list_empty(&of_list_head));
	mutex_destroy(&of_list_mutex);
	return 0;
}

/*
 * RPL Instance Functions
 */

int rpl_instance_add(struct rpl_instance *instance)
{
	struct list_head *ptr;
	struct rpl_instance *entry;
	struct net *net;
	if(!instance){
		return -EINVAL;
	}
	net = instance->net;
	mutex_lock(&net->ipv6.rpl.rpl_instances_list_mutex);
	list_for_each(ptr, &net->ipv6.rpl.rpl_instances_list_head)
	{
		entry = list_entry(ptr,struct rpl_instance,instances_list);
		if (entry->instanceID == instance->instanceID &&
				entry != instance) {
			RPL_PRINTK(2, warn,
					"%s: instance already exists\n",__func__);
			mutex_unlock(&net->ipv6.rpl.rpl_instances_list_mutex);
			return -EPERM;
		}
	}
	list_add(&instance->instances_list,&net->ipv6.rpl.rpl_instances_list_head);
	mutex_unlock(&net->ipv6.rpl.rpl_instances_list_mutex);
	return 0;
}

int rpl_instance_del(struct rpl_instance *instance)
{
	struct net *net;
	if(!instance){
		return -EINVAL;
	}
	net = instance->net;
	mutex_lock(&net->ipv6.rpl.rpl_instances_list_mutex);
	list_del(&instance->instances_list);
	mutex_unlock(&net->ipv6.rpl.rpl_instances_list_mutex);
	return 0;
}

struct rpl_instance *rpl_instance_new(struct net *net, __u8 instanceID, rpl_ocp_t ocp)
{
	struct rpl_instance *instance = NULL;
	instance = kzalloc(sizeof(struct rpl_instance), GFP_KERNEL);
	if(!instance)
		goto out;
	INIT_LIST_HEAD(&instance->instances_list);

	instance->instanceID = instanceID;
	instance->net = net;
	instance->of = rpl_of_get(ocp);
	if(!instance->of)
	{
		RPL_PRINTK(2, warn,
				"%s: Objective Function not supported\n",__func__);
		rpl_instance_free(instance);
		return NULL;
	}

	rpl_instance_hold(instance);

	rpl_instance_add(instance);

	return instance;
out:
	return NULL;

}

void rpl_instance_free(struct rpl_instance *instance)
{
	if(instance){
		RPL_PRINTK(2, warn,
						"%s: Freeing instance: 0x%02X\n",__func__,instance->instanceID);
		rpl_instance_del(instance);
		kfree(instance);
	}
}

/*
 * RPL DAG Functions
 */

void rpl_dag_dio_timer_handler(unsigned long arg)
{
	struct rpl_dag *dag = (struct rpl_dag *) arg;
	int err = 0;
	if(dag)
	{
		err = rpl_send_dio(dag,NULL,NULL,true,false);
	}
	return;
}

int rpl_dag_dio_timer_reset(struct rpl_dag *dag)
{
	int err = -EINVAL;
	if(dag)
	{
		if(dag->dio_timer)
		{
			trickle_free(dag->dio_timer);
		}
		dag->dio_timer = trickle_new(1 << dag->DIOIntMin,dag->DIOIntDoubl,dag->DIORedun,rpl_dag_dio_timer_handler,(unsigned long)dag);
		if(!dag->dio_timer)
		{
			RPL_PRINTK(0, err,
					"%s(): Error creating trickle\n",
					__func__);
			err = -ENOMEM;
			goto out;
		}
		err = trickle_start(dag->dio_timer);
		if(err)
		{
			RPL_PRINTK(0, err,
					"%s(): Error starting trickle\n",
					__func__);
			goto out;
		}
		msleep(500);
	}
out:
	return err;
}

struct rpl_dao_tx_work {
	struct work_struct 	work;
	struct rpl_dag 		*dag;
};

static void rpl_dag_dao_tx_worker(struct work_struct *work){
	int err = 0;
	struct rpl_dao_tx_work *rw = container_of(work, struct rpl_dao_tx_work, work);

	printk(KERN_DEBUG "%s(): called DAO trigger\n",__func__);

	if(rw && rw->dag){
		err = rpl_send_dao(rw->dag,NULL,true,false);
		if(err)
		{
			RPL_PRINTK(1,err,"RPL: Error sending DAO to all nodes: %d\n",err);
		}
		err = rpl_send_dao(rw->dag,NULL,false,false);
		if(err)
		{
			RPL_PRINTK(1,err,"RPL: Error sending DAO to DAO parents: %d\n",err);
		}
		rpl_dag_put(rw->dag);
	}
	if(rw)
		kfree(rw);
}

static void rpl_dag_dao_timer_handler(unsigned long arg){
	struct rpl_dao_tx_work *work;
	struct rpl_dag *dag = (struct rpl_dag *) arg;
	work = kzalloc(sizeof(struct rpl_dao_tx_work), GFP_ATOMIC);
	if (!work)
	{
		goto out;
	}
	INIT_WORK(&work->work, rpl_dag_dao_tx_worker);
	work->dag = dag;
	queue_work(dag->dao_tx_wq, &work->work);
out:
	return;
}

void rpl_dag_cancel_dao_timer(struct rpl_dag *dag){
	int err = 0;
	if(dag && timer_pending(&dag->dao_timer)){
		if((err = try_to_del_timer_sync(&dag->dao_timer))<0){
			RPL_PRINTK(0, err,"%s(): Failed to del dis timer (err %d)\n",__func__,err);
		}
		rpl_dag_put(dag);
	}
}

struct rpl_dag *rpl_dag_alloc(struct rpl_instance *instance, struct in6_addr *dodagid, int *err){
	struct rpl_dag *dag;
	dag = kzalloc(sizeof(struct rpl_dag), GFP_KERNEL);
	if(!dag){
		RPL_PRINTK(0, err,"%s(): Error allocating memory to dag\n",__func__);
		*err = -ENOMEM;
		goto out;
	}
	INIT_LIST_HEAD(&dag->dag_list);
	memcpy(&dag->dodagid,dodagid,16);

	setup_timer(&dag->dao_timer, rpl_dag_dao_timer_handler, (unsigned long) dag);
	dag->dao_tx_wq = create_singlethread_workqueue("dao_tx_wq");
	if(!dag->dao_tx_wq){
		RPL_PRINTK(0, err,"%s(): Error creating workqueue\n",__func__);
		*err = -ENOMEM;
		kfree(dag);
		goto out;
	}

	dag->DTSN = RPL_LOLLIPOP_INIT;
	dag->version = RPL_LOLLIPOP_INIT;
	dag->DAOSequence = RPL_LOLLIPOP_INIT;

	rpl_dag_set_rank(dag,RPL_INFINITE_RANK);
	dag->PCS = RPL_DEFAULT_PATH_CONTROL_SIZE;

	dag->authenticated = false;

	dag->DIOIntDoubl = RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS;
	dag->DIOIntMin = RPL_DEFAULT_DIO_INTERVAL_MIN;
	dag->DIORedun = RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT;

	dag->MaxRankIncrease = RPL_DEFAULT_MAX_RANK_INCREASE;
	dag->MinHopRankIncrease = RPL_DEFAULT_MIN_HOP_RANK_INCREASE;

	dag->def_lifetime = 0xff;
	dag->lifetime_unit = 0xffff;

	dag->auto_gen = false;
	dag->is_root = false;
	dag->dio_timer = NULL;

	dag->unreachable_counter = 0;

	rpl_instance_hold(instance);
	dag->instance = instance;

	mutex_init(&dag->parents_lock);
	INIT_LIST_HEAD(&dag->neighbours);
	INIT_LIST_HEAD(&dag->dodag_parents);

	INIT_LIST_HEAD(&dag->targets_head);

	INIT_LIST_HEAD(&dag->allowed_interfaces);

	rpl_dag_hold(dag);
out:
	return dag;
}

bool rpl_dag_is_allowed(struct rpl_dag *dag, struct net_device *dev){
	bool allowed = false;
	struct rpl_allowed_if *allowed_if;
	if(dag){
		if(dag->auto_gen){
			allowed = true;
		} else {
			list_for_each_entry(allowed_if,&dag->allowed_interfaces,allowed_if_list){
				//printk(KERN_DEBUG "%s(): checking %X %s and %X %s\n",__func__,dev,dev->name,allowed_if->dev,allowed_if->dev->name);
				if(dev == allowed_if->dev){
					if(allowed_if->enabled){
						allowed = true;
					}
					break;
				}
			}
		}
	}
	return allowed;
}

int rpl_dag_set_allowed(struct rpl_dag *dag, struct net_device *dev,
		bool enabled, bool auto_gen, bool *should_trigger_dio) {
	int err = -EINVAL;
	bool updated = false;
	struct rpl_allowed_if *allowed_if = NULL;
	if(dag){
		list_for_each_entry(allowed_if,&dag->allowed_interfaces,allowed_if_list){
			if(!strcmp(dev->name,allowed_if->dev->name)){
				if(dev != allowed_if->dev){
					dev_put(allowed_if->dev);
					dev_hold(dev);
					allowed_if->dev = dev;
				}
				allowed_if->auto_gen = auto_gen;
				allowed_if->enabled = true;
				updated = true;
				err = 0;
				goto out;
			}
		}
		allowed_if = kzalloc(sizeof(struct rpl_allowed_if), GFP_KERNEL);
		if(!allowed_if)
		{
			RPL_PRINTK(0, err,"%s(): Error allocating memory to allowed interface\n",__func__);
			err = -ENOMEM;
			goto out;
		}
		allowed_if->node_addr_path_sequence = RPL_LOLLIPOP_INIT;
		allowed_if->enabled = enabled;
		if(enabled)
			updated = true;
		allowed_if->auto_gen = auto_gen;
		dev_hold(dev);
		allowed_if->dev = dev;
		INIT_LIST_HEAD(&allowed_if->allowed_if_list);
		list_add(&allowed_if->allowed_if_list,&dag->allowed_interfaces);
		err = 0;
	}
out:
	if(should_trigger_dio)
		*should_trigger_dio = updated;
	return err;
}

int rpl_dag_set_enabled(struct rpl_dag *dag, struct net_device *dev, bool enabled){
	int err = -EINVAL;
	struct rpl_allowed_if *allowed_if = NULL;
	struct list_head *allowed_if_ptr,*allowed_if_next;
	if(dag){
		list_for_each_safe(allowed_if_ptr,allowed_if_next,&dag->allowed_interfaces){
			allowed_if = list_entry(allowed_if_ptr,struct rpl_allowed_if,allowed_if_list);
			if(!strcmp(dev->name,allowed_if->dev->name)){
				if(dev != allowed_if->dev){
					dev_put(allowed_if->dev);
					dev_hold(dev);
					allowed_if->dev = dev;
				}
				allowed_if->enabled = enabled;
				//if(!allowed_if->enabled && allowed_if->auto_gen){
				if(!allowed_if->enabled){ //FIXME we should allow the configuration to be persistent
					list_del(&allowed_if->allowed_if_list);
					dev_put(allowed_if->dev);
					kfree(allowed_if);
				}
				err = 0;
				break;
			}
		}
		err = 0;
	}
	return err;
}

void rpl_dag_free(struct rpl_dag *dag)
{
	struct list_head *ptr,*next;
	struct rpl_node *parent;
	struct rpl_target *target;
	struct rpl_allowed_if *allowed_if;
	if(dag){
		printk(KERN_DEBUG "rpl: %s: freeing dag: %pI6\n",__func__,&dag->dodagid);

		// stop trickle timer
		trickle_stop(dag->dio_timer);

		// destroy dao_timer
		rpl_dag_cancel_dao_timer(dag);

		// destroy DAO TX workqueue
		flush_workqueue(dag->dao_tx_wq);
		destroy_workqueue(dag->dao_tx_wq);

		// release prefix
		if(dag->prefix_info)
			kfree(dag->prefix_info);

		// release parents
		mutex_lock(&dag->parents_lock);
		list_for_each_safe(ptr,next,&dag->neighbours)
		{
			parent = list_entry(ptr,struct rpl_node,node_list);
			list_del(&parent->node_list);
			rpl_node_free(parent);
		}
		list_for_each_safe(ptr,next,&dag->dodag_parents)
		{
			parent = list_entry(ptr,struct rpl_node,node_list);
			list_del(&parent->node_list);
			rpl_node_free(parent);
		}
		mutex_unlock(&dag->parents_lock);
		mutex_destroy(&dag->parents_lock);

		list_for_each_safe(ptr,next,&dag->targets_head)
		{
			target = list_entry(ptr,struct rpl_target,target_list);
			list_del(&target->target_list);
			rpl_target_free(target);
		}

		// free trickle timer
		trickle_free(dag->dio_timer);

		// cleaning up allowed interfaces list
		list_for_each_safe(ptr,next,&dag->allowed_interfaces)
		{
			allowed_if = list_entry(ptr,struct rpl_allowed_if,allowed_if_list);
			list_del(&allowed_if->allowed_if_list);
			dev_put(allowed_if->dev);
			kfree(allowed_if);
		}

		// decrementing instance refcount
		rpl_instance_put(dag->instance);

		// release kernel resources
		kfree(dag);
	}
	return;
}

int rpl_dags_list_init(struct netns_rpl *rplns)
{
	INIT_LIST_HEAD(&rplns->rpl_dags_list_head);
	mutex_init(&rplns->rpl_dags_list_mutex);
	return 0;
}

int _rpl_dags_list_del(struct rpl_dag *dag);

int rpl_dags_list_cleanup(struct netns_rpl *rplns){
	struct rpl_dag *dag;
	struct list_head *ptr,*next;
	mutex_lock(&rplns->rpl_dags_list_mutex);
	list_for_each_safe(ptr,next,&rplns->rpl_dags_list_head){
		dag = list_entry(ptr,struct rpl_dag,dag_list);

		// FIXME we should disjoin first if we are joined

		// Cancelling dao timer to decrement the refcnt and allow the free
		rpl_dag_cancel_dao_timer(dag);

		_rpl_dags_list_del(dag);
	}
	mutex_unlock(&rplns->rpl_dags_list_mutex);
	mutex_destroy(&rplns->rpl_dags_list_mutex);
	return 0;
}

int rpl_dags_list_dump(struct net *net){
	struct rpl_dag *dag;
	mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
	list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
		rpl_dag_dbg_dump(dag);
	}
	mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
	return 0;
}

int rpl_dags_list_add(struct net *net, struct rpl_dag *dag){
	int err = -EINVAL;
	if(dag)
	{
		mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
		rpl_dag_hold(dag);
		list_add(&dag->dag_list,&net->ipv6.rpl.rpl_dags_list_head);
		mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
		err = 0;
	}
	return err;
}

int _rpl_dags_list_del(struct rpl_dag *dag){
	int err = -EINVAL;
	if(dag)
	{
		list_del(&dag->dag_list);
		rpl_dag_put(dag);
		err = 0;
	}
	return err;
}

int rpl_dags_list_del(struct net *net, struct rpl_dag *dag){
	int err = -EINVAL;
	if(dag)
	{
		mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
		_rpl_dags_list_del(dag);
		mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
		err = 0;
	}
	return err;
}

struct rpl_dag *rpl_dag_find(struct net *net, __u8 instanceID, const struct in6_addr *dodagid)
{
	struct rpl_dag *dag = NULL;
	mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
	list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
		if(dag->instance->instanceID == instanceID && ipv6_addr_equal(dodagid,&dag->dodagid)){
			rpl_dag_hold(dag);
			mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
			return dag;
		}
	}
	mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
	return NULL;
}

rpl_rank_t rpl_dag_calculate_rank(struct rpl_dag *dag, struct rpl_node *parent, rpl_rank_t base)
{
	rpl_rank_t new_rank = RPL_INFINITE_RANK;
	int err = 0;
	if(dag && dag->instance && dag->instance->of)
	{
		new_rank = rpl_of_calculate_rank(dag->instance->of,parent,base,&err);
		if(err)
		{
			RPL_PRINTK(1, err,
					"%s(): Error getting rank: %d\n",
					__func__,err);
			goto out;
		}
	}
out:
	return new_rank;
}

int rpl_dag_compare_nodes(struct rpl_dag *dag, struct rpl_node *p1, struct rpl_node *p2)
{
	int err = 0;
	int res = 0;
	if(dag && dag->instance && dag->instance->of)
	{
		res = rpl_of_compare_nodes(dag->instance->of,p1,p2,&err);
		if(err)
		{
			RPL_PRINTK(1, err,
					"%s(): Error getting compare result: %d\n",
					__func__,err);
			goto out;
		}
	}
out:
	return res;
}

struct rpl_node *rpl_dag_get_node(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *addr)
{
	struct list_head *ptr;
	struct rpl_node *entry;
	if(dag && dev && addr)
	{
		mutex_lock(&dag->parents_lock);
		list_for_each(ptr, &dag->dodag_parents)
		{
			entry = list_entry(ptr,struct rpl_node,node_list);
			if (dev == entry->dev && ipv6_addr_equal(addr,&entry->addr)) {
				mutex_unlock(&dag->parents_lock);
				return entry;
			}
		}
		list_for_each(ptr, &dag->neighbours)
		{
			entry = list_entry(ptr,struct rpl_node,node_list);
			if (dev == entry->dev && ipv6_addr_equal(addr,&entry->addr)) {
				mutex_unlock(&dag->parents_lock);
				return entry;
			}
		}
		mutex_unlock(&dag->parents_lock);
	}
	if (!dag)
		RPL_PRINTK(1, err, "%s(): dag is NULL\n", __func__);
	if (!addr)
		RPL_PRINTK(1, err, "%s(): addr is NULL\n", __func__);
	return NULL;
}

/*
 * when adding new target, if existing target is found, old target is merged with
 * new one and new is the freed
 */
int rpl_dag_add_target(struct rpl_dag *dag, struct rpl_target *target, bool *updated) {
	int err = -EINVAL;
	struct rpl_target *old_target = NULL;
	bool routes_updated = false;
	if(!dag || !target)
	{
		if (!dag)
			RPL_PRINTK(1, err, "%s(): dag is NULL\n", __func__);
		if (!target)
			RPL_PRINTK(1, err, "%s(): target is NULL\n", __func__);
		goto out;
	}

	old_target = rpl_dag_get_target(dag,&target->prefix,target->prefix_len);
	if(old_target)
	{
		err = rpl_target_merge_transit_info(old_target,target,updated);
		if(err)
		{
			RPL_PRINTK(1, err, "%s(): Error merging targets transit infos: %d\n", __func__,err);
			goto out;
		}
		rpl_target_free(target);
		target = old_target;
	} else {
		list_add(&target->target_list,&dag->targets_head);
		if(updated)
			*updated |= true;
	}

	err = rpl_target_check_routes(target,&routes_updated);
	if(err)
	{
		RPL_PRINTK(1, err, "%s(): Error updating routes: %d\n", __func__,err);
	}
	if(updated)
		*updated |= routes_updated;
out:
	return err;
}

struct rpl_target *rpl_dag_get_target(struct rpl_dag *dag, const struct in6_addr *prefix, __u8 prefix_len)
{
	struct rpl_target *target = NULL;
	if(!dag || !prefix)
	{
		RPL_PRINTK(0, err,"%s(): Invalid arguments\n",__func__);
		goto out;
	}
	list_for_each_entry(target,&dag->targets_head,target_list){
		if(target->prefix_len == prefix_len && ipv6_prefix_equal(prefix,&target->prefix,prefix_len))
			return target;
	}
out:
	return NULL;
}

int rpl_dag_add_node(struct rpl_dag *dag, struct rpl_node *node)
{
	int err = -EINVAL;
	if(dag && node)
	{
		mutex_lock(&dag->parents_lock);
		list_add(&node->node_list,&dag->neighbours);
		node->dag = dag;
		mutex_unlock(&dag->parents_lock);
		err = 0;
	}
	return err;
}

int rpl_node_set_default_route(struct rpl_node *parent);
int rpl_node_unset_default_route(struct rpl_node *parent);

int rpl_dag_del_node(struct rpl_node *parent)
{
	int err = -EINVAL;
	struct rpl_dag *dag;
	if(parent)
	{
		dag = parent->dag;
		if(dag){
			mutex_lock(&dag->parents_lock);
//			if(parent->is_dao_parent || parent->is_dodag_parent){
			if(parent->is_preferred){
				err = rpl_node_unset_default_route(parent);
				if (err) {
					RPL_PRINTK(2, err,
							"%s(): error removing default route to parent: %d\n",
							__func__, err);
				}
			}
			list_del_init(&parent->node_list);
			parent->dag = NULL;
			mutex_unlock(&dag->parents_lock);
		}
		err = 0;
	}
	return err;
}

int rpl_dag_target_unreachable(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *addr)
{
	int err = -EINVAL;
	struct rpl_target *target = NULL;
	struct rpl_target_transit_info *transit_info = NULL;
	if(dag){
		// -------------------- prefix test -----------------
		// if no target match, lets check prefix

		if(ipv6_prefix_equal(addr,&dag->prefix_info->prefix,dag->prefix_info->prefix_len)){
			dag->unreachable_counter++;
			printk(KERN_DEBUG "%s(): address match prefix: %pI6/%d unreachable count: %d\n",__func__,&dag->prefix_info->prefix,dag->prefix_info->prefix_len,dag->unreachable_counter);
		}

		// -------------------- prefix test -----------------

		list_for_each_entry(target,&dag->targets_head,target_list){
			if(target){
				if(ipv6_prefix_equal(addr,&target->prefix,target->prefix_len)){
					transit_info = rpl_target_get_installed(target);
					if (transit_info){
						RPL_LOLLIPOP_INCREMENT(dag->DTSN);
						rpl_dag_inconsistent(dag);
						goto out;
					}
				}
			} else {
				printk(KERN_DEBUG "%s(): TARGET is NULL!!!\n",__func__);
			}
		}
out:
		err = 0;
	}
	return err;
}

int rpl_dag_purge_nodes(struct rpl_dag *dag){
	int err = -EINVAL;
	struct list_head *ptr,*next;
	struct rpl_node *neighbor = NULL;
	if(dag){
		list_for_each_safe(ptr,next,&dag->neighbours){
			neighbor = list_entry(ptr,struct rpl_node,node_list);
			err = rpl_dag_purge_targets_by_nexthop(dag,neighbor->dev,&neighbor->addr);
			if(err){
				RPL_PRINTK(2, err, "%s(): error setting nexthop no-path to neigh: %d\n",__func__,err);
				continue;
			}
			err = rpl_dag_del_node(neighbor);
			if(err){
				RPL_PRINTK(2, err, "%s(): error deleting node: %d\n",__func__,err);
				continue;
			}
			err = rpl_node_free(neighbor);
			if(err){
				RPL_PRINTK(2, err, "%s(): error freeing node: %d\n",__func__,err);
				continue;
			}
		}
		list_for_each_safe(ptr,next,&dag->dodag_parents){
			neighbor = list_entry(ptr,struct rpl_node,node_list);
			err = rpl_dag_purge_targets_by_nexthop(dag,neighbor->dev,&neighbor->addr);
			if(err){
				RPL_PRINTK(2, err, "%s(): error setting nexthop no-path to neigh: %d\n",__func__,err);
				continue;
			}
			err = rpl_dag_del_node(neighbor);
			if(err){
				RPL_PRINTK(2, err, "%s(): error deleting node: %d\n",__func__,err);
				continue;
			}
			err = rpl_node_free(neighbor);
			if(err){
				RPL_PRINTK(2, err, "%s(): error freeing node: %d\n",__func__,err);
				continue;
			}
		}
		if(!dag->is_root && list_empty(&dag->dodag_parents)){
			printk(KERN_ERR "%s(): dodag parents list is empty!!!\n",__func__);
			rpl_dag_set_rank(dag,RPL_INFINITE_RANK);
		}
		err = 0;
	}
	return err;
}

int rpl_dag_unlink_nodes_by_dev(struct rpl_dag *dag, struct net_device *dev){
	int err = -EINVAL;
	bool updated = false;
	struct rpl_node *neighbor = NULL;
	struct list_head *ptr,*next;
	if(dag){
		list_for_each_safe(ptr,next,&dag->neighbours){
			neighbor = list_entry(ptr,struct rpl_node,node_list);

			//printk(KERN_DEBUG "%s(): checking %X %s and %X %s\n",__func__,dev,dev->name,neighbor->dev,neighbor->dev->name);

			if(neighbor->dev != dev)
				continue;

			err = rpl_dag_purge_targets_by_nexthop(dag,neighbor->dev,&neighbor->addr);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error setting nexthop no-path to neigh: %d\n",__func__,err);
				continue;
			}

			err = rpl_dag_del_node(neighbor);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error deleting node: %d\n",__func__,err);
				continue;
			}

			err = rpl_node_free(neighbor);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error freeing node: %d\n",__func__,err);
				continue;
			}
		}

		list_for_each_safe(ptr,next,&dag->dodag_parents){
			neighbor = list_entry(ptr,struct rpl_node,node_list);

			//printk(KERN_DEBUG "%s(): checking %X %s and %X %s\n",__func__,dev,dev->name,neighbor->dev,neighbor->dev->name);

			if(neighbor->dev != dev)
				continue;

			err = rpl_dag_purge_targets_by_nexthop(dag,neighbor->dev,&neighbor->addr);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error setting nexthop no-path to neigh: %d\n",__func__,err);
				continue;
			}

			err = rpl_dag_del_node(neighbor);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error deleting node: %d\n",__func__,err);
				continue;
			}

			err = rpl_node_free(neighbor);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error freeing node: %d\n",__func__,err);
				continue;
			}
		}

		err = rpl_dag_update_upward_routes(dag,&updated);
		if(err)
		{
			RPL_PRINTK(2, err, "%s(): error updating upward routes: %d\n",__func__,err);
			goto out;
		}

		if(!dag->is_root && list_empty(&dag->dodag_parents))
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
out:
	return err;
}

int rpl_dag_unlink_node(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *addr){
	int err = -EINVAL;
	bool updated = false;
	struct rpl_node *neighbor;

	if(dag){
		neighbor = rpl_dag_get_node(dag,dev,addr);
		if(!neighbor)
		{
			RPL_PRINTK(2, err, "%s(): Neighbor not found\n",__func__);
			//goto out;
		}

		err = rpl_dag_purge_targets_by_nexthop(dag,dev,addr);
		if(err)
		{
			RPL_PRINTK(2, err, "%s(): error setting nexthop no-path to neigh: %d\n",__func__,err);
			goto out;
		}

		if(neighbor){
			err = rpl_dag_del_node(neighbor);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error deleting node: %d\n",__func__,err);
				goto out;
			}

			err = rpl_node_free(neighbor);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error freeing node: %d\n",__func__,err);
				goto out;
			}

			err = rpl_dag_update_upward_routes(dag,&updated);
			if(err)
			{
				RPL_PRINTK(2, err, "%s(): error updating upward routes: %d\n",__func__,err);
				goto out;
			}

			if(list_empty(&dag->dodag_parents))
			{
				printk(KERN_ERR "%s(): dodag parents list is empty!!!\n",__func__);
				rpl_dag_set_rank(dag,RPL_INFINITE_RANK);
				updated = true;
			}
		}
		if(updated)
		{
			rpl_dag_inconsistent(dag);
			rpl_dag_trigger_dao_timer(dag);
		}
		err = 0;
	}
out:
	return err;
}


struct rpl_node *rpl_node_alloc(const struct in6_addr *addr, struct net_device *dev, rpl_rank_t rank, __u8 dtsn, int *err);

void rpl_node_dbg_dump(struct rpl_node *node);
void rpl_target_dbg_dump(struct rpl_target *target);

void rpl_node_list_dbg_dump(struct list_head *head)
{
	struct rpl_node *parent;
	if(head){
		list_for_each_entry(parent,head,node_list)
		{
			rpl_node_dbg_dump(parent);
		}
	}
}

void rpl_target_list_dbg_dump(struct list_head *head)
{
	struct rpl_target *target;
	list_for_each_entry(target,head,target_list)
	{
		rpl_target_dbg_dump(target);
	}
}

void rpl_dag_dbg_dump(struct rpl_dag *dag)
{
	struct rpl_allowed_if *allowed_if;
	if(dag)
	{
		if(dag->instance)
			printk(KERN_DEBUG "%s(): instance: %d\n", __func__,dag->instance->instanceID);
		if(dag->instance->of)
			printk(KERN_DEBUG "%s(): OF: %d\n", __func__,dag->instance->of->ocp);
		printk(KERN_DEBUG "%s(): Version: %d\n", __func__,dag->version);
		printk(KERN_DEBUG "%s(): DodagID: %pI6\n",__func__,&dag->dodagid);
		printk(KERN_DEBUG "%s(): Rank: %d\n", __func__,dag->rank);
		printk(KERN_DEBUG "%s(): Grounded: %d\n", __func__,dag->grounded);
		printk(KERN_DEBUG "%s(): MOP: %d\n", __func__,dag->mop);
		printk(KERN_DEBUG "%s(): Prf: %d\n", __func__,dag->preference);
		printk(KERN_DEBUG "%s(): DTSN: %d\n", __func__,dag->DTSN);
		printk(KERN_DEBUG "%s(): Root: %d\n", __func__,dag->is_root);
		printk(KERN_DEBUG "%s(): AutoGen: %d\n", __func__,dag->auto_gen);
		printk(KERN_DEBUG "%s(): Auth: %d\n", __func__,dag->authenticated);
		printk(KERN_DEBUG "%s(): PCS: %d\n", __func__,dag->PCS);
		printk(KERN_DEBUG "%s(): DIOIntDoubl: %d\n", __func__,dag->DIOIntDoubl);
		printk(KERN_DEBUG "%s(): DIOIntMin: %d\n", __func__,dag->DIOIntMin);
		printk(KERN_DEBUG "%s(): DIORedun: %d\n", __func__,dag->DIORedun);
		printk(KERN_DEBUG "%s(): MaxRankIncrease: %u\n", __func__,dag->MaxRankIncrease);
		printk(KERN_DEBUG "%s(): MinHopRankIncrease: %u\n", __func__,dag->MinHopRankIncrease);
		printk(KERN_DEBUG "%s(): def_lifetime: %d\n", __func__,dag->def_lifetime);
		printk(KERN_DEBUG "%s(): lifetime_unit: %u\n", __func__,dag->lifetime_unit);

		printk(KERN_DEBUG "%s(): Allowed Interfaces _____________\n", __func__);
		list_for_each_entry(allowed_if,&dag->allowed_interfaces,allowed_if_list){
			printk(KERN_DEBUG "%s(): %%%s enabled: %d auto_gen: %d\n", __func__,allowed_if->dev->name,allowed_if->enabled,allowed_if->auto_gen);
		}

		printk(KERN_DEBUG "%s(): Neighbors _____________\n", __func__);
		rpl_node_list_dbg_dump(&dag->neighbours);
		printk(KERN_DEBUG "%s(): DODAG Parents _____________\n", __func__);
		rpl_node_list_dbg_dump(&dag->dodag_parents);
		printk(KERN_DEBUG "%s(): Targets _____________\n", __func__);
		rpl_target_list_dbg_dump(&dag->targets_head);
	} else {
		RPL_PRINTK(2, dbg, "%s(): null dag\n", __func__);
	}
}

int ipv6_get_global_addr(struct net_device *dev, struct in6_addr *addr,
		    unsigned char banned_flags)
{
	struct inet6_dev *idev;
	int err = -EADDRNOTAVAIL;

	rcu_read_lock();
	idev = __in6_dev_get(dev);
	if (idev) {
		struct inet6_ifaddr *ifp;

		read_lock_bh(&idev->lock);
		list_for_each_entry(ifp, &idev->addr_list, if_list) {
			if (ipv6_addr_src_scope(&ifp->addr) == IPV6_ADDR_SCOPE_GLOBAL &&
			    !(ifp->flags & banned_flags)) {
				*addr = ifp->addr;
				err = 0;
				break;
			}
		}
		read_unlock_bh(&idev->lock);
	}
	rcu_read_unlock();
	return err;
}

struct rpl_dag *rpl_dag_setup_using_conf(struct net *net, struct rpl_dag_conf *cfg, int *perr){
	int err = 0;
	struct rpl_dag *dag = NULL;
	struct rpl_instance *instance;

	if(cfg){
		dag = rpl_dag_find(net,cfg->instanceID,&cfg->dodagid);
		if(dag){
			/*
			 * Dag found. lets update configuration
			 */
			//TODO update dag parameters
		} else {
			/*
			 * Dag not found. lets create a new one
			 */
			instance = rpl_instances_find(net,cfg->instanceID);
			if(!instance){
				instance = rpl_instance_new(net,cfg->instanceID,cfg->ocp);
				if(!instance){
					RPL_PRINTK(1, err,"%s(): Error creating new instance\n",__func__);
					err = -EPERM;
					goto out;
				}
			}

			dag = rpl_dag_alloc(instance, &cfg->dodagid,&err);
			if(!dag) {
				RPL_PRINTK(1, err,
						"%s(): Error allocating dag: %d\n",__func__,err);
				rpl_instance_put(instance);
				goto out;
			}

			if(!cfg->use_defaults){
				dag->grounded = cfg->grounded;
				dag->mop = cfg->mop;
				dag->preference = cfg->preference;

				dag->DIOIntDoubl = cfg->DIOIntDoubl;
				dag->DIOIntMin = cfg->DIOIntMin;
				dag->DIORedun = cfg->DIORedun;
				dag->PCS = cfg->PCS;
				dag->MinHopRankIncrease = cfg->MinHopRankIncrease;

				if(dag->prefix_info)
					kfree(dag->prefix_info);
				dag->prefix_info = kmalloc(sizeof(struct prefix_info),GFP_ATOMIC);
				if(!dag->prefix_info){
					RPL_PRINTK(1, err,"%s(): Error creating prefix_info\n",__func__);
				} else {
					memcpy(dag->prefix_info, &cfg->prefix_info, sizeof(struct prefix_info));

//					//FIXME should we set address?
//					addrconf_prefix_rcv(skb->dev,(u8 *)prefix_option,
//							sizeof(struct prefix_info),0);
				}
			}

			if(cfg->root){
				dag->is_root = true;
				//dag->rank = RPL_ROOT_RANK;
				rpl_dag_set_rank(dag,RPL_ROOT_RANK);
			}

			dag->auto_gen = false;

			rpl_dags_list_add(net,dag);

			if(instance)
				rpl_instance_put(instance);
		}
		err = 0;
	}
out:
	if(perr)
		*perr = err;
	return dag;
}

/*
 * every router
 * - RPLInstanceID
 * - List of supported Objective Code Points (OCPs)
 * - List of supported metrics
 * - Prefix Information
 * - Solicited Information
 * - 'K' flag: when a node should set the 'K' flag in a DAO message
 * - MOP
 * - Route Information
 *
 * Non-DODAG-Root router
 * - A RPL implementation MUST allow configuring the Target prefix [DAO
   message, in RPL Target option].
 *
 * - Trigger a local repair.
 *
 * DODAG Root
 * - DIOIntervalDoublings
 * - DIOIntervalMin
 * - DIORedundancyConstant
 * - Path Control Size
 * - MinHopRankIncrease
 * - The DODAGPreference field
 * - DODAGID
 */

void rpl_dag_conf_default_init(struct rpl_dag_conf *cfg){
	if(cfg){
		memset(cfg, 0, sizeof(*cfg));
		/*
		 * General config
		 */
		cfg->use_defaults = true;
		cfg->root = false;
		cfg->grounded = true;

		/*
		 * DODAG Root router config
		 */
		cfg->DIOIntDoubl = RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS;
		cfg->DIOIntMin = RPL_DEFAULT_DIO_INTERVAL_MIN;
		cfg->DIORedun = RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT;
		cfg->PCS = RPL_DEFAULT_PATH_CONTROL_SIZE;
		cfg->MinHopRankIncrease = RPL_DEFAULT_MIN_HOP_RANK_INCREASE;
		cfg->preference = 0;
		memcpy(&cfg->dodagid,&in6addr_any,sizeof(struct in6_addr));

		/*
		 * Every router config
		 */
		cfg->ocp = RPL_OF_OF0;
		cfg->instanceID = RPL_DEFAULT_INSTANCE;
		cfg->mop = RPL_MOP_STORING_MODE_WITHOUT_MC;
	}
}


// FIXME we could use the *net from *dev
int rpl_dag_start_root(struct net *net, struct rpl_dag_conf *cfg, struct net_device *dev){
	struct rpl_instance *instance = NULL;
	struct rpl_dag *dag = NULL;
	int err = -EINVAL;
	int addr_scope = 0;
	bool add_new_dag = false;

	//FIXME make use of rpl_dag_conf

	rpl_ocp_t ocp = RPL_OF_OF0;
	__u8 instanceID = 0;
	bool grounded = true;
	__u8 mop = RPL_MOP_STORING_MODE_WITHOUT_MC;
	__u8 preference = 0;
	struct prefix_info 	*prefix_info;
	int prefix_len = 64;
	struct in6_addr dodagid;

	if(!dev)
	{
		RPL_PRINTK(0,err,"%s: NULL pointer, invalid argument: %d",__func__,err);
		goto out;
	}

	instance = rpl_instances_find(net,instanceID);
	if(instance == NULL)
	{
		instance = rpl_instance_new(net,instanceID, ocp);
		if(instance == NULL)
		{
			RPL_PRINTK(1,dbg,"%s(): Error create new instance\n",__func__);
			goto out;
		}
	}

	// --- get global address BEGIN

	ipv6_get_global_addr(dev,&dodagid,0);
	addr_scope = ipv6_addr_src_scope(&dodagid);

	if(addr_scope != IPV6_ADDR_SCOPE_GLOBAL)
	{
		printk(KERN_DEBUG "rpl: %s: Bad non global address: %pI6 scope: %X\n",__func__,&dodagid,addr_scope);
		goto out;
	}
	else{
		printk(KERN_DEBUG "rpl: %s: using global address: %pI6 scope: %X\n",__func__,&dodagid,addr_scope);
	}

	// -- get global address END

	dag = rpl_dag_find(net,instanceID,&dodagid);
	if(!dag){

		dag = rpl_dag_alloc(instance, &dodagid,&err);
		if(!dag){
			RPL_PRINTK(1, err,"%s(): Error allocating dag: %d\n",__func__,err);
			goto out;
		}

		prefix_info = kzalloc(sizeof(struct prefix_info),GFP_ATOMIC);
		if(!prefix_info){
			RPL_PRINTK(1, err, "%s(): Error creating prefix_info\n", __func__);
			rpl_dag_put(dag);
			dag = NULL;
			goto out;
		}

		ipv6_addr_prefix(&prefix_info->prefix,&dodagid,prefix_len);
		prefix_info->prefix_len = prefix_len;
		prefix_info->autoconf = true;
		prefix_info->valid = 0xffffffff;
		prefix_info->prefered = 0xffffffff;

		add_new_dag = true;

		dag->prefix_info = prefix_info;
	}

	dag->grounded = grounded;
	dag->mop = mop;
	dag->preference = preference;
	rpl_dag_set_rank(dag,RPL_ROOT_RANK);
	dag->is_root = true;

	rpl_dag_dio_timer_reset(dag);

	if(add_new_dag)
		rpl_dags_list_add(net,dag);

	rpl_dag_set_allowed(dag,dev,true,dag->auto_gen,NULL);

	rpl_dag_inconsistent(dag);

	err = 0;
out:
	if(dag)
		rpl_dag_put(dag);
	if(instance)
		rpl_instance_put(instance);
	return err;
}

// FIXME we could use the *net from *dev
struct rpl_dag *rpl_dag_new_from_dio(struct net *net, struct net_device *dev, struct sk_buff *skb){
	int err = 0;

	struct rpl_instance *instance;
	struct rpl_dag *dag = NULL;

	struct rpl_msg *msg;
	const struct in6_addr *saddr;

	struct prefix_info *prefix_option;

	u_rpl_option *prefix_info_option;
	u_rpl_option *dodag_conf_option;

	msg = (struct rpl_msg *)skb_transport_header(skb);
	if (msg->icmp6_code != ICMPV6_RPL_DIO) {
		RPL_PRINTK(1, dbg,
				"%s(): Invalid RPL Message. Unable to join\n",
				__func__);
		err = -EPERM;
		goto out;
	}
	saddr = &ipv6_hdr(skb)->saddr;

	// Get Prefix Information Option
	prefix_info_option = icmpv6_rpl_find_option(skb, ICMPV6_RPL_OPT_Prefix_Information);

	// Get DODAG Configuration Option
	dodag_conf_option = icmpv6_rpl_find_option(skb, ICMPV6_RPL_OPT_DODAG_Configuration);

	instance = rpl_instances_find(net,msg->base.dio.instanceID);
	if(!instance && dodag_conf_option){
		instance = rpl_instance_new(net,msg->base.dio.instanceID,be16_to_cpu(dodag_conf_option->dodag_configuration.OCP));
		if(!instance){
			RPL_PRINTK(1, err,"%s(): Error creating new instance\n",__func__);
			err = -EPERM;
			goto out;
		}
	}

	dag = rpl_dag_alloc(instance, &msg->base.dio.dodagid,&err);
	if(!dag)
	{
		RPL_PRINTK(1, err,
				"%s(): Error allocating dag. Unable to join: %d\n",
				__func__,err);
		rpl_instance_put(instance);
		goto out;
	}

	// Initiate DAG using DIO
	dag->version = msg->base.dio.version;
	dag->grounded = RPL_DIO_IS_GROUNDED(msg->base.dio.g_mop_prf);
	dag->mop = RPL_DIO_MOP(msg->base.dio.g_mop_prf);
	dag->preference = RPL_DIO_Prf(msg->base.dio.g_mop_prf);

	// Process Prefix Information Option
	if(prefix_info_option){
		prefix_option = (struct prefix_info *) prefix_info_option;
		addrconf_prefix_rcv(skb->dev,(u8 *)prefix_option,
				sizeof(struct prefix_info),0);

		//FIXME: check if we should change prefix!!!
		if(dag->prefix_info)
			kfree(dag->prefix_info);
		dag->prefix_info = kmalloc(sizeof(struct prefix_info),GFP_ATOMIC);
		if(!dag->prefix_info){
			RPL_PRINTK(1, err,"%s(): Error creating prefix_info\n",__func__);
		} else {
			memcpy(dag->prefix_info, prefix_option, sizeof(struct prefix_info));
		}
	}

	// Process DODAG Configuration Option
	if(dodag_conf_option){
		dag->authenticated =  RPL_DCO_A(dodag_conf_option->dodag_configuration.flags_A_PCS);
		dag->PCS = RPL_DCO_PCS(dodag_conf_option->dodag_configuration.flags_A_PCS);
		dag->DIOIntDoubl = dodag_conf_option->dodag_configuration.DIOIntDoubl;
		dag->DIOIntMin = dodag_conf_option->dodag_configuration.DIOIntMin;
		dag->DIORedun = dodag_conf_option->dodag_configuration.DIORedun;
		dag->MaxRankIncrease = be16_to_cpu(dodag_conf_option->dodag_configuration.MaxRankIncrease);
		dag->MinHopRankIncrease = be16_to_cpu(dodag_conf_option->dodag_configuration.MinHopRankIncrease);
		dag->def_lifetime = dodag_conf_option->dodag_configuration.def_lifetime;
		dag->lifetime_unit = be16_to_cpu(dodag_conf_option->dodag_configuration.lifetime_unit);
	}

	dag->auto_gen = true;

	rpl_dag_dio_timer_reset(dag);

	rpl_dags_list_add(net,dag);

	rpl_dag_set_allowed(dag,dev,true,dag->auto_gen,NULL);

	if(instance)
		rpl_instance_put(instance);
out:
	return dag;
}

int rpl_dag_poison(struct rpl_dag *dag, struct net_device *dev){
	int err = -EINVAL;
	if(dag)
	{
		printk("%s: POISON.... REMOVEME\n",__func__);
		err = rpl_send_dio(dag,dev,NULL,false,true);
		if(err){
			RPL_PRINTK(1, err,
					"%s(): Error sending DIO: %d\n",
					__func__,err);
			goto out;
		}
	}
out:
	return err;
}

int rpl_dag_disjoin(struct rpl_dag *dag, struct net_device *dev)
{
	int err = -EINVAL;
	bool enabled = false;
	struct rpl_allowed_if *allowed_if = NULL;
	/*
	 * 3.2.2
	 * DODAG disjoin
	 * When a node is part of a DODAG and for metric or
	 * administrative reasons wants to disassociate,
	 * it will perform a disjoin.
	 * This procedure consists in disabling the trickle timer (if it
	 * was active), communicating the disjoin from the DODAG to
	 * the neighbors by sending a poisoning DIO to each of them
	 * and deleting all the rows from the routing table and the
	 * neighbors set. The poisoning DIO will remove that node
	 * from the routing table and the neighbors set. The node will
	 * then try to join a new DODAG.
	 */
	if(dag)
	{
		err = rpl_dag_poison(dag,dev);
		if(err){
			RPL_PRINTK(1, err,"%s(): Error poisoning dag: %d\n",__func__,err);
		} else if(!dag->is_root){
			err = rpl_send_dao(dag,dev,true,true);
			if(err)
			{
				RPL_PRINTK(1,err,"RPL: Error sending DAO to all nodes: %d\n",err);
			}
			err = rpl_send_dao(dag,dev,false,true);
			if(err)
			{
				RPL_PRINTK(1,err,"RPL: Error sending DAO to DAO parents: %d\n",err);
			}
		}

		err = rpl_dag_unlink_nodes_by_dev(dag,dev);
		if(err){
			RPL_PRINTK(2, err,"%s(): Error unlinking all nodes: %d\n",__func__,err);
			goto out;
		}

		err = rpl_dag_purge_targets_by_dev(dag,dev);
		if(err) {
			RPL_PRINTK(2, err, "%s(): purging targets from device %s: %d\n",__func__,dev->name,err);
			goto out;
		}

		rpl_dag_set_enabled(dag,dev,false);

		list_for_each_entry(allowed_if,&dag->allowed_interfaces,allowed_if_list){
			if(allowed_if->enabled){
				enabled = true;
				break;
			}
		}

		if(!enabled){
			rpl_dag_set_rank(dag,RPL_INFINITE_RANK);
			rpl_dag_cancel_dao_timer(dag);
		}
	}
out:
	return err;
}

int rpl_dag_set_rank(struct rpl_dag *dag, rpl_rank_t rank){
	int err = -EINVAL;
	if(!dag)
		return err;

	dag->rank = rank;

	// TODO refactor the ledtrigger
	if(dag->rank == RPL_INFINITE_RANK){
		led_trigger_event(ledtrig_rpl_joined,LED_OFF);
	} else {
		led_trigger_event(ledtrig_rpl_joined,LED_FULL);
	}
	return 0;
}

int rpl_dag_inconsistent(struct rpl_dag *dag)
{
	int err = -EINVAL;
	if(dag)
	{
		err = trickle_hear_inconsistent(dag->dio_timer);
	}
	return err;
}

int rpl_dag_consistent(struct rpl_dag *dag)
{
	int err = -EINVAL;
	if(dag)
	{
		err = trickle_hear_consistent(dag->dio_timer);
	}
	return err;
}

int rpl_dag_cleanup_no_path(struct rpl_dag *dag){
	int err = -EINVAL;
	struct rpl_target *target;
	struct list_head *ptr_target,*next_target;
	struct rpl_target_transit_info *transit_info = NULL;
	struct list_head *ptr_transit,*next_transit;
	if(dag){
		list_for_each_safe(ptr_target,next_target,&dag->targets_head)
		{
			target = list_entry(ptr_target,struct rpl_target,target_list);
			list_for_each_safe(ptr_transit,next_transit,&target->transit_head)
			{
				transit_info = list_entry(ptr_transit,struct rpl_target_transit_info,transit_info_list);
				if(transit_info && transit_info->path_lifetime == 0x00 && !transit_info->installed)
				{
					list_del(&transit_info->transit_info_list);
					rpl_transit_info_free(transit_info);
				}
			}
			if(list_empty(&target->transit_head)){
				list_del(&target->target_list);
				rpl_target_free(target);
			}
		}
		err = 0;
	}
	return err;
}

int rpl_dag_trigger_dao_timer(struct rpl_dag *dag)
{
	int err = -EINVAL;
	if(dag && !dag->is_root){
		if(!timer_pending(&dag->dao_timer))
		{
			printk(KERN_DEBUG "%s(): dao trigger\n",__func__);
			rpl_dag_hold(dag);
			if (unlikely(mod_timer(&dag->dao_timer, jiffies + RPL_DEFAULT_DAO_DELAY*HZ))) {
				printk("RPL: BUG, DAO double timer add\n");
				dump_stack();
			}
		}
		err = 0;
	} else if(dag->is_root){
		err = rpl_dag_cleanup_no_path(dag);
	}
	return err;
}

int rpl_node_cmp(void *pdag, struct list_head *l1, struct list_head *l2);

int rpl_add_route_nexthop(struct net_device *dev, const struct in6_addr *prefix,
		__u8 prefix_len, const struct in6_addr *next_hop) {
	int err = -EINVAL;
	int pref = 0;
	struct fib6_config cfg;
	//FIXME check expires!!

	memset(&cfg, 0, sizeof(cfg));
	cfg.fc_table	= RT6_TABLE_DFLT;
	cfg.fc_metric	= IP6_RT_PRIO_USER;
	cfg.fc_ifindex	= dev->ifindex;
	cfg.fc_flags	= RTF_GATEWAY | RTF_PREF(pref);
	cfg.fc_nlinfo.portid = 0;
	cfg.fc_nlinfo.nlh = NULL;
	cfg.fc_nlinfo.nl_net = dev_net(dev);
	cfg.fc_dst = *prefix;
	cfg.fc_dst_len = prefix_len;
	cfg.fc_gateway = *next_hop;

//	RPL_PRINTK(1, err, "%s(): fc_ifindex: %d\n", __func__,cfg.fc_ifindex);
//	RPL_PRINTK(1, err, "%s(): fc_src: %pI6/%d\n", __func__,&cfg.fc_src,cfg.fc_src_len);
//	RPL_PRINTK(1, err, "%s(): fc_dst: %pI6/%d\n", __func__,&cfg.fc_dst,cfg.fc_dst_len);
//	RPL_PRINTK(1, err, "%s(): fc_gw: %pI6\n", __func__,&cfg.fc_gateway);
//	RPL_PRINTK(1, err, "%s(): fc_flags: %04X\n", __func__,cfg.fc_flags);

	err = ip6_route_add(&cfg);

	return err;
}

int rpl_dag_purge_targets_by_dev(struct rpl_dag *dag, struct net_device *dev){
	/*
	 * For all targets whose nexthop use idev, set no-path.
	 * Iterate dag targets and set_no_path for those transit that use device
	 * as nexthop. It might be necessary to reinstall a new transit/route to same
	 * targets with known alternatives
	 */

	int err = -EINVAL;
	struct rpl_target *target;
	struct rpl_target_transit_info *transit_info;
	bool updated = false;
	bool trigger_dao = false;
	if (!dag) {
		RPL_PRINTK(1, err, "%s(): dag is NULL\n", __func__);
		goto out;
	}
	list_for_each_entry(target,&dag->targets_head,target_list)
	{
		list_for_each_entry(transit_info,&target->transit_head,transit_info_list){
			if(dev == transit_info->dev){
				err = rpl_transit_info_update(target, transit_info,
						transit_info->DAOSequence, transit_info->path_sequence, 0,
						transit_info->path_control,&updated);
				if (err) {
					RPL_PRINTK(1, err, "%s(): Error updating transit: %d\n",
							__func__, err);
				}
				trigger_dao |= updated;
			}
		}
	}
	if(trigger_dao)
	{
		rpl_dag_trigger_dao_timer(dag);
	}
	err = 0;
out:
	return err;
}

int rpl_dag_purge_targets_by_nexthop(struct rpl_dag *dag, struct net_device *dev, const struct in6_addr *addr){
	/*
	 * For all targets whose nexthop is neighbor->addr, set no-path.
	 * Iterate dag targets and set_no_path for those transit that use neighbour
	 * as nexthop. It might be necessary to reinstall a new transit/route to same
	 * targets with known alternatives
	 */

	int err = -EINVAL;
	struct rpl_target *target;
	struct rpl_target_transit_info *transit_info;
	bool updated = false;
	bool trigger_dao = false;
	if (!dag) {
		RPL_PRINTK(1, err, "%s(): dag is NULL\n", __func__);
		goto out;
	}
	list_for_each_entry(target,&dag->targets_head,target_list)
	{
		transit_info = rpl_target_find_transit_info(target,dev,addr);
		if (transit_info) {
			err = rpl_transit_info_update(target, transit_info,
					transit_info->DAOSequence, transit_info->path_sequence, 0,
					transit_info->path_control,&updated);
			if (err) {
				RPL_PRINTK(1, err, "%s(): Error updating transit: %d\n",
						__func__, err);
			}
			trigger_dao |= updated;
		} else {
			RPL_PRINTK(1, dbg, "%s(): transit not found: %pI6%%%s\n",__func__,addr,dev->name);
		}
	}
	if(trigger_dao)
	{
		rpl_dag_trigger_dao_timer(dag);
	}
	err = 0;
out:
	return err;
}

int rpl_dag_update_upward_routes(struct rpl_dag *dag, bool *updated)
{
	int err = -EINVAL;
	rpl_rank_t candidate_rank;
	struct list_head *ptr,*next;
	bool parent_found = false;
	bool preferred_found = false;
	bool upward_routes_changed = false;
	struct rpl_node *parent;

	if(dag)
	{
		mutex_lock(&dag->parents_lock);

		// move all parents from dodag_parents to neighbours
		list_for_each_safe(ptr,next,&dag->dodag_parents)
		{
			parent = list_entry(ptr,struct rpl_node,node_list);
			list_del_init(&parent->node_list);
			list_add(&parent->node_list,&dag->neighbours);
		}

		// lets sort neighbours
		list_sort(dag,&dag->neighbours,rpl_node_cmp);

		// lets move best parents to dodag_parents and set default route
		list_for_each_safe(ptr,next,&dag->neighbours)
		{

			parent = list_entry(ptr,struct rpl_node,node_list);

			// check if is higher rank than best
			if(!parent_found){
				candidate_rank = rpl_dag_calculate_rank(dag,parent,0);

				//printk(KERN_DEBUG "%s(): Candidate RANK: %u parent_rank: %u dag_rank: %u\n",__func__,candidate_rank,parent->rank,dag->rank);
				if(DAGRank(candidate_rank,dag) > DAGRank(dag->rank,dag))
				{
					// We already found all best DODAG Parents
					parent_found = true;
				} else {
					// this is the lowest (best) rank found

					list_del_init(&parent->node_list);
					list_add(&parent->node_list,&dag->dodag_parents);

					if(!parent->is_dodag_parent){
						// setting flags DAO parent and DODAG Parent
						parent->is_dao_parent = true;
						parent->is_dodag_parent = true;
						parent->is_preferred = false;
						upward_routes_changed = true;
					}

					if(!preferred_found){
						// adding default route to this parent
						if(!parent->is_preferred){
							err = rpl_node_set_default_route(parent);
							if(err){
								RPL_PRINTK(2, err,
										"%s(): error setting default route to parent: %d\n",
										__func__,err);
							}
							parent->is_preferred = true;
						}
						preferred_found = true;
					}

					//dag->rank = rpl_dag_calculate_rank(dag,parent,0);
					rpl_dag_set_rank(dag,rpl_dag_calculate_rank(dag,parent,0));
				}
			}

			if(parent_found) {
				/*
				 *  we already found best DODAG parents.
				 *  lets check if we need to remove some default route
				 */
				if(parent->is_dodag_parent)
				{
					/*
					 * if parent were already found and we got a dodag parent,
					 * we need to remove the route and update neighbour
					 */
					parent->is_dao_parent = false;
					parent->is_dodag_parent = false;
					upward_routes_changed = true;
					if(parent->is_preferred){
						err = rpl_node_unset_default_route(parent);
						if(err){
							RPL_PRINTK(2, err,
									"%s(): error removing default route to parent: %d\n",
									__func__,err);
						}
						parent->is_preferred = false;
					}
				}
			}
		}
		mutex_unlock(&dag->parents_lock);
		err = 0;
		if(updated)
			*updated = upward_routes_changed;
		//printk(KERN_DEBUG "%s(): FINAL BEST RANK: %u dag_rank: %u\n",__func__,best,dag->rank);

	}
	return err;
}

/*
 * RPL Node Functions
 */

struct rpl_node *rpl_node_alloc(const struct in6_addr *addr, struct net_device *dev, rpl_rank_t rank, __u8 dtsn, int *err)
{
	struct rpl_node *node;
	node = kzalloc(sizeof(struct rpl_node), GFP_KERNEL);
	if(!node)
	{
		RPL_PRINTK(0, err,
				"%s(): Error allocating memory to node\n",
				__func__);
		*err = -ENOMEM;
		goto out;
	}
	INIT_LIST_HEAD(&node->node_list);
	node->rank = rank;
	node->dtsn = dtsn;
	node->dev = dev;
	node->is_dao_parent = false;
	node->is_dodag_parent = false;
	node->is_preferred = false;
	dev_hold(node->dev);
	memcpy(&node->addr,addr,16);
out:
	return node;
}

int rpl_node_free(struct rpl_node *node)
{
	int err = -EINVAL;
	if(node)
	{
		if(node->dev){
			dev_put(node->dev);
		}
		kfree(node);
		err = 0;
		goto out;
	}
out:
	return err;
}

int rpl_node_cmp(void *pdag, struct list_head *l1, struct list_head *l2)
{
	struct rpl_dag *dag = (struct rpl_dag *) pdag;
	struct rpl_node *p1,*p2;
	int res = 0;
	if(!dag)
		return res;
	p1 = list_entry(l1,struct rpl_node,node_list);
	p2 = list_entry(l2,struct rpl_node,node_list);
	res = rpl_dag_compare_nodes(dag,p1,p2);
	//printk(KERN_DEBUG "%s(): RES: %d p1: %pI6 rank: %u p2: %pI6 rank: %u\n",__func__,res,&p1->addr,p1->rank,&p2->addr,p2->rank);
	return res;
}

/*
 * RPL Target Functions
 */

struct rpl_target *rpl_target_alloc(const struct in6_addr *prefix, __u8 prefix_len, int *err) {
	struct rpl_target *target;
	target = kzalloc(sizeof(struct rpl_target), GFP_KERNEL);
	if(!target)
	{
		RPL_PRINTK(0, err,
				"%s(): Error allocating memory to target\n",
				__func__);
		if(err)
			*err = -ENOMEM;
		goto out;
	}
	INIT_LIST_HEAD(&target->target_list);
	INIT_LIST_HEAD(&target->transit_head);
	memcpy(&target->prefix,prefix,16);
	target->prefix_len = prefix_len;
out:
	return target;
}

void rpl_target_free(struct rpl_target *target)
{
	struct rpl_target_transit_info *transit_info;
	struct list_head *ptr,*next;
	if(target)
	{
		list_for_each_safe(ptr,next,&target->transit_head)
		{
			transit_info = list_entry(ptr,struct rpl_target_transit_info,transit_info_list);
			list_del(&transit_info->transit_info_list);
			rpl_transit_info_free(transit_info);
		}
		kfree(target);
	}
}

struct rpl_target_transit_info *rpl_target_get_installed(struct rpl_target *target)
{
	struct rpl_target_transit_info *transit_info = NULL;
	if(target){
		list_for_each_entry(transit_info,&target->transit_head,transit_info_list){
			if(transit_info->installed == true){
				return transit_info;
			}
		}
	}
	return NULL;
}

/*
 * when adding transit information to target, if there's already a transit info from
 * such node, it will only update info if path sequence is newer.
 * Upon existing transit_info found, the given transit info is freed and MUST not be accessed
 */
int rpl_target_add_transit_info(struct rpl_target *target, struct rpl_target_transit_info *transit_info, bool *updated)
{
	int err = -EINVAL;
	struct rpl_target_transit_info *old = NULL;
	bool transit_info_updated = false;
	if(target && transit_info){
		old = rpl_target_find_transit_info(target,transit_info->dev,&transit_info->next_hop);
		if(old){
			if (transit_info->path_lifetime == 0x00 || lollipop_greater_than(transit_info->path_sequence,old->path_sequence)) {
				err = rpl_transit_info_update(target, old,
						transit_info->DAOSequence, transit_info->path_sequence,
						transit_info->path_lifetime,
						transit_info->path_control,
						&transit_info_updated);
				if (err) {
					RPL_PRINTK(0, err,"%s(): error updating transit info: %d\n", __func__,err);
					goto out;
				}
			}
			rpl_transit_info_free(transit_info);
			if(updated)
				*updated = transit_info_updated;
		} else {
			list_add(&transit_info->transit_info_list,&target->transit_head);
			if(updated)
				*updated = true;
		}
		err = 0;
	}
out:
	return err;
}

struct rpl_target_transit_info *rpl_target_find_transit_info(struct rpl_target *target,
		struct net_device *dev, const struct in6_addr *next_hop) {
	struct rpl_target_transit_info *transit_info = NULL;
	if(!target || !dev || !next_hop)
	{
		RPL_PRINTK(0, err,"%s(): Invalid arguments\n",__func__);
		goto out;
	}
	list_for_each_entry(transit_info,&target->transit_head,transit_info_list){
		if(dev == transit_info->dev && ipv6_addr_equal(next_hop,&transit_info->next_hop))
			return transit_info;
	}
out:
	return NULL;
}

int rpl_target_merge_transit_info(struct rpl_target *old_target,struct rpl_target *new_target, bool *updated)
{
	int err = -EINVAL;
	bool transit_info_updated = false;
	struct rpl_target_transit_info *transit_info = NULL;
	struct list_head *ptr,*next;
	if(!old_target || !new_target)
	{
		RPL_PRINTK(0, err,"%s(): Invalid arguments\n",__func__);
		goto out;
	}
	list_for_each_safe(ptr,next,&new_target->transit_head)
	{
		transit_info = list_entry(ptr,struct rpl_target_transit_info,transit_info_list);
		list_del(&transit_info->transit_info_list);
		rpl_target_add_transit_info(old_target,transit_info,&transit_info_updated);
		*updated |= transit_info_updated;
		transit_info = NULL;
	}
	err = 0;
out:
	return err;
}

int rpl_transit_info_cmp(void *ptarget, struct list_head *l1, struct list_head *l2);
int rpl_del_route(struct net_device *dev, const struct in6_addr *target_addr,
		__u8 target_addr_len, const struct in6_addr *next_hop);

int rpl_target_check_routes(struct rpl_target *target, bool *routes_updated)
{
	struct rpl_target_transit_info *transit_info = NULL;
	bool first = true;
	bool updated = false;
	int err = 0;
	/*
	 * this function must check all available transit info for target and select the best
	 * next_hop. if changes are applied, the old route must be removed and new must be installed.
	 * on changes,
	 * http://tools.ietf.org/html/rfc6550#section-9.6
	 */
	if(!target)
	{
		RPL_PRINTK(0, err,"%s(): Invalid arguments\n",__func__);
		err = -EINVAL;
		goto out;
	}

	// sort all transit_infos. Best route will be in first element
	list_sort(target,&target->transit_head,rpl_transit_info_cmp);

	list_for_each_entry(transit_info,&target->transit_head,transit_info_list){
		if(first){
			if(!transit_info->installed)
			{
				err = rpl_add_route_nexthop(transit_info->dev, &target->prefix,
						target->prefix_len, &transit_info->next_hop);
				if(err){
					RPL_PRINTK(0, err,"%s(): error adding route: %d\n",__func__,err);
					if(err == -EEXIST){
						transit_info->installed = true;
					}
				} else {
					transit_info->installed = true;
					updated = true;
				}
			}
			first = false;
		} else {
			if(transit_info->installed)
			{
				err = rpl_del_route(transit_info->dev, &target->prefix,
						target->prefix_len, &transit_info->next_hop);
				if(err){
					RPL_PRINTK(0, err,"%s(): error adding route: %d\n",__func__,err);
				}
				transit_info->installed = false;
				updated = true;
			}
		}
	}
	if(routes_updated)
		*routes_updated = updated;
	err = 0;
out:
	return err;
}

int rpl_target_set_no_path(struct net *net, __u8 instanceID, const struct in6_addr *dodagid,
		struct net_device *dev, const struct in6_addr *target_prefix,
		__u8 target_prefix_len, const struct in6_addr *next_hop) {
	int err = -EINVAL;
	struct rpl_target *target;
	struct rpl_target_transit_info *transit_info;
	struct rpl_dag *dag;
	bool transit_info_updated = false;

	if(dodagid){
		/*
		 * Set no_path to target found in specified dodagid
		 */
		dag = rpl_dag_find(net,instanceID,dodagid);
		if(dag){
			target = rpl_dag_get_target(dag,target_prefix,target_prefix_len);
			if(target){
				transit_info = rpl_target_find_transit_info(target,dev,next_hop);
				err = rpl_transit_info_update(target,transit_info,
						transit_info->DAOSequence, transit_info->path_sequence,
						0, transit_info->path_control,&transit_info_updated);
				if(err)
				{
					RPL_PRINTK(0, err,"%s(): Error updating transit: %d\n",__func__,err);
					rpl_dag_put(dag);
					dag = NULL;
					goto out;
				}
				if(transit_info_updated)
				{
					rpl_dag_trigger_dao_timer(dag);
				}
			}
			rpl_dag_put(dag);
		}
	} else
	{
		/*
		 * Set no_path to target found for all dodags to given instanceID
		 */
		mutex_lock(&net->ipv6.rpl.rpl_dags_list_mutex);
		list_for_each_entry(dag,&net->ipv6.rpl.rpl_dags_list_head,dag_list){
			if(dag == NULL){
				BUG();
				printk(KERN_DEBUG "%s(): DAG is NULL!!!\n",__func__);
			}
			if(instanceID == dag->instance->instanceID && rpl_dag_is_allowed(dag,dev)){
				target = rpl_dag_get_target(dag,target_prefix,target_prefix_len);
				if(target)
				{
					transit_info = rpl_target_find_transit_info(target,dev,next_hop);
					if(transit_info){
						err = rpl_transit_info_update(target,transit_info,
								transit_info->DAOSequence, transit_info->path_sequence,
								0, transit_info->path_control,&transit_info_updated);
						if(err)
						{
							RPL_PRINTK(0, err,"%s(): Error updating transit: %d\n",__func__,err);
						}
						if(transit_info_updated)
						{
							rpl_dag_trigger_dao_timer(dag);
						}
					}
				}
			}
		}
		mutex_unlock(&net->ipv6.rpl.rpl_dags_list_mutex);
	}
out:
	return err;
}

struct rpl_target_transit_info *rpl_transit_info_alloc(const struct in6_addr *next_hop, struct net_device *dev, bool is_one_hop, int *err)
{
	struct rpl_target_transit_info *transit_info;
	transit_info = kzalloc(sizeof(struct rpl_target_transit_info), GFP_KERNEL);
	if(!transit_info)
	{
		RPL_PRINTK(0, err,
				"%s(): Error allocating memory to transit info\n",
				__func__);
		if(err)
			*err = -ENOMEM;
		goto out;
	}
	INIT_LIST_HEAD(&transit_info->transit_info_list);
	memcpy(&transit_info->next_hop,next_hop,16);
	dev_hold(dev);
	transit_info->dev = dev;
	transit_info->installed = false;
	transit_info->one_hop = is_one_hop;
out:
	return transit_info;
}

void rpl_transit_info_free(struct rpl_target_transit_info *transit_info)
{
	if(transit_info){
		if(transit_info->dev){
			dev_put(transit_info->dev);
		}
		kfree(transit_info);
	}
}

int rpl_transit_info_update(struct rpl_target *target, struct rpl_target_transit_info *transit_info,
		__u8 DAOSequence, __u8 path_sequence, __u8 path_lifetime,
		__u8 path_control, bool *updated)
{
	int err = -EINVAL;
	bool update_required = false;
	if(!target || !transit_info)
	{
		RPL_PRINTK(0, err, "RPL: %s: transit is NULL\n", __func__);
		goto out;
	}
	if(transit_info->DAOSequence != DAOSequence){
		transit_info->DAOSequence = DAOSequence;
		update_required = true;
	}
	if(transit_info->path_sequence != path_sequence){
		transit_info->path_sequence = path_sequence;
		update_required = true;
	}
	if(transit_info->path_lifetime != path_lifetime){
		transit_info->path_lifetime = path_lifetime;
		update_required = true;
	}
	if(transit_info->path_control != path_control){
		transit_info->path_control = path_control;
		update_required = true;
	}
	if((update_required || transit_info->path_lifetime == 0) && transit_info->installed){
		rpl_del_route(transit_info->dev, &target->prefix,
				target->prefix_len, &transit_info->next_hop);
	}
	transit_info->installed = false;
	if(updated)
		*updated = update_required;
	err = 0;
out:
	return err;
}

/*
 * This function compares two transit info to a given target.
 * This function is to be used with list_sort.
 * It compares two transit info with goal of sorting a list of transit infos from
 * best transit info, to worst.
 *
 * It first compares path_sequences, choosing higher value.
 * For same path_sequences, it chooses higher path_lifetime.
 * If same path_lifetime, it chooses one_hop transit_info.
 */
int rpl_transit_info_cmp(void *ptarget, struct list_head *l1, struct list_head *l2)
{
	struct rpl_target *target = (struct rpl_target *) ptarget;
	struct rpl_target_transit_info *t1,*t2;
	int res = 0;
	if(!target)
		return res;
	t1 = list_entry(l1,struct rpl_target_transit_info,transit_info_list);
	t2 = list_entry(l2,struct rpl_target_transit_info,transit_info_list);

	if(lollipop_greater_than(t1->path_sequence,t2->path_sequence)){
		/*
		 * most recent
		 */
		res = 1;
	} else if(t1->path_sequence == t2->path_sequence){
		if(t1->path_lifetime > t2->path_lifetime){
			res = -1;
		} else if(t1->path_lifetime < t2->path_lifetime){
			res = 1;
		} else {
			if(t1->one_hop && !t2->one_hop){
				res = -1;
			} else if(!t1->one_hop && t2->one_hop){
				res = 1;
			} else {
				res = 0;
			}
		}
	} else {
		res = -1;
	}
	return res;
}

int rpl_node_unset_default_route(struct rpl_node *parent)
{
	struct rt6_info *rt = NULL;
	struct neighbour *neigh = NULL;
	int err = -EINVAL;

	if(parent)
	{
		rt = rt6_get_dflt_router(&parent->addr, parent->dev);
		if (rt) {
			neigh = dst_neigh_lookup(&rt->dst, &parent->addr);
			if (!neigh) {
				RPL_PRINTK(0, err,
					  "RPL: %s got default router without neighbour\n",
					  __func__);
				ip6_rt_put(rt);
				err = -ENXIO;
				goto out;
			}
		}
		if (rt) {
			err = ip6_del_rt(rt);
			if(err){
				RPL_PRINTK(0, err,
					  "RPL: %s some error occur removing default route\n",
					  __func__);
			}
			rt = NULL;
		}
		err = 0;
		if(neigh)
			neigh_release(neigh);
	}
out:
	return err;
}

int rpl_node_set_default_route(struct rpl_node *parent)
{
	int err = -EINVAL;
	struct rt6_info *rt = NULL;
	struct neighbour *neigh = NULL;
	int lifetime;
	int pref = 0;

	if(parent)
	{
		rt = rt6_get_dflt_router(&parent->addr, parent->dev);
		if (rt) {
			neigh = dst_neigh_lookup(&rt->dst, &parent->addr);
			if (!neigh) {
				RPL_PRINTK(0, err,
					  "RPL: %s got default router without neighbour\n",
					  __func__);
				ip6_rt_put(rt);
				rt = NULL;
				err = -ENXIO;
				goto out;
			}
		}
		if (rt) {
			err = ip6_del_rt(rt);
			if(err){
				RPL_PRINTK(0, err,
					  "RPL: %s some error occur removing default route\n",
					  __func__);
			}
			rt = NULL;
		}
		lifetime = parent->dag->lifetime_unit*parent->dag->def_lifetime;
		lifetime &= 0xFFFF; //FIXME kernel 3.8.13 complain about lifetime too big >4bytes (int?)
		if (rt == NULL && lifetime) {
			RPL_PRINTK(3, dbg, "RPL: adding default router\n");

			rt = rt6_add_dflt_router(&parent->addr, parent->dev, pref);
			if (rt == NULL) {
				RPL_PRINTK(0, err,
					  "RPL: %s failed to add default route\n",
					  __func__);
				err = -ENXIO;
				goto out;
			}

			neigh = dst_neigh_lookup(&rt->dst, &parent->addr);
			if (neigh == NULL) {
				RPL_PRINTK(0, err,
					  "RPL: %s got default router without neighbour\n",
					  __func__);
				ip6_rt_put(rt);
				rt = NULL;
				err = -ENXIO;
				goto out;
			}
			neigh->flags |= NTF_ROUTER;
		} else if (rt) {
			rt->rt6i_flags = (rt->rt6i_flags & ~RTF_PREF_MASK) | RTF_PREF(pref);
		}

		if (rt)
			rt6_set_expires(rt, jiffies + (HZ * lifetime));

		err = 0;
	}
out:
	if(rt)
		ip6_rt_put(rt);
	if (neigh)
		neigh_release(neigh);
	return err;
}


static int __ip6_del_rt(struct rt6_info *rt, struct nl_info *info)
{
	int err;
	struct fib6_table *table;
	struct net *net = dev_net(rt->dst.dev);

	if (rt == net->ipv6.ip6_null_entry) {
		err = -ENOENT;
		goto out;
	}

	table = rt->rt6i_table;
	write_lock_bh(&table->tb6_lock);
	err = fib6_del(rt, info);
	write_unlock_bh(&table->tb6_lock);

out:
	ip6_rt_put(rt);
	return err;
}

static int ip6_route_del(struct fib6_config *cfg)
{
	struct fib6_table *table;
	struct fib6_node *fn;
	struct rt6_info *rt;
	int err = -ESRCH;

	table = fib6_get_table(cfg->fc_nlinfo.nl_net, cfg->fc_table);
	if (!table)
		return err;

	read_lock_bh(&table->tb6_lock);

	fn = fib6_locate(&table->tb6_root,
			 &cfg->fc_dst, cfg->fc_dst_len,
			 &cfg->fc_src, cfg->fc_src_len);

	if (fn) {
		for (rt = fn->leaf; rt; rt = rt->dst.rt6_next) {
			if (cfg->fc_ifindex &&
			    (!rt->dst.dev ||
			     rt->dst.dev->ifindex != cfg->fc_ifindex))
				continue;
			if ((cfg->fc_flags & RTF_GATEWAY) &&
			    !ipv6_addr_equal(&cfg->fc_gateway, &rt->rt6i_gateway))
				continue;
			if (cfg->fc_metric && cfg->fc_metric != rt->rt6i_metric)
				continue;
			dst_hold(&rt->dst);
			read_unlock_bh(&table->tb6_lock);

			return __ip6_del_rt(rt, &cfg->fc_nlinfo);
		}
	}
	read_unlock_bh(&table->tb6_lock);

	return err;
}

int rpl_del_route(struct net_device *dev, const struct in6_addr *target_addr,
		__u8 target_addr_len, const struct in6_addr *next_hop) {
	int err = -EINVAL;
	int pref = 0;
	struct fib6_config cfg;

	if(!dev || !target_addr || !next_hop) {
		RPL_PRINTK(0, err,
				"%s(): Null pointers.\n",
				__func__);
		goto out;
	}

//	RPL_PRINTK(1, err, "%s(): target: %pI6/%d\n", __func__,target_addr,target_addr_len);
//	RPL_PRINTK(1, err, "%s(): next_hop: %pI6\n", __func__,next_hop);

	memset(&cfg, 0, sizeof(cfg));
	cfg.fc_table	= RT6_TABLE_DFLT;
	cfg.fc_metric	= IP6_RT_PRIO_USER;
	cfg.fc_ifindex	= dev->ifindex;
	cfg.fc_flags	= RTF_GATEWAY | RTF_PREF(pref);
	cfg.fc_nlinfo.portid = 0;
	cfg.fc_nlinfo.nlh = NULL;
	cfg.fc_nlinfo.nl_net = dev_net(dev);
	cfg.fc_dst = *target_addr;
	cfg.fc_dst_len = target_addr_len;
	cfg.fc_gateway = *next_hop;

	err = ip6_route_del(&cfg);

	err = 0;
out:
	return err;
}

void rpl_transit_info_dbg_dump(struct rpl_target_transit_info *transit_info)
{
	if(transit_info)
	{
		printk(KERN_DEBUG "%s(): NextHop: %pI6%%%s\n",__func__,&transit_info->next_hop,transit_info->dev->name);
		printk(KERN_DEBUG "%s(): DAOSequence: %u\n", __func__,transit_info->DAOSequence);
		printk(KERN_DEBUG "%s(): Path Sequence: %u\n", __func__,transit_info->path_sequence);
		printk(KERN_DEBUG "%s(): Path Lifetime: %u\n", __func__,transit_info->path_lifetime);
		printk(KERN_DEBUG "%s(): Path Control: %u\n", __func__,transit_info->path_control);
		printk(KERN_DEBUG "%s(): OneHop: %s\n", __func__,(transit_info->one_hop)?"Yes":"No");
		printk(KERN_DEBUG "%s(): Installed: %s\n", __func__,(transit_info->installed)?"Yes":"No");
	}
}

void rpl_target_dbg_dump(struct rpl_target *target)
{
	struct rpl_target_transit_info *transit_info;
	if(target)
	{
		printk(KERN_DEBUG "%s(): Prefix: %pI6/%u\n",__func__,&target->prefix,target->prefix_len);
		list_for_each_entry(transit_info,&target->transit_head,transit_info_list)
		{
			rpl_transit_info_dbg_dump(transit_info);
		}
	}
}

void rpl_node_dbg_dump(struct rpl_node *node)
{
	if(node)
	{
		printk(KERN_DEBUG "%s(): Addr: %pI6%%%s\n",__func__,&node->addr,node->dev->name);
		if(node->dag)
		{
			printk(KERN_DEBUG "%s(): DodagID: %pI6\n",__func__,&node->dag->dodagid);
		}
		printk(KERN_DEBUG "%s(): IsDAOParent: %u\n", __func__,node->is_dao_parent);
		printk(KERN_DEBUG "%s(): IsDODAGParent: %u\n", __func__,node->is_dodag_parent);
		printk(KERN_DEBUG "%s(): IsPreferred: %u\n", __func__,node->is_preferred);

		printk(KERN_DEBUG "%s(): Rank: %u\n", __func__,node->rank);
		printk(KERN_DEBUG "%s(): DTSN: %u\n", __func__,node->dtsn);
		printk(KERN_DEBUG "%s(): LinkMetric: %u\n", __func__,node->metric_link);
	} else {
		RPL_PRINTK(2, dbg, "%s(): null parent\n", __func__);
	}
}
