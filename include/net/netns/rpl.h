/**
 * @file rpl.h
 *
 * @date Nov 30, 2013
 * @author Joao Pedro Taveira <joao.silva@inov.pt>
 */

#ifndef __NETNS_RPL_H_
#define __NETNS_RPL_H_

struct netns_rpl {
	/*
	 * List of enabled devices (struct rpl_enabled_device)
	 */
	struct list_head 	rpl_enabled_devices_list_head;
	struct mutex 		rpl_enabled_devices_list_mutex;

	/*
	 * RPL Input processing queue
	 */
	struct workqueue_struct		*rpl_rx_wq;

	/*
	 * List of RPL instances (struct rpl_instance)
	 */
	struct mutex 		rpl_instances_list_mutex;
	struct list_head 	rpl_instances_list_head;

	/*
	 * List of RPL dags (struct rpl_dag)
	 */
	struct mutex 		rpl_dags_list_mutex;
	struct list_head 	rpl_dags_list_head;

	struct sock			*rpl_sk;
};

#endif /* __NETNS_RPL_H_ */
