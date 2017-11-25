/*
 *	Trickle Timer: The Trickle Algorithm (RFC6206)
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
 * @file rpl_trickle.c
 *
 * @date Jul 30, 2013
 * @author Joao Pedro Taveira
 */

#define pr_fmt(fmt) "ICMPv6: " fmt

#include <linux/kthread.h>	// for threads
#include <linux/time.h>		// for using jiffies
#include <linux/random.h>	// for randomize_range
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <net/rpl/rpl_trickle.h>

#define RPL_DEBUG 1

#define RPL_PRINTK(val, level, fmt, ...)				\
do {								\
	if (val <= RPL_DEBUG)					\
		net_##level##_ratelimited(fmt, ##__VA_ARGS__);	\
} while (0)

/*
 * Since using randomize_range (which's !exported) from <linux/random.h> I got following error:
 * ERROR: "randomize_range" [net/ipv6/ipv6.ko] undefined!
 * here's the same function...
 */
static unsigned long
rpl_randomize_range(unsigned long start, unsigned long end, unsigned long len)
{
	unsigned long range = end - len - start;

	if (end <= start + len)
		return 0;
	return get_random_int() % range + start;
}

struct trickle_timer *trickle_new(
		unsigned long Imin,
		unsigned long Imax,
		int k,
		void (*trickle_fn)(unsigned long arg),
		unsigned long trickle_fn_arg)
{
	struct trickle_timer *trickle = NULL;
	trickle = kmalloc(sizeof(struct trickle_timer),GFP_KERNEL);
	if(!trickle)
	{
		RPL_PRINTK(0, err, "rpl_trickle: %s: error allocating memory to timer\n", __func__);
		return NULL;
	}
	trickle->task = NULL;
	trickle->Imin = Imin;
	trickle->Imax = Imin * (1 << Imax);
	trickle->k = k;

	trickle->trickle_fn = trickle_fn;
	trickle->trickle_fn_arg = trickle_fn_arg;

	// step 1
	trickle->I = rpl_randomize_range(trickle->Imin, trickle->Imax, 1);

	// step 2
	trickle->c = 0;
	trickle->t = rpl_randomize_range(trickle->I / 2, trickle->I, 1);

	mutex_init(&trickle->lock);

	//RPL_PRINTK(2, info, "rpl_trickle: %s: next trickle timer is set to run in %lu (ms) Imin: %lu Imax: %lu\n",__func__,trickle->t,trickle->Imin,trickle->Imax);
	return trickle;
}

static int _trickle_stop(struct trickle_timer *trickle);
void trickle_free(struct trickle_timer *trickle)
{
	if(trickle)
	{
		mutex_lock(&trickle->lock);
		if(trickle->task)
			_trickle_stop(trickle);
		mutex_unlock(&trickle->lock);
		kfree(trickle);
	}
}

static int trickle_threadfn(void *data) {
	struct trickle_timer *trickle = (struct trickle_timer *) data;
	int local_k = 0;
	int local_c = 0;
	unsigned long local_t = 0, j0 = 0, delay = 0, delay_remain = 0;
	bool should_stop = false;

	RPL_PRINTK(2, info, "rpl_trickle: %s: starting..HZ: %d\n",__func__,HZ);
	set_current_state(TASK_INTERRUPTIBLE);
	should_stop = kthread_should_stop();
	while (!should_stop) {
		j0 = jiffies;
		mutex_lock(&trickle->lock);
		delay = trickle->t * HZ / 1000;
		local_t = j0 + delay;
		mutex_unlock(&trickle->lock);

		RPL_PRINTK(2, info, "rpl_trickle: %s: waiting for %lu (ms) or %lu (jiffies)\n",__func__,trickle->t,delay);

		delay_remain = delay;
		while(delay_remain>0){
			set_current_state(TASK_INTERRUPTIBLE);
			delay_remain = schedule_timeout(delay);
			delay = delay_remain;

			if((should_stop = kthread_should_stop()))
				break;
			else if(delay_remain>0)
				RPL_PRINTK(2, info, "rpl_trickle: %s: Interrupted: waiting for %lu (ms) Remain: %lu (jiffies)\n",__func__,trickle->t,delay);
		}

		if(should_stop)
			break;

		RPL_PRINTK(2, info, "rpl_trickle: %s: trickle timer waited for %lu (ms)\n",__func__,trickle->t);

		// Step #4
		mutex_lock(&trickle->lock);
		local_k = trickle->k;
		local_c = trickle->c;
		mutex_unlock(&trickle->lock);
		if(local_k == 0 || local_c < local_k)
		{
			//RPL_PRINTK(2, info, "rpl_trickle: %s: calling trickle_fn\n",__func__);
			trickle->trickle_fn(trickle->trickle_fn_arg);
		}

		mutex_lock(&trickle->lock);
		// step #5
		trickle->I = trickle->I * 3;
		if(trickle->I > trickle->Imax)
		{
			RPL_PRINTK(2, info, "rpl_trickle: %s: trickle timer has reached maximum interval size\n",__func__);
			trickle->I = trickle->Imax;
		}
		local_c = trickle->c = 0;
		trickle->t = rpl_randomize_range(trickle->I / 2, trickle->I, 1);
		RPL_PRINTK(2, info, "rpl_trickle: %s: next trickle timer is set to run in %lu (ms)\n",__func__,trickle->t);
		mutex_unlock(&trickle->lock);
		should_stop = kthread_should_stop();
	}
	return 0;
}

static int _trickle_start(struct trickle_timer *trickle)
{
	struct task_struct *__k = NULL;
	int ret = -EINVAL;
	if(trickle){
		RPL_PRINTK(2, info, "rpl_trickle: %s: starting thread\n",__func__);
		__k = kthread_run(trickle_threadfn, trickle, "trickle-timer");
		if (IS_ERR(__k))
		{
			ret = PTR_ERR(__k);
		} else {
			trickle->task = __k;
			ret = 0;
		}
	}
	return ret;
}

int trickle_start(struct trickle_timer *trickle)
{
	int ret = -EINVAL;
	if(trickle){
		mutex_lock(&trickle->lock);
		ret = _trickle_start(trickle);
		mutex_unlock(&trickle->lock);
		ret = 0;
	}
	return ret;
}

static int _trickle_stop(struct trickle_timer *trickle)
{
	int ret = -EINVAL;
	if(trickle){
		ret = kthread_stop(trickle->task);
		trickle->task = NULL;
	}
	return ret;
}

int trickle_stop(struct trickle_timer *trickle)
{
	int ret = -EINVAL;
	if(trickle){
		mutex_lock(&trickle->lock);
		ret = _trickle_stop(trickle);
		mutex_unlock(&trickle->lock);
		ret = 0;
	}
	return ret;
}

int trickle_hear_consistent(struct trickle_timer *trickle)
{
	int ret = -EINVAL;
	if(trickle){
		mutex_lock(&trickle->lock);
		RPL_PRINTK(2, info, "rpl_trickle: %s: Hearing a consistent message\n", __func__);
		// step 3
		trickle->c += 1;
		mutex_unlock(&trickle->lock);
		ret = 0;
	}
	return ret;
}

int trickle_hear_inconsistent(struct trickle_timer *trickle)
{
	int ret = -EINVAL;
	if(trickle){
		mutex_lock(&trickle->lock);
		// step #6
		RPL_PRINTK(2, info, "rpl_trickle: %s: Hearing a inconsistent message, resetting timer\n", __func__);
		if(trickle->I != trickle->Imin)
		{
			mutex_unlock(&trickle->lock);
			if ((ret = _trickle_stop(trickle)) != 0) {
				RPL_PRINTK(0, err, "rpl_trickle: %s error stopping thread: %d\n",__func__,ret);
			} else {
				mutex_lock(&trickle->lock);
				trickle->I = trickle->Imin;
				trickle->c = 0;
				trickle->t = rpl_randomize_range(trickle->I / 2, trickle->I, 1);
				mutex_unlock(&trickle->lock);
	//			if((ret = _trickle_stop(trickle)) != 0)
	//			{
	//				RPL_PRINTK(0, err, "rpl_trickle: %s error stopping thread\n", __func__);
	//			} else
				if((ret = _trickle_start(trickle)) != 0){
					RPL_PRINTK(0, err, "rpl_trickle: %s error starting thread: %d\n", __func__,ret);
				}
			}
		} else {
			mutex_unlock(&trickle->lock);
		}
	}
	return ret;
}
