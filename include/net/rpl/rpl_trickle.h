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
 * @file rpl_trickle.h
 *
 * @date Jul 30, 2013
 * @author Joao Pedro Taveira
 */

#ifndef RPL_TRICKLE_H_
#define RPL_TRICKLE_H_

#ifdef CONFIG_IPV6_RPL

#include <linux/sched.h>	// for task_struct

struct trickle_timer {
	struct mutex		lock;

	// Imin, Imax, I and t fields are MILISECONDS

	unsigned long 		Imin;	// Imin: minimum interval size (default 100 ms)
	unsigned long 		Imax;	// Imax: maximum interval size, expressed in the number of doubling of the minimum interval size (default 16, that is 6553.6 seconds)
	int 				k;		// k: redundancy constant

	unsigned long		I;
	int					c;
	unsigned long		t;

	struct task_struct	*task;
	void				(*trickle_fn)(unsigned long arg);
	unsigned long		trickle_fn_arg;
};

extern struct trickle_timer *
trickle_new(
		unsigned long Imin,
		unsigned long Imax,
		int k,
		void (*trickle_fn)(unsigned long arg),
		unsigned long trickle_fn_arg);

extern void trickle_free(struct trickle_timer *trickle);

extern int trickle_start(struct trickle_timer *trickle);

extern int trickle_stop(struct trickle_timer *trickle);

extern int trickle_hear_consistent(struct trickle_timer *trickle);

extern int trickle_hear_inconsistent(struct trickle_timer *trickle);

#endif /* CONFIG_IPV6_RPL */

#endif /* RPL_TRICKLE_H_ */
