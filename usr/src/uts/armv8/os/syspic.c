/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Richard Lowe
 * Copyright 2026 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/stddef.h>
#include <sys/syspic.h>
#include <sys/syspic_impl.h>
#include <sys/cmn_err.h>

/*
 * State we track for debugging, such as mdb's `::interrupts`
 *
 * We store an AVL keyed on vector (since our space is far too sparse for
 * tables).  `syspic_intrs_lock` protects the tree and the entries in the tree.
 *
 * Effort is taken such that people consuming `syspic_intrs_lock` receive a
 * consistent view (that is, `syspic_intrs_lock` is held until the state changes
 * are in hardware).  This is a courtesy as long as the state is only observed
 * by a debugger, as intended.
 */
kmutex_t syspic_intrs_lock;
avl_tree_t syspic_intrs;

static void stub_not_config(void);
static void stub_intr_exit(spo_ctx_t ctx, intr_ipl_t ipl);

static syspic_ops_t spo_default_ops = {
	.spo_cpu_init		= (spo_cpu_init_t)stub_not_config,
	.spo_intr_enter		= (spo_intr_enter_t)stub_not_config,
	.spo_intr_exit		= stub_intr_exit,
	.spo_iack		= (spo_iack_t)stub_not_config,
	.spo_cookie_to_intid	= (spo_cookie_to_intid_t)stub_not_config,
	.spo_is_spurious	= (spo_is_spurious_t)stub_not_config,
	.spo_eoi		= (spo_eoi_t)stub_not_config,
	.spo_deactivate		= (spo_deactivate_t)stub_not_config,
	.spo_send_ipi		= (spo_send_ipi_t)stub_not_config,
	.spo_addspl		= (spo_addspl_t)stub_not_config,
	.spo_delspl		= (spo_delspl_t)stub_not_config
};

static spo_ctx_t spo_ctx = &spo_default_ops;
static syspic_ops_t *spo_ops = &spo_default_ops;
static dev_info_t *syspic_dip;

static void
stub_not_config(void)
{
	panic("System PIC not configured");
}

static void
stub_intr_exit(spo_ctx_t ctx __unused, intr_ipl_t ipl __unused)
{
	/*
	 * Nothing to do here.
	 *
	 * intr_exit() is called while locking and printing in the early
	 * kmem_init path (console_{enter,exit}, putq, cprintf) and in startup
	 * (cmn_err and mod_setup, reaching many of the same locks as in the
	 * kmem_init path).
	 *
	 * Adjusting the priority level this early is unnecessary, since
	 * interrupts are completely disabled. Locking is also unnecessary,
	 * since only one CPU is running. However, avoiding these calls in this
	 * case would overly complicate the general case of running the system,
	 * so we just allow the calls to be no-ops prior to loading a PIC
	 * implementation module.
	 */
}

static int
syspic_intr_state_cmp(const void *l, const void *r)
{
	const syspic_intr_state_t *li = l;
	const syspic_intr_state_t *ri = r;

	if (li->si_vector > ri->si_vector)
		return (1);
	if (li->si_vector < ri->si_vector)
		return (-1);
	return (0);
}

syspic_intr_state_t *
syspic_get_state(int irq)
{
	syspic_intr_state_t lookup, *new;
	avl_index_t where = 0;

	lookup.si_vector = irq;

	mutex_enter(&syspic_intrs_lock);

	if ((new = avl_find(&syspic_intrs, &lookup, &where)) == NULL) {
		new = kmem_zalloc(sizeof (*new), KM_SLEEP);
		new->si_vector = irq;
		avl_insert(&syspic_intrs, new, where);
	} else {
		new->si_vector = irq;
	}

	return (new);
}

void
syspic_remove_state(int irq)
{
	syspic_intr_state_t lookup, *st;

	ASSERT(MUTEX_HELD(&syspic_intrs_lock));

	lookup.si_vector = irq;
	st = avl_find(&syspic_intrs, &lookup, NULL);
	VERIFY3P(st, !=, NULL);

	avl_remove(&syspic_intrs, st);
	kmem_free(st, sizeof (syspic_intr_state_t));
}

int
syspic_init(void)
{
	mutex_init(&syspic_intrs_lock, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&syspic_intrs, syspic_intr_state_cmp,
	    sizeof (syspic_intr_state_t),
	    offsetof(syspic_intr_state_t, si_node));

	return (0);
}

int
syspic_register_syspic(spo_ctx_t ctx, syspic_ops_t *ops, dev_info_t *dip)
{
	VERIFY3U(spo_ctx, ==, &spo_default_ops);
	VERIFY3U(spo_ops, ==, &spo_default_ops);

	if (spo_ctx != &spo_default_ops || spo_ops != &spo_default_ops)
		return (0);

	spo_ctx = ctx;
	spo_ops = ops;
	VERIFY3P(dip, !=, NULL);
	VERIFY3P(syspic_dip, ==, NULL);
	syspic_dip = dip;
	return (1);
}

dev_info_t *
syspic_get_dip(void)
{
	return (syspic_dip);
}

void
syspic_cpu_init(cpu_t *cp)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	return (spo_ops->spo_cpu_init(spo_ctx, cp));
}

int
syspic_intr_enter(intr_intid_t intid)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	return (spo_ops->spo_intr_enter(spo_ctx, intid));
}

void
syspic_intr_exit(intr_ipl_t ipl)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	spo_ops->spo_intr_exit(spo_ctx, ipl);
}

intr_cookie_t
syspic_iack(void)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	return (spo_ops->spo_iack(spo_ctx));
}

intr_intid_t
syspic_cookie_to_intid(intr_cookie_t cookie)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	return (spo_ops->spo_cookie_to_intid(spo_ctx, cookie));
}

boolean_t
syspic_is_spurious(intr_intid_t intid)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	return (spo_ops->spo_is_spurious(spo_ctx, intid));
}

void
syspic_eoi(intr_cookie_t cookie)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	spo_ops->spo_eoi(spo_ctx, cookie);
}

void
syspic_intr_deactivate(intr_cookie_t cookie)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	spo_ops->spo_deactivate(spo_ctx, cookie);
}

void
syspic_send_ipi(cpuset_t cpuset, intr_intid_t intid)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	spo_ops->spo_send_ipi(spo_ctx, cpuset, intid);
}

void
syspic_send_ipi_one(cpu_t *cpu, intr_intid_t intid)
{
	ASSERT3P(cpu, !=, NULL);
	syspic_send_ipi_one_id(cpu->cpu_id, intid);
}

void
syspic_send_ipi_one_id(int cpuid, intr_intid_t intid)
{
	cpuset_t cpuset;

	CPUSET_ZERO(cpuset);
	CPUSET_ADD(cpuset, cpuid);

	syspic_send_ipi(cpuset, intid);
}

static int
syspic_addspl(int irq, int ipl, int min_ipl, int max_ipl)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	return (spo_ops->spo_addspl(spo_ctx, (intr_intid_t)irq,
	    (intr_ipl_t)ipl, (intr_ipl_t)min_ipl, (intr_ipl_t)max_ipl));
}

int (*addspl)(int, int, int, int) = syspic_addspl;

static int
syspic_delspl(int irq, int ipl, int min_ipl, int max_ipl)
{
	ASSERT3U(spo_ctx, !=, NULL);
	ASSERT3U(spo_ops, !=, NULL);

	return (spo_ops->spo_delspl(spo_ctx, (intr_intid_t)irq,
	    (intr_ipl_t)ipl, (intr_ipl_t)min_ipl, (intr_ipl_t)max_ipl));
}

int (*delspl)(int, int, int, int) = syspic_delspl;
