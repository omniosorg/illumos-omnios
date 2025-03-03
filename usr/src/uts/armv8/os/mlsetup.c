/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/disp.h>
#include <sys/autoconf.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/promimpl.h>
#include <sys/platform_module.h>
#include <sys/clock.h>
#include <sys/pte.h>
#include <sys/cpu.h>
#include <sys/stack.h>
#include <vm/as.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include <sys/vtrace.h>
#include <sys/trap.h>
#include <sys/privregs.h>
#include <sys/proc.h>
#include <sys/pset.h>
#include <sys/copyops.h>
#include <sys/panic.h>
#include <sys/pg.h>
#include <sys/kdi.h>
#include <sys/cpupart.h>
#include <sys/cpuinfo.h>
#include <sys/psci.h>
#include <sys/bootsvcs.h>

#include <sys/debug.h>

#include <sys/sunddi.h>
#include <sys/lgrp.h>

#include <sys/kobj_impl.h>
#include <sys/kdi_machimpl.h>

#include <sys/bootinfo.h>
#include <sys/bootconf.h>	/* for bootops */

#include <sys/controlregs.h>
#include <sys/arch_timer.h>

extern void bsvc_init(struct xboot_info *);

/*
 * called immediately from _start to stitch the
 * primary modules together
 */
void
kobj_start(struct xboot_info *xbp)
{
	Ehdr *ehdr;
	Phdr *phdr;
	uint32_t eadr, padr;
	val_t bootaux[BA_NUM];
	int i;
	extern int moddebug;

	bop_init(xbp);
	for (i = 0; i < BA_NUM; i++)
		bootaux[i].ba_val = 0;

	bootaux[BA_PAGESZ].ba_val = MMU_PAGESIZE;
	kobj_init(sysp, NULL, bootops, bootaux);
}

static int
translate_to_pa(uint64_t va, uint64_t *pa)
{
	uint64_t p;
	write_s1e1r(va);
	isb();
	p = read_par_el1();
	if (p & PAR_EL1_F)
		return (-1);
	*pa = (p & (PAR_EL1_PA_HI|PAR_EL1_PA)) | (va & MMU_PAGEOFFSET);
	return (0);
}

/*
 * Setup routine called right before main(). Interposing this function
 * before main() allows us to call it in a machine-independent fashion.
 */
void
mlsetup(struct regs *rp, struct xboot_info *xbp)
{
	extern char t0stack[];
	extern struct classfuncs sys_classfuncs;
	extern disp_t cpu0_disp;

	/*
	 * initialize cpu_self
	 */
	write_tpidr_el1((uintptr_t)&t0);
	cpu[0]->cpu_self = cpu[0];

	/*
	 * initialize t0
	 */
	t0.t_stk = (caddr_t)rp - MINFRAME;
	/* Can't use va_to_pa here - wait until prom_ initialized */
	t0.t_stkbase = t0stack;
	t0.t_pri = maxclsyspri - 3;
	t0.t_schedflag = TS_LOAD | TS_DONT_SWAP;
	t0.t_procp = &p0;
	t0.t_plockp = &p0lock.pl_lock;
	t0.t_lwp = &lwp0;
	t0.t_forw = &t0;
	t0.t_back = &t0;
	t0.t_next = &t0;
	t0.t_prev = &t0;
	t0.t_cpu = cpu[0];
	t0.t_disp_queue = &cpu0_disp;
	t0.t_bind_cpu = PBIND_NONE;
	t0.t_bind_pset = PS_NONE;
	t0.t_bindflag = (uchar_t)default_binding_mode;
	t0.t_cpupart = &cp_default;
	t0.t_clfuncs = &sys_classfuncs.thread;
	t0.t_copyops = NULL;
	THREAD_ONPROC(&t0, CPU);

	lwp0.lwp_thread = &t0;
	lwp0.lwp_regs = (void *)rp;
	lwp0.lwp_procp = &p0;
	t0.t_tid = p0.p_lwpcnt = p0.p_lwprcnt = p0.p_lwpid = 1;

	p0.p_exec = NULL;
	p0.p_stat = SRUN;
	p0.p_flag = SSYS;
	p0.p_tlist = &t0;
	p0.p_stksize = 0;
	p0.p_stkpageszc = 0;
	p0.p_as = &kas;
	p0.p_lockp = &p0lock;
	p0.p_utraps = NULL;
	p0.p_brkpageszc = 0;
	p0.p_t1_lgrpid = LGRP_NONE;
	p0.p_tr_lgrpid = LGRP_NONE;
	psecflags_default(&p0.p_secflags);
	sigorset(&p0.p_ignore, &ignoredefault);

	CPU->cpu_thread = &t0;
	CPU->cpu_dispthread = &t0;
	bzero(&cpu0_disp, sizeof (disp_t));
	CPU->cpu_disp = &cpu0_disp;
	CPU->cpu_disp->disp_cpu = CPU;
	CPU->cpu_idle_thread = &t0;
	CPU->cpu_flags = CPU_READY | CPU_RUNNING | CPU_EXISTS | CPU_ENABLE;
	CPU->cpu_id = 0;
	CPU->cpu_m.affinity = read_mpidr() & MPIDR_AFF_MASK;
	CPU->cpu_dispatch_pri = t0.t_pri;
	/*
	 * Save the boot EL. Bits [3:2] hold the value, so we
	 * shift the bits over to get the integer form.
	 */
	CPU->cpu_m.mcpu_boot_el = ((read_CurrentEL() >> 2) & 0x3);

	/*
	 * Select the system timer. Use the phys timer only if EL2.
	 */
	arch_timer_set_fw_freq(xbp->bi_arch_timer_freq);
	arch_timer_select((CPU->cpu_m.mcpu_boot_el == 2) ? TMR_PHYS : TMR_VIRT);

	/*
	 * Switch to our own exception vector as early as possible.
	 * We need the concept of time, so that's now.
	 *
	 * If we booted with kmdb, its trap table may already have been set
	 * when it loaded in load_kmdb() -- prior to mlsetup()! -- don't
	 * overwrite it with ours.
	 */
	if (!(boothowto & RB_KMDB)) {
		extern void exception_vector(void);
		write_vbar((uintptr_t)exception_vector);
	}

	/*
	 * Initialize thread/cpu microstate accounting
	 */
	init_mstate(&t0, LMS_SYSTEM);
	init_cpu_mstate(CPU, CMS_SYSTEM);

	/*
	 * Initialize lists of available and active CPUs.
	 */
	cpu_list_init(CPU);

	if (boothowto & RB_DEBUGENTER)
		kmdb_enter();

	cpu_vm_data_init(CPU);

	pg_cpu_bootstrap(CPU);

	/* Get value of boot_ncpus. */
	boot_ncpus = NCPU;
	max_ncpus = boot_max_ncpus = boot_ncpus;

	/*
	 * Initialise CPU info for the boot processor and fill in accurate
	 * values for boot_ncpus, boot_max_ncpus and max_ncpus.
	 */
	cpuinfo_bootstrap(CPU);

	/*
	 * lgroup framework initialization. This must be done prior
	 * to devices being mapped.
	 */
	lgrp_init(LGRP_INIT_STAGE1);

	/*
	 * Hypervisor trap table replacement.
	 *
	 * When Hypervisor extensions are present but VHE is not present the
	 * boot process installs a stub Hypervisor trap table that only knows
	 * how to replace itself, then drops to EL1.
	 *
	 * Since this trap table lives in low memory we need to replace it
	 * with the PA of the kernel's Hypervisor trap table before we drop
	 * the lower mappings. This sounds odd, but due to the way we boot
	 * the physical pages referenced by the lower mappings are not the
	 * same pages as those backing the running kernel, so we need to update
	 * things before those early pages get reclaimed.
	 */
	if (CPU->cpu_m.mcpu_boot_el == 1 && xbp->bi_hyp_stubs != 0) {
		int rv;
		uint64_t pa_hvc_stub;
		extern void hyp_stub_vectors(void);

		rv = translate_to_pa((uint64_t)hyp_stub_vectors, &pa_hvc_stub);
		VERIFY(rv == 0);

		__asm__ __volatile__(
		    "mov x0, %0" "\n"
		    "hvc #0"
		    : : "r"(pa_hvc_stub) : "memory");
	}

	if (boothowto & RB_HALT) {
		prom_printf("unix: kernel halted by -h flag\n");
		prom_enter_mon();
	}

	ASSERT_STACK_ALIGNED();
}

void
mach_modpath(char *path, const char *fname)
{
	char *p;
	int len, compat;
	const char prefix[] = "/platform/";
	char platname[MAXPATHLEN];
	char defname[] = "armv8";
	const char suffix[] = "/kernel";
	const char isastr[] = "/aarch64";

	/*
	 * check for /platform
	 */
	p = (char *)fname;
	if (strncmp(p, prefix, sizeof (prefix) - 1) != 0)
		goto nopath;
	p += sizeof (prefix) - 1;

	/*
	 * check for the default name or the platform name.
	 * also see if we used the 'compatible' name
	 * (platname == default)
	 */
	(void) BOP_GETPROP(bootops, "impl-arch-name", platname);
	compat = strcmp(platname, defname) == 0;
	len = strlen(platname);
	if (strncmp(p, platname, len) == 0)
		p += len;
	else if (strncmp(p, defname, sizeof (defname) - 1) == 0)
		p += sizeof (defname) - 1;
	else
		goto nopath;

	/*
	 * check for /kernel/aarch64 or just /kernel
	 */
	if (strncmp(p, suffix, sizeof (suffix) - 1) != 0)
		goto nopath;
	p += sizeof (suffix) - 1;
	if (strncmp(p, isastr, sizeof (isastr) - 1) == 0)
		p += sizeof (isastr) - 1;

	/*
	 * check we're at the last component
	 */
	if (p != strrchr(fname, '/'))
		goto nopath;

	/*
	 * everything is kosher; setup modpath
	 */
	(void) strcpy(path, "/platform/");
	(void) strcat(path, platname);
	(void) strcat(path, "/kernel");
	if (!compat) {
		(void) strcat(path, " /platform/");
		(void) strcat(path, defname);
		(void) strcat(path, "/kernel");
	}
	return;

nopath:
	/*
	 * Construct the directory path from the filename.
	 */
	if ((p = strrchr(fname, '/')) == NULL)
		return;

	while (p > fname && *(p - 1) == '/')
		p--;	/* remove trailing '/' characters */
	if (p == fname)
		p++;	/* so "/" -is- the modpath in this case */

	/*
	 * Remove optional isa-dependent directory name - the module
	 * subsystem will put this back again (!)
	 */
	len = p - fname;
	if (len > sizeof (isastr) - 1 &&
	    strncmp(&fname[len - (sizeof (isastr) - 1)], isastr,
	    sizeof (isastr) - 1) == 0)
		p -= sizeof (isastr) - 1;
	(void) strncpy(path, fname, p - fname);
}
