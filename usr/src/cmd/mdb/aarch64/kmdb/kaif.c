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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Interface between the debugger and the platform debug support.
 *
 * These interfaces deal with three things: setting break/watchpoints,
 * stepping, and interfacing with the KDI to set up kmdb's exception handlers.
 */

#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_umemglue.h>
#include <kmdb/kaif.h>
#include <kmdb/kmdb_io.h>
#include <kmdb/kaif_start.h>
#include <kmdb/kvm_isadep.h>
#include <kmdb/kmdb_asmutil.h>

#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_aarch64util.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb.h>

#include <sys/bitmap.h>
#include <sys/controlregs.h>
#include <sys/cpuid.h>
#include <sys/kdi_impl.h>
#include <sys/sysmacros.h>
#include <sys/termios.h>
#include <sys/types.h>

/*
 * This is the area containing the saved state when we enter
 * via kmdb's trap entries.
 */
kdi_cpusave_t	*kaif_cpusave;
int		kaif_ncpusave;
uint64_t	kaif_waptmap;

void (*kaif_modchg_cb)(struct modctl *, int);

#define	KAIF_BREAKPOINT_INSTR	0xd4200000 /* brk #0 */

#define	KAIF_WPPRIV2ID(wp)	(int)(uintptr_t)((wp)->wp_priv)

/*
 * Called during normal debugger operation and during debugger faults.
 */
static void
kaif_enter_mon(void)
{
	char c;

	for (;;) {
		mdb_iob_printf(mdb.m_out,
		    "%s: Do you really want to reboot? (y/n) ",
		    mdb.m_pname);
		mdb_iob_flush(mdb.m_out);
		mdb_iob_clearlines(mdb.m_out);

		c = kmdb_getchar();

		if (c == 'n' || c == 'N' || c == CTRL('c'))
			return;
		else if (c == 'y' || c == 'Y') {
			mdb_iob_printf(mdb.m_out, "Rebooting...\n");

			kmdb_dpi_reboot();
		}
	}
}

static kaif_cpusave_t *
kaif_cpuid2save(int cpuid)
{
	kaif_cpusave_t *save;

	if (cpuid == DPI_MASTER_CPUID)
		return (&kaif_cpusave[kaif_master_cpuid]);

	if (cpuid < 0 || cpuid >= kaif_ncpusave) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	save = &kaif_cpusave[cpuid];

	if (save->krs_cpu_state != KAIF_CPU_STATE_MASTER &&
	    save->krs_cpu_state != KAIF_CPU_STATE_SLAVE) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	return (save);
}

static int
kaif_get_cpu_state(int cpuid)
{
	kaif_cpusave_t *save;

	if ((save = kaif_cpuid2save(cpuid)) == NULL)
		return (-1); /* errno is set for us */

	switch (save->krs_cpu_state) {
	case KAIF_CPU_STATE_MASTER:
		return (DPI_CPU_STATE_MASTER);
	case KAIF_CPU_STATE_SLAVE:
		return (DPI_CPU_STATE_SLAVE);
	default:
		return (set_errno(EINVAL));
	}
}

static int
kaif_get_master_cpuid(void)
{
	return (kaif_master_cpuid);
}

static mdb_tgt_gregset_t *
kaif_kdi_to_gregs(int cpuid)
{
	kaif_cpusave_t *save;

	if ((save = kaif_cpuid2save(cpuid)) == NULL)
		return (NULL); /* errno is set for us */

	/*
	 * The saved registers are actually identical to an mdb_tgt_gregset,
	 * so we can directly cast here.
	 */
	return ((mdb_tgt_gregset_t *)save->krs_gregs);
}

static const mdb_tgt_gregset_t *
kaif_get_gregs(int cpuid)
{
	return (kaif_kdi_to_gregs(cpuid));
}

typedef struct kaif_reg_synonyms {
	const char *rs_syn;
	const char *rs_name;
} kaif_reg_synonyms_t;

static kreg_t *
kaif_find_regp(const char *regname)
{
	static const kaif_reg_synonyms_t synonyms[] = {
	    { "tt", "trapno" }
	};
	mdb_tgt_gregset_t *regs;
	int i;

	if ((regs = kaif_kdi_to_gregs(DPI_MASTER_CPUID)) == NULL)
		return (NULL);

	for (i = 0; i < sizeof (synonyms) / sizeof (synonyms[0]); i++) {
		if (strcmp(synonyms[i].rs_syn, regname) == 0)
			regname = synonyms[i].rs_name;
	}

	for (i = 0; mdb_aarch64_kregs[i].rd_name != NULL; i++) {
		const mdb_tgt_regdesc_t *rd = &mdb_aarch64_kregs[i];

		if (strcmp(rd->rd_name, regname) == 0)
			return (&regs->kregs[rd->rd_num]);
	}

	(void) set_errno(ENOENT);
	return (NULL);
}

static int
kaif_get_register(const char *regname, kreg_t *valp)
{
	kreg_t *regp;

	if ((regp = kaif_find_regp(regname)) == NULL)
		return (-1);

	*valp = *regp;

	return (0);
}

static int
kaif_set_register(const char *regname, kreg_t val)
{
	kreg_t *regp;

	if ((regp = kaif_find_regp(regname)) == NULL)
		return (-1);

	*regp = val;

	return (0);
}

static int
kaif_brkpt_arm(uintptr_t addr, mdb_instr_t *instrp)
{
	mdb_instr_t bkpt = KAIF_BREAKPOINT_INSTR;

	if (mdb_tgt_aread(mdb.m_target, MDB_TGT_AS_VIRT_I, instrp,
	    sizeof (mdb_instr_t), addr) != sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */

	if (mdb_tgt_awrite(mdb.m_target, MDB_TGT_AS_VIRT_I, &bkpt,
	    sizeof (mdb_instr_t), addr) != sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */

	flush_instr(addr);

	return (0);
}

static int
kaif_brkpt_disarm(uintptr_t addr, mdb_instr_t instrp)
{
	if (mdb_tgt_awrite(mdb.m_target, MDB_TGT_AS_VIRT_I, &instrp,
	    sizeof (mdb_instr_t), addr) != sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */

	flush_instr(addr);

	return (0);
}

static int
kaif_wapt_validate(kmdb_wapt_t *wp)
{
	if (wp->wp_wflags & MDB_TGT_WA_X) {
		warn("execute watchpoints are not supported on this "
		    "platform\n");
		/*
		 * XXXKDI: You'd think this would be TGTHWNOTSUP, but it
		 * isn't on other platforms
		 */
		return (set_errno(EMDB_TGTNOTSUP));
	}

	if (wp->wp_type != DPI_WAPT_TYPE_VIRT) {
		warn("requested watchpoint type not supported on this "
		    "platform\n");
		return (set_errno(EMDB_TGTHWNOTSUP));
	}

	/* watched areas must be 2G or less */
	if (wp->wp_size > 0x80000000LL) {
		warn("watchpoints must be 2G or less");
		return (set_errno(EINVAL));
	}

	/* only support one hardware watchpoint per logical watchpoint */
	if ((wp->wp_size <= 8) &&
	    ((P2PHASE(wp->wp_addr, 8) + wp->wp_size) > 8)) {
		warn("watchpoint of %lu bytes at %p would require "
		    "two hw watchpoints", wp->wp_size, wp->wp_addr);
		return (set_errno(EINVAL));
	}

	/* watched areas > 8 bytes must be a power of two in size */
	if (!ISP2(wp->wp_size)) {
		warn("watchpoints of over 8 bytes must be a power "
		    "of two size, not %lu\n", wp->wp_size);
		return (set_errno(EINVAL));
	}

	/* watched areas > 8 bytes must be naturally aligned */
	if ((wp->wp_size > 8) &&
	    ((wp->wp_size & -(wp->wp_size)) != wp->wp_size)) {
		warn("watchpoints of %lu bytes must be %lu-byte aligned\n",
		    (ulong_t)wp->wp_size, (ulong_t)wp->wp_size);
		return (set_errno(EINVAL));
	}

	/* watched areas [4,8] bytes must be double-word aligned */
	if ((wp->wp_size > 4) && (wp->wp_size <= 8) &&
	    P2NPHASE(wp->wp_addr, 8) != 0) {
		warn("%lu-byte watchpoints must be 8-byte aligned\n",
		    wp->wp_size);
		return (set_errno(EINVAL));
	}

	/* watched areas [1,4] bytes must be word-aligned */
	if ((wp->wp_size <= 4) && P2NPHASE(wp->wp_addr, 4) != 0) {
		warn("%lu-byte watchpoints must be 4-byte aligned\n",
		    wp->wp_size);
		return (set_errno(EINVAL));
	}

	return (0);
}

static int
kaif_wapt_reserve(kmdb_wapt_t *wp)
{
	size_t wrps = 0;
	int id;

	wrps = kmdb_kdi_num_wapts();

	for (id = 0; id < wrps; id++) {
		if (!BT_TEST(&kaif_waptmap, id)) {
			/* found one */
			BT_SET(&kaif_waptmap, id);
			wp->wp_priv = (void *)(uintptr_t)id;
			return (0);
		}
	}

	return (set_errno(EMDB_WPTOOMANY));
}

static void
kaif_wapt_release(kmdb_wapt_t *wp)
{
	int id = KAIF_WPPRIV2ID(wp);

	ASSERT(BT_TEST(&kaif_waptmap, id));
	BT_CLEAR(&kaif_waptmap, id);
}

static void
kaif_wapt_arm(kmdb_wapt_t *wp)
{
	kdi_waptreg_t waptreg = {0};
	uint_t hwid = KAIF_WPPRIV2ID(wp);
	uint_t rw = 0;

	ASSERT(BT_TEST(&kaif_waptmap, hwid));

	if (wp->wp_wflags & MDB_TGT_WA_R)
		rw |= WCR_LSC_LOAD;
	if (wp->wp_wflags & MDB_TGT_WA_W)
		rw |= WCR_LSC_STORE;

	/*
	 * byte-address-select, a mask of the bytes following wp_addr which
	 * are watched.  Not necessarily starting at 0.
	 */
	uint8_t bas = 0xff;
	uintptr_t addr = P2ALIGN(wp->wp_addr, 8);
	ptrdiff_t addr_phase = P2PHASE(wp->wp_addr, 8);
	uint8_t mask = 0x0;

	/*
	 * double-word aligned address, 8-byte byte-address-select
	 * word aligned address, 4-byte byte-address select
	 */
	if ((IS_P2ALIGNED(wp->wp_addr, 8) && wp->wp_size <= 8) ||
	    (IS_P2ALIGNED(wp->wp_addr, 4) && wp->wp_size <= 4)) {
		bas = (1 - wp->wp_size) << addr_phase;
	} else {
		mask = (1 << wp->wp_size) - 1;
	}

	ASSERT((mask == 0x0) || (bas == 0xff));

	waptreg.kw_hwid = hwid;
	waptreg.kw_addr = addr;
	waptreg.kw_ctl = WCR_MASK(mask) | WCR_BAS(bas) | WCR_LSC(rw) |
	    WCR_PAC(1) | WCR_ENABLE;

	kmdb_kdi_update_waptreg(&waptreg);

}

static void
kaif_wapt_disarm(kmdb_wapt_t *wp)
{
	kdi_waptreg_t new = {0};
	int hwid = KAIF_WPPRIV2ID(wp);


	ASSERT(BT_TEST(&kaif_waptmap, hwid));

	kmdb_kdi_read_waptreg(hwid, &new);

	new.kw_ctl &= ~WCR_ENABLE;

	kmdb_kdi_update_waptreg(&new);
}

static int
kaif_wapt_match(kmdb_wapt_t *wp)
{
	uint64_t far = 0;
	int hwid = KAIF_WPPRIV2ID(wp);
	int i;

	ASSERT(BT_TEST(&kaif_waptmap, hwid));

	(void) kmdb_dpi_get_register("far", &far);

	for (i = 0; i < kmdb_kdi_num_wapts(); i++) {
		kdi_waptreg_t kw;

		kmdb_kdi_read_waptreg(i, &kw);

		if ((far >= wp->wp_addr) &&
		    (far < (wp->wp_addr + wp->wp_size))) {
			return (1);
		}
	}

	return (0);
}

static int
kaif_step(void)
{
	kreg_t spsr;

	/*
	 * set single-step, disable interrupts, and clear PSTATE.D when we
	 * resume.
	 */
	(void) kmdb_dpi_get_register("spsr", &spsr);
	(void) kmdb_dpi_set_register("spsr", (spsr | PSR_SS | PSR_I) & ~PSR_D);
	write_mdscr_el1(read_mdscr_el1() | MDSCR_SS);

	kmdb_dpi_resume_master(); /* Run the next instruction and come back */

	/*
	 * restore the single step setting and mask settings, leave the rest
	 * of the status register alone.
	 */
	(void) kmdb_dpi_get_register("spsr", &spsr);
	(void) kmdb_dpi_set_register("spsr",
	    (spsr & ~(PSR_SS | PSR_I)) | PSR_D);
	write_mdscr_el1(read_mdscr_el1() & ~MDSCR_SS);

	return (0);
}

static uintptr_t
kaif_call(uintptr_t funcva, uint_t argc, const uintptr_t argv[])
{
	return (kaif_invoke(funcva, argc, argv));
}

static void
dump_crumb(kdi_crumb_t *krmp)
{
	kdi_crumb_t krm;

	if (mdb_vread(&krm, sizeof (kdi_crumb_t), (uintptr_t)krmp) !=
	    sizeof (kdi_crumb_t)) {
		warn("failed to read crumb at %p", krmp);
		return;
	}

	mdb_printf("state: ");
	switch (krm.krm_cpu_state) {
	case KAIF_CPU_STATE_MASTER:
		mdb_printf("M");
		break;
	case KAIF_CPU_STATE_SLAVE:
		mdb_printf("S");
		break;
	default:
		mdb_printf("%d", krm.krm_cpu_state);
	}

	mdb_printf(" trapno %3d sp %08x flag %d pc %p %A\n",
	    krm.krm_trapno, krm.krm_sp, krm.krm_flag, krm.krm_pc, krm.krm_pc);
}

static void
dump_crumbs(kaif_cpusave_t *save)
{
	int i;

	for (i = KDI_NCRUMBS; i > 0; i--) {
		uint_t idx = (save->krs_curcrumbidx + i) % KDI_NCRUMBS;
		dump_crumb(&save->krs_crumbs[idx]);
	}
}

static void
kaif_dump_crumbs(uintptr_t addr, int cpuid)
{
	int i;

	if (addr != 0) {
		/* dump_crumb will protect us against bogus addresses */
		dump_crumb((kdi_crumb_t *)addr);

	} else if (cpuid != -1) {
		if (cpuid < 0 || cpuid >= kaif_ncpusave)
			return;

		dump_crumbs(&kaif_cpusave[cpuid]);

	} else {
		for (i = 0; i < kaif_ncpusave; i++) {
			kaif_cpusave_t *save = &kaif_cpusave[i];

			if (save->krs_cpu_state == KAIF_CPU_STATE_NONE)
				continue;

			mdb_printf("%sCPU %d crumbs: (curidx %d)\n",
			    (i == 0 ? "" : "\n"), i, save->krs_curcrumbidx);

			dump_crumbs(save);
		}
	}
}

static void
kaif_modchg_register(void (*func)(struct modctl *, int))
{
	kaif_modchg_cb = func;
}

static void
kaif_modchg_cancel(void)
{
	ASSERT(kaif_modchg_cb != NULL);

	kaif_modchg_cb = NULL;
}

void
kaif_trap_set_debugger(void)
{
	kmdb_kdi_set_exception_vector(NULL);
}

void
kaif_trap_set_saved(kaif_cpusave_t *cpusave)
{
	kmdb_kdi_set_exception_vector(cpusave);
}

static void
kaif_vmready(void)
{
}

void
kaif_memavail(caddr_t base, size_t len)
{
	int ret;
	/*
	 * In the unlikely event that someone is stepping through this routine,
	 * we need to make sure that the KDI knows about the new range before
	 * umem gets it.  That way the entry code can recognize stacks
	 * allocated from the new region.
	 */
	kmdb_kdi_memrange_add(base, len);
	ret = mdb_umem_add(base, len);
	ASSERT(ret == 0);
}

void
kaif_mod_loaded(struct modctl *modp)
{
	if (kaif_modchg_cb != NULL)
		kaif_modchg_cb(modp, 1);
}

void
kaif_mod_unloading(struct modctl *modp)
{
	if (kaif_modchg_cb != NULL)
		kaif_modchg_cb(modp, 0);
}

void
kaif_handle_fault(greg_t trapno, greg_t pc, greg_t sp, int cpuid)
{
	kmdb_dpi_handle_fault((kreg_t)trapno, (kreg_t)pc,
	    (kreg_t)sp, cpuid);
}

static kdi_debugvec_t kaif_dvec = {
	.dv_kctl_vmready = NULL,
	.dv_kctl_memavail = NULL,
	.dv_kctl_modavail = NULL,
	.dv_kctl_thravail = NULL,
	.dv_vmready = kaif_vmready,
	.dv_memavail = kaif_memavail,
	.dv_mod_loaded = kaif_mod_loaded,
	.dv_mod_unloading = kaif_mod_unloading,
	.dv_handle_fault = kaif_handle_fault,
};

void
kaif_kdi_entry(kdi_cpusave_t *cpusave)
{
	int ret = kaif_main_loop(cpusave);
	ASSERT(ret == KAIF_CPU_CMD_RESUME ||
	    ret == KAIF_CPU_CMD_RESUME_MASTER);
}

void
kaif_activate(kdi_debugvec_t **dvecp, uint_t flags __unused)
{
	kmdb_kdi_activate(kaif_kdi_entry, kaif_cpusave, kaif_ncpusave);
	*dvecp = &kaif_dvec;
}

static int
kaif_init(kmdb_auxv_t *kav)
{
	/* Allocate the per-CPU save areas */
	kaif_cpusave = mdb_zalloc(sizeof (kaif_cpusave_t) * kav->kav_ncpu,
	    UM_SLEEP);
	kaif_ncpusave = kav->kav_ncpu;

	kaif_modchg_cb = NULL;

	return (0);
}

dpi_ops_t kmdb_dpi_ops = {
	.dpo_init = kaif_init,
	.dpo_debugger_activate = kaif_activate,
	.dpo_debugger_deactivate = kmdb_kdi_deactivate,
	.dpo_enter_mon = kaif_enter_mon,
	.dpo_modchg_register = kaif_modchg_register,
	.dpo_modchg_cancel = kaif_modchg_cancel,
	.dpo_get_cpu_state = kaif_get_cpu_state,
	.dpo_get_master_cpuid = kaif_get_master_cpuid,
	.dpo_get_gregs = kaif_get_gregs,
	.dpo_get_register = kaif_get_register,
	.dpo_set_register = kaif_set_register,
	.dpo_brkpt_arm = kaif_brkpt_arm,
	.dpo_brkpt_disarm = kaif_brkpt_disarm,
	.dpo_wapt_validate = kaif_wapt_validate,
	.dpo_wapt_reserve = kaif_wapt_reserve,
	.dpo_wapt_release = kaif_wapt_release,
	.dpo_wapt_arm = kaif_wapt_arm,
	.dpo_wapt_disarm = kaif_wapt_disarm,
	.dpo_wapt_match = kaif_wapt_match,
	.dpo_step = kaif_step,
	.dpo_call = kaif_call,
	.dpo_dump_crumbs = kaif_dump_crumbs,
};
