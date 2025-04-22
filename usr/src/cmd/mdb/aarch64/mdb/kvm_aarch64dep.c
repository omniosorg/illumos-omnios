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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2022 Richard Lowe
 */

/*
 * Libkvm Kernel Target AArch64 component
 *
 * This file provides the ISA-dependent portion of the libkvm kernel target.
 * For more details on the implementation refer to mdb_kvm.c.
 */

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_disasm.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_stack.h>
#include <mdb/mdb_kvm.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>
#include <mdb/kvm_isadep.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_isautil.h>

#include <sys/panic.h>

int
kt_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const kreg_t *grs = &((mdb_tgt_gregset_t *)addr)->kregs[0];

	mdb_printf("%%x0 = 0x%0?p\t%%x1 = 0x%0?p\n",
	    grs[KREG_X0], grs[KREG_X1]);
	mdb_printf("%%x2 = 0x%0?p\t%%x3 = 0x%0?p\n",
	    grs[KREG_X2], grs[KREG_X3]);
	mdb_printf("%%x4 = 0x%0?p\t%%x5 = 0x%0?p\n",
	    grs[KREG_X4], grs[KREG_X5]);
	mdb_printf("%%x6 = 0x%0?p\t%%x7 = 0x%0?p\n",
	    grs[KREG_X6], grs[KREG_X7]);
	mdb_printf("%%x8 = 0x%0?p\t%%x9 = 0x%0?p\n",
	    grs[KREG_X8], grs[KREG_X9]);
	mdb_printf("%%x10 = 0x%0?p\t%%x11 = 0x%0?p\n",
	    grs[KREG_X10], grs[KREG_X11]);
	mdb_printf("%%x12 = 0x%0?p\t%%x13 = 0x%0?p\n",
	    grs[KREG_X12], grs[KREG_X13]);
	mdb_printf("%%x14 = 0x%0?p\t%%x15 = 0x%0?p\n",
	    grs[KREG_X14], grs[KREG_X15]);
	mdb_printf("%%x16 = 0x%0?p\t%%x17 = 0x%0?p\n",
	    grs[KREG_X16], grs[KREG_X17]);
	mdb_printf("%%x18 = 0x%0?p\t%%x19 = 0x%0?p\n",
	    grs[KREG_X18], grs[KREG_X19]);
	mdb_printf("%%x20 = 0x%0?p\t%%x21 = 0x%0?p\n",
	    grs[KREG_X20], grs[KREG_X21]);
	mdb_printf("%%x22 = 0x%0?p\t%%x23 = 0x%0?p\n",
	    grs[KREG_X22], grs[KREG_X23]);
	mdb_printf("%%x24 = 0x%0?p\t%%x25 = 0x%0?p\n",
	    grs[KREG_X24], grs[KREG_X25]);
	mdb_printf("%%x26 = 0x%0?p\t%%x27 = 0x%0?p\n",
	    grs[KREG_X26], grs[KREG_X27]);
	mdb_printf("%%x28 = 0x%0?p\t%%x29 = 0x%0?p\n",
	    grs[KREG_X28], grs[KREG_X29]);
	mdb_printf("%%x30 = 0x%0?p\n", grs[KREG_X30]);
	mdb_printf("\n");

	mdb_printf("%%sp = 0x%0?p\t%%pc = 0x%0?p\n",
	    grs[KREG_SP], grs[KREG_PC]);
	mdb_printf("%%tp = 0x%0?p\t%%spsr = 0x%0?p\n",
	    grs[KREG_TP], grs[KREG_SPSR]);

	return (DCMD_OK);
}

void
kt_regs_to_kregs(struct regs *regs, mdb_tgt_gregset_t *gregs)
{
	gregs->kregs[KREG_SAVFP] = regs->r_savfp;
	gregs->kregs[KREG_SAVPC] = regs->r_savpc;

	gregs->kregs[KREG_X0] = regs->r_x0;
	gregs->kregs[KREG_X1] = regs->r_x1;
	gregs->kregs[KREG_X2] = regs->r_x2;
	gregs->kregs[KREG_X3] = regs->r_x3;
	gregs->kregs[KREG_X4] = regs->r_x4;
	gregs->kregs[KREG_X5] = regs->r_x5;
	gregs->kregs[KREG_X6] = regs->r_x6;
	gregs->kregs[KREG_X7] = regs->r_x7;
	gregs->kregs[KREG_X8] = regs->r_x8;
	gregs->kregs[KREG_X9] = regs->r_x9;
	gregs->kregs[KREG_X10] = regs->r_x10;
	gregs->kregs[KREG_X11] = regs->r_x11;
	gregs->kregs[KREG_X12] = regs->r_x12;
	gregs->kregs[KREG_X13] = regs->r_x13;
	gregs->kregs[KREG_X14] = regs->r_x14;
	gregs->kregs[KREG_X15] = regs->r_x15;
	gregs->kregs[KREG_X16] = regs->r_x16;
	gregs->kregs[KREG_X17] = regs->r_x17;
	gregs->kregs[KREG_X18] = regs->r_x18;
	gregs->kregs[KREG_X19] = regs->r_x19;
	gregs->kregs[KREG_X20] = regs->r_x20;
	gregs->kregs[KREG_X21] = regs->r_x21;
	gregs->kregs[KREG_X22] = regs->r_x22;
	gregs->kregs[KREG_X23] = regs->r_x23;
	gregs->kregs[KREG_X24] = regs->r_x24;
	gregs->kregs[KREG_X25] = regs->r_x25;
	gregs->kregs[KREG_X26] = regs->r_x26;
	gregs->kregs[KREG_X27] = regs->r_x27;
	gregs->kregs[KREG_X28] = regs->r_x28;
	gregs->kregs[KREG_X29] = regs->r_x29;
	gregs->kregs[KREG_X30] = regs->r_x30;
	gregs->kregs[KREG_SP] = regs->r_sp;
	gregs->kregs[KREG_PC] = regs->r_pc;
	gregs->kregs[KREG_SPSR] = regs->r_spsr;
	gregs->kregs[KREG_TP] = regs->r_tp;
	gregs->kregs[KREG_ESR] = regs->r_esr;
	gregs->kregs[KREG_FAR] = regs->r_far;
	gregs->kregs[KREG_TRAPNO] = regs->r_trapno;
}

int
kt_putareg(mdb_tgt_t *t, mdb_tgt_tid_t tid, const char *rname, mdb_tgt_reg_t r)
{
	const mdb_tgt_regdesc_t *rdp;
	kt_data_t *kt = t->t_data;

	if (tid != kt->k_tid)
		return (set_errno(EMDB_NOREGS));

	for (rdp = kt->k_rds; rdp->rd_name != NULL; rdp++) {
		if (strcmp(rname, rdp->rd_name) == 0) {
			if (rdp->rd_flags & MDB_TGT_R_32)
				r &= 0xffffffffULL;

			kt->k_regs->kregs[rdp->rd_num] = (kreg_t)r;
			return (0);
		}
	}

	return (set_errno(EMDB_BADREG));
}

static int
kt_stack_common(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    mdb_stack_frame_flags_t sflags, mdb_tgt_stack_f *func)
{
	mdb_tgt_t *t = mdb.m_target;
	kt_data_t *kt = t->t_data;
	mdb_tgt_gregset_t gregs, *grp;
	mdb_stack_frame_hdl_t *hdl;
	uint_t arglim = mdb.m_nargs;
	int i;

	if (flags & DCMD_ADDRSPEC) {
		bzero(&gregs, sizeof (gregs));
		gregs.kregs[KREG_FP] = addr;
		grp = &gregs;
	} else {
		grp = kt->k_regs;
	}

	i = mdb_getopts(argc, argv,
	    's', MDB_OPT_SETBITS, MSF_SIZES, &sflags,
	    't', MDB_OPT_SETBITS, MSF_TYPES, &sflags,
	    'v', MDB_OPT_SETBITS, MSF_VERBOSE, &sflags,
	    NULL);

	argc -= i;
	argv += i;

	if (argc != 0) {
		if (argv->a_type == MDB_TYPE_CHAR || argc > 1)
			return (DCMD_USAGE);

		arglim = mdb_argtoull(argv);
	}

	if ((hdl = mdb_stack_frame_init(t, arglim, sflags)) == NULL) {
		mdb_warn("failed to init stack frame\n");
		return (DCMD_ERR);
	}

	(void) mdb_isa_kvm_stack_iter(t, grp, func, (void *)hdl);
	return (DCMD_OK);
}

int
kt_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kt_stack_common(addr, flags, argc, argv,
	    0, mdb_isa_kvm_frame));
}

int
kt_stackv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kt_stack_common(addr, flags, argc, argv,
	    MSF_VERBOSE, mdb_isa_kvm_frame));
}

const mdb_tgt_ops_t kt_aarch64_ops = {
	.t_setflags = kt_setflags,
	.t_setcontext = kt_setcontext,
	.t_activate = kt_activate,
	.t_deactivate = kt_deactivate,
	.t_periodic = (void (*)())(uintptr_t)mdb_tgt_nop,
	.t_destroy = kt_destroy,
	.t_name = kt_name,
	.t_isa = (const char *(*)())mdb_conf_isa,
	.t_platform = kt_platform,
	.t_uname = kt_uname,
	.t_dmodel = kt_dmodel,
	.t_aread = kt_aread,
	.t_awrite = kt_awrite,
	.t_vread = kt_vread,
	.t_vwrite = kt_vwrite,
	.t_pread = kt_pread,
	.t_pwrite = kt_pwrite,
	.t_fread = kt_fread,
	.t_fwrite = kt_fwrite,
	.t_ioread = (ssize_t (*)())mdb_tgt_notsup,
	.t_iowrite = (ssize_t (*)())mdb_tgt_notsup,
	.t_vtop = kt_vtop,
	.t_lookup_by_name = kt_lookup_by_name,
	.t_lookup_by_addr = kt_lookup_by_addr,
	.t_symbol_iter = kt_symbol_iter,
	.t_mapping_iter = kt_mapping_iter,
	.t_object_iter = kt_object_iter,
	.t_addr_to_map = kt_addr_to_map,
	.t_name_to_map = kt_name_to_map,
	.t_addr_to_ctf = kt_addr_to_ctf,
	.t_name_to_ctf = kt_name_to_ctf,
	.t_status = kt_status,
	.t_run = (int (*)())(uintptr_t)mdb_tgt_notsup,
	.t_step = (int (*)())(uintptr_t)mdb_tgt_notsup,
	.t_step_out = (int (*)())(uintptr_t)mdb_tgt_notsup,
	.t_next = (int (*)())(uintptr_t)mdb_tgt_notsup,
	.t_cont = (int (*)())(uintptr_t)mdb_tgt_notsup,
	.t_signal = (int (*)())(uintptr_t)mdb_tgt_notsup,
	.t_add_vbrkpt = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_add_sbrkpt = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_add_pwapt = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_add_vwapt = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_add_iowapt = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_add_sysenter = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_add_sysexit = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_add_signal = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_add_fault = (int (*)())(uintptr_t)mdb_tgt_null,
	.t_getareg = kt_getareg,
	.t_putareg = kt_putareg,
	.t_stack_iter = mdb_isa_kvm_stack_iter,
	.t_auxv = (int (*)())(uintptr_t)mdb_tgt_notsup
};

void
kt_aarch64_init(mdb_tgt_t *t)
{
	kt_data_t *kt = t->t_data;
	panic_data_t pd;
	struct regs regs;
	uintptr_t addr;

	/*
	 * Initialize the machine-dependent parts of the kernel target
	 * structure.  Once this is complete and we fill in the ops
	 * vector, the target is now fully constructed and we can use
	 * the target API itself to perform the rest of our initialization.
	 */
	kt->k_rds = mdb_isa_kregs;
	kt->k_regs = mdb_zalloc(sizeof (mdb_tgt_gregset_t), UM_SLEEP);
	kt->k_regsize = sizeof (mdb_tgt_gregset_t);
	kt->k_dcmd_regs = kt_regs;
	kt->k_dcmd_stack = kt_stack;
	kt->k_dcmd_stackv = kt_stackv;
	kt->k_dcmd_stackr = kt_stackv;
	kt->k_dcmd_cpustack = (int (*)())(uintptr_t)mdb_tgt_notsup;
	kt->k_dcmd_cpuregs = (int (*)())(uintptr_t)mdb_tgt_notsup;

	t->t_ops = &kt_aarch64_ops;

	(void) mdb_dis_select("a64");

	/*
	 * Don't attempt to load any thread or register information if
	 * we're examining the live operating system.
	 */
	if (kt->k_symfile != NULL && strcmp(kt->k_symfile, "/dev/ksyms") == 0)
		return;

	/*
	 * If the panicbuf symbol is present and we can consume a panicbuf
	 * header of the appropriate version from this address, then we can
	 * initialize our current register set based on its contents.
	 * Prior to the re-structuring of panicbuf, our only register data
	 * was the panic_regs label_t, into which a setjmp() was performed,
	 * or the panic_reg register pointer, which was only non-zero if
	 * the system panicked as a result of a trap calling die().
	 */
	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &pd, sizeof (pd),
	    MDB_TGT_OBJ_EXEC, "panicbuf") == sizeof (pd) &&
	    pd.pd_version == PANICBUFVERS) {

		size_t pd_size = MIN(PANICBUFSIZE, pd.pd_msgoff);
		panic_data_t *pdp = mdb_zalloc(pd_size, UM_SLEEP);
		uint_t i, n;

		(void) mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, pdp, pd_size,
		    MDB_TGT_OBJ_EXEC, "panicbuf");

		n = (pd_size - (sizeof (panic_data_t) -
		    sizeof (panic_nv_t))) / sizeof (panic_nv_t);

		for (i = 0; i < n; i++) {
			(void) kt_putareg(t, kt->k_tid,
			    pdp->pd_nvdata[i].pnv_name,
			    pdp->pd_nvdata[i].pnv_value);
		}

		mdb_free(pdp, pd_size);

		return;
	};

	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &addr, sizeof (addr),
	    MDB_TGT_OBJ_EXEC, "panic_reg") == sizeof (addr) && addr != 0 &&
	    mdb_tgt_vread(t, &regs, sizeof (regs), addr) == sizeof (regs)) {
		kt_regs_to_kregs(&regs, kt->k_regs);
		return;
	}

	warn("failed to read panicbuf and panic_reg -- "
	    "current register set will be unavailable\n");
}
