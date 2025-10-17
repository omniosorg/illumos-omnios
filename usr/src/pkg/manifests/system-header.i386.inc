#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2013 Saso Kiselkov. All rights reserved.
# Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
# Copyright 2018 Nexenta Systems, Inc.
# Copyright 2019 Peter Tribble.
# Copyright 2020 Joyent, Inc.
# Copyright 2022 Garrett D'Amore
# Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2025 Oxide Computer company

dir path=usr/include/$(ARCH64)
dir path=usr/include/$(ARCH64)/sys
file path=usr/include/$(ARCH64)/sys/kdi_regs.h
file path=usr/include/$(ARCH64)/sys/privmregs.h
file path=usr/include/$(ARCH64)/sys/privregs.h
file path=usr/include/asm/bitmap.h
file path=usr/include/asm/clock.h
file path=usr/include/asm/cpuvar.h
file path=usr/include/asm/htable.h
file path=usr/include/asm/mmu.h
dir path=usr/include/ia32
dir path=usr/include/ia32/sys
link path=usr/include/ia32/sys/asm_linkage.h \
    target=../../sys/asm_linkage.h
file path=usr/include/ia32/sys/kdi_regs.h
link path=usr/include/ia32/sys/machtypes.h \
    target=../../sys/machtypes.h
file path=usr/include/ia32/sys/privmregs.h
file path=usr/include/ia32/sys/privregs.h
link path=usr/include/ia32/sys/psw.h target=../../sys/psw.h
link path=usr/include/ia32/sys/pte.h target=../../sys/pte.h
link path=usr/include/ia32/sys/reg.h target=../../sys/reg.h
link path=usr/include/ia32/sys/stack.h target=../../sys/stack.h
link path=usr/include/ia32/sys/trap.h target=../../sys/trap.h
link path=usr/include/ia32/sys/traptrace.h \
    target=../../sys/traptrace.h
file path=usr/include/stack_unwind.h
file path=usr/include/sys/bootregs.h
file path=usr/include/sys/debugreg.h
file path=usr/include/sys/dma_engine.h
file path=usr/include/sys/dma_i8237A.h
file path=usr/include/sys/ecppio.h
file path=usr/include/sys/ecppreg.h
file path=usr/include/sys/ecppvar.h
file path=usr/include/sys/firmload.h
file path=usr/include/sys/hypervisor.h
file path=usr/include/sys/i8272A.h
file path=usr/include/sys/iommulib.h
file path=usr/include/sys/mc.h
file path=usr/include/sys/mc_amd.h
file path=usr/include/sys/mc_intel.h
file path=usr/include/sys/mca_amd.h
file path=usr/include/sys/mca_x86.h
file path=usr/include/sys/pcic_reg.h
file path=usr/include/sys/pcic_var.h
file path=usr/include/sys/pic.h
file path=usr/include/sys/pit.h
file path=usr/include/sys/pmem.h
file path=usr/include/sys/privmregs.h
file path=usr/include/sys/prom_emul.h
file path=usr/include/sys/prom_isa.h
file path=usr/include/sys/rtc.h
file path=usr/include/sys/segment.h
file path=usr/include/sys/segments.h
file path=usr/include/sys/sysi86.h
file path=usr/include/sys/traptrace.h
file path=usr/include/sys/tss.h
file path=usr/include/sys/ucode.h
file path=usr/include/sys/ucode_amd.h
file path=usr/include/sys/ucode_intel.h
file path=usr/include/sys/x86_archext.h
file path=usr/include/sys/xen_errno.h
dir path=usr/platform/i86pc group=sys
dir path=usr/platform/i86pc/include
dir path=usr/platform/i86pc/include/sys
file path=usr/platform/i86pc/include/sys/acpidev.h
file path=usr/platform/i86pc/include/sys/amd_iommu.h
file path=usr/platform/i86pc/include/sys/asm_misc.h
file path=usr/platform/i86pc/include/sys/clock.h
file path=usr/platform/i86pc/include/sys/cram.h
file path=usr/platform/i86pc/include/sys/ddi_subrdefs.h
file path=usr/platform/i86pc/include/sys/debug_info.h
file path=usr/platform/i86pc/include/sys/fastboot.h
file path=usr/platform/i86pc/include/sys/hma.h
file path=usr/platform/i86pc/include/sys/mach_mmu.h
file path=usr/platform/i86pc/include/sys/machclock.h
file path=usr/platform/i86pc/include/sys/machcpuvar.h
file path=usr/platform/i86pc/include/sys/machparam.h
file path=usr/platform/i86pc/include/sys/machprivregs.h
file path=usr/platform/i86pc/include/sys/machsystm.h
file path=usr/platform/i86pc/include/sys/machthread.h
file path=usr/platform/i86pc/include/sys/memnode.h
file path=usr/platform/i86pc/include/sys/pc_mmu.h
file path=usr/platform/i86pc/include/sys/psm.h
file path=usr/platform/i86pc/include/sys/psm_defs.h
file path=usr/platform/i86pc/include/sys/psm_modctl.h
file path=usr/platform/i86pc/include/sys/psm_types.h
file path=usr/platform/i86pc/include/sys/rm_platter.h
file path=usr/platform/i86pc/include/sys/sbd_ioctl.h
file path=usr/platform/i86pc/include/sys/smp_impldefs.h
file path=usr/platform/i86pc/include/sys/smt.h
file path=usr/platform/i86pc/include/sys/smt_machcpu.h
file path=usr/platform/i86pc/include/sys/vm_machparam.h
file path=usr/platform/i86pc/include/sys/x_call.h
file path=usr/platform/i86pc/include/sys/xc_levels.h
file path=usr/platform/i86pc/include/sys/xsvc.h
dir path=usr/platform/i86pc/include/vm
file path=usr/platform/i86pc/include/vm/hat_i86.h
file path=usr/platform/i86pc/include/vm/hat_pte.h
file path=usr/platform/i86pc/include/vm/hment.h
file path=usr/platform/i86pc/include/vm/htable.h
file path=usr/platform/i86pc/include/vm/kboot_mmu.h
dir path=usr/platform/i86xpv group=sys
dir path=usr/platform/i86xpv/include
dir path=usr/platform/i86xpv/include/sys
file path=usr/platform/i86xpv/include/sys/balloon.h
file path=usr/platform/i86xpv/include/sys/machprivregs.h
file path=usr/platform/i86xpv/include/sys/xen_mmu.h
file path=usr/platform/i86xpv/include/sys/xpv_impl.h
dir path=usr/platform/i86xpv/include/vm
file path=usr/platform/i86xpv/include/vm/seg_mf.h
dir path=usr/share/src/uts/i86pc
link path=usr/share/src/uts/i86pc/sys \
    target=../../../../platform/i86pc/include/sys
link path=usr/share/src/uts/i86pc/vm \
    target=../../../../platform/i86pc/include/vm
dir path=usr/share/src/uts/i86xpv
link path=usr/share/src/uts/i86xpv/sys \
    target=../../../../platform/i86xpv/include/sys
link path=usr/share/src/uts/i86xpv/vm \
    target=../../../../platform/i86xpv/include/vm
