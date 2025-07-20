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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>
 * Copyright 2014 Pluribus Networks, Inc.
 * Copyright 2016 Nexenta Systems, Inc.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2018 Joyent, Inc.
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/autoconf.h>
#include <sys/avintr.h>
#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/ddi_impldefs.h>
#include <sys/ethernet.h>
#include <sys/instance.h>
#include <sys/kmem.h>
#include <sys/machsystm.h>
#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <sys/atomic.h>
#include <sys/spl.h>
#include <sys/archsystm.h>
#include <vm/seg_kmem.h>
#include <sys/ontrap.h>
#include <sys/fm/protocol.h>
#include <sys/ramdisk.h>
#include <sys/sunndi.h>
#include <sys/vmem.h>
#include <sys/lgrp.h>
#include <sys/mach_intr.h>
#include <vm/hat_aarch64.h>
#include <sys/obpdefs.h>
#include <sys/framebuffer.h>

size_t dma_max_copybuf_size = 0x101000;		/* 1M + 4K */
uint64_t ramdisk_start, ramdisk_end;

static void impl_bus_initialprobe(void);
static void impl_bus_reprobe(void);

static void i_ddi_free_unitintr(unit_intr_t *);

/*
 * We use an AVL tree to store contiguous address allocations made with the
 * kalloca() routine, so that we can return the size to free with kfreea().
 * Note that in the future it would be vastly faster if we could eliminate
 * this lookup by insisting that all callers keep track of their own sizes,
 * just as for kmem_alloc().
 */
struct ctgas {
	avl_node_t ctg_link;
	void *ctg_addr;
	size_t ctg_size;
};

static avl_tree_t ctgtree;

static kmutex_t		ctgmutex;
#define	CTGLOCK()	mutex_enter(&ctgmutex)
#define	CTGUNLOCK()	mutex_exit(&ctgmutex)

uint8_t
i_ddi_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	uint8_t x;
	__asm__ volatile("ldrb %w0, %1" : "=r" (x) : "Q" (*addr) : "memory");
	return (x);
}

uint16_t
i_ddi_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t x;
	__asm__ volatile("ldrh %w0, %1" : "=r" (x) : "Q" (*addr) : "memory");
	return (x);
}

uint32_t
i_ddi_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t x;
	__asm__ volatile("ldr %w0, %1" : "=r" (x) : "Q" (*addr) : "memory");
	return (x);
}

uint64_t
i_ddi_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t x;
	__asm__ volatile("ldr %0, %1" : "=r" (x) : "Q" (*addr) : "memory");
	return (x);
}

void
i_ddi_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	__asm__ volatile("strb %w1, %0" : "=Q" (*addr) : "r"(value) : "memory");
}

void
i_ddi_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	__asm__ volatile("strh %w1, %0" : "=Q" (*addr) : "r"(value) : "memory");
}

void
i_ddi_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	__asm__ volatile("str %w1, %0" : "=Q" (*addr) : "r"(value) : "memory");
}

void
i_ddi_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	__asm__ volatile("str %1, %0" : "=Q" (*addr) : "r"(value) : "memory");
}

void
i_ddi_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldrb %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldrb %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr))
			    : "memory");
}

void
i_ddi_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, const uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr))
			    : "memory");
}

void
i_ddi_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr))
			    : "memory");
}

void
i_ddi_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldr %0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldr %0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr))
			    : "memory");
}

void
i_ddi_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strb %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strb %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

uint16_t
i_ddi_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t x;
	__asm__ volatile("ldrh %w0, %1"
	    : "=r" (x)
	    : "Q" (*addr)
	    : "memory");
	return (__builtin_bswap16(x));
}

uint32_t
i_ddi_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t x;
	__asm__ volatile("ldr %w0, %1"
	    : "=r" (x)
	    : "Q" (*addr)
	    : "memory");
	return (__builtin_bswap32(x));
}

uint64_t
i_ddi_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t x;
	__asm__ volatile("ldr %0, %1"
	    : "=r" (x)
	    : "Q" (*addr)
	    : "memory");
	return (__builtin_bswap64(x));
}

void
i_ddi_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	__asm__ volatile("strh %w1, %0"
	    : "=Q" (*addr)
	    : "r"(__builtin_bswap16(value))
	    : "memory");
}

void
i_ddi_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	__asm__ volatile("str %w1, %0"
	    : "=Q" (*addr)
	    : "r"(__builtin_bswap32(value))
	    : "memory");
}

void
i_ddi_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	__asm__ volatile("str %1, %0"
	    : "=Q" (*addr)
	    : "r"(__builtin_bswap64(value))
	    : "memory");
}

void
i_ddi_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, const uint_t flags)
{
	uint16_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap16(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap16(x);
		}
}

void
i_ddi_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap32(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap32(x);
		}
}

void
i_ddi_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldr %0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap64(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldr %0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap64(x);
		}
}

void
i_ddi_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(__builtin_bswap16(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(__builtin_bswap16(*(host_addr++)))
			    : "memory");
}

void
i_ddi_swap_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(__builtin_bswap32(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(__builtin_bswap32(*(host_addr++)))
			    : "memory");
}

void
i_ddi_swap_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(__builtin_bswap64(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(__builtin_bswap64(*(host_addr++)))
			    : "memory");
}

uint8_t
i_ddi_io_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	uint8_t *io_addr =
	    (uint8_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint8_t x;
	__asm__ volatile("ldrb %w0, %1" : "=r" (x) : "Q" (*io_addr) : "memory");
	return (x);
}

uint16_t
i_ddi_io_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t *io_addr =
	    (uint16_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint16_t x;
	__asm__ volatile("ldrh %w0, %1" : "=r" (x) : "Q" (*io_addr) : "memory");
	return (x);
}

uint32_t
i_ddi_io_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t *io_addr =
	    (uint32_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint32_t x;
	__asm__ volatile("ldr %w0, %1" : "=r" (x) : "Q" (*io_addr) : "memory");
	return (x);
}

uint64_t
i_ddi_io_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t *io_addr =
	    (uint64_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint64_t x;
	__asm__ volatile("ldr %0, %1" : "=r" (x) : "Q" (*io_addr) : "memory");
	return (x);
}

void
i_ddi_io_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	uint8_t *io_addr =
	    (uint8_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("strb %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(value)
	    : "memory");
}

void
i_ddi_io_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	uint16_t *io_addr =
	    (uint16_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("strh %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(value)
	    : "memory");
}

void
i_ddi_io_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	uint32_t *io_addr =
	    (uint32_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("str %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(value)
	    : "memory");
}

void
i_ddi_io_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	uint64_t *io_addr =
	    (uint64_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("str %1, %0"
	    : "=Q" (*io_addr)
	    : "r"(value)
	    : "memory");
}

void
i_ddi_io_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t *io_dev_addr =
	    (uint8_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldrb %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldrb %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr))
			    : "memory");
}

void
i_ddi_io_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, const uint_t flags)
{
	uint16_t *io_dev_addr =
	    (uint16_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr))
			    : "memory");
}

void
i_ddi_io_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *io_dev_addr =
	    (uint32_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr))
			    : "memory");
}

void
i_ddi_io_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *io_dev_addr =
	    (uint64_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldr %0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldr %0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr))
			    : "memory");
}

void
i_ddi_io_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t *io_dev_addr =
	    (uint8_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strb %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strb %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_io_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *io_dev_addr =
	    (uint16_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_io_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *io_dev_addr =
	    (uint32_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_io_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *io_dev_addr =
	    (uint64_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

uint16_t
i_ddi_io_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t *io_addr =
	    (uint16_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint16_t x;
	__asm__ volatile("ldrh %w0, %1"
	    : "=r" (x)
	    : "Q" (*io_addr)
	    : "memory");
	return (__builtin_bswap16(x));
}

uint32_t
i_ddi_io_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t *io_addr =
	    (uint32_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint32_t x;
	__asm__ volatile("ldr %w0, %1"
	    : "=r" (x)
	    : "Q" (*io_addr)
	    : "memory");
	return (__builtin_bswap32(x));
}

uint64_t
i_ddi_io_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t *io_addr =
	    (uint64_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint64_t x;
	__asm__ volatile("ldr %0, %1"
	    : "=r" (x)
	    : "Q" (*io_addr)
	    : "memory");
	return (__builtin_bswap64(x));
}

void
i_ddi_io_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	uint16_t *io_addr =
	    (uint16_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("strh %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(__builtin_bswap16(value))
	    : "memory");
}

void
i_ddi_io_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	uint32_t *io_addr =
	    (uint32_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("str %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(__builtin_bswap32(value))
	    : "memory");
}

void
i_ddi_io_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	uint64_t *io_addr =
	    (uint64_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("str %1, %0"
	    : "=Q" (*io_addr)
	    : "r"(__builtin_bswap64(value))
	    : "memory");
}

void
i_ddi_io_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, const uint_t flags)
{
	uint16_t *io_dev_addr =
	    (uint16_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	uint16_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap16(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap16(x);
		}
}

void
i_ddi_io_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *io_dev_addr =
	    (uint32_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	uint32_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap32(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap32(x);
		}
}

void
i_ddi_io_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *io_dev_addr =
	    (uint64_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	uint64_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldr %0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap64(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldr %0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap64(x);
		}
}

void
i_ddi_io_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *io_dev_addr =
	    (uint16_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(__builtin_bswap16(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(__builtin_bswap16(*(host_addr++)))
			    : "memory");
}

void
i_ddi_io_swap_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *io_dev_addr =
	    (uint32_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(__builtin_bswap32(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(__builtin_bswap32(*(host_addr++)))
			    : "memory");
}

void
i_ddi_io_swap_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *io_dev_addr =
	    (uint64_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(__builtin_bswap64(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(__builtin_bswap64(*(host_addr++)))
			    : "memory");
}

static void
i_ddi_caut_getput_ctlops(ddi_acc_impl_t *hp, uint64_t host_addr,
    uint64_t dev_addr, size_t size, size_t repcount,
    uint_t flags, ddi_ctl_enum_t cmd)
{
	peekpoke_ctlops_t	cautacc_ctlops_arg;

	cautacc_ctlops_arg.size = size;
	cautacc_ctlops_arg.dev_addr = dev_addr;
	cautacc_ctlops_arg.host_addr = host_addr;
	cautacc_ctlops_arg.handle = (ddi_acc_handle_t)hp;
	cautacc_ctlops_arg.repcount = repcount;
	cautacc_ctlops_arg.flags = flags;

	(void) ddi_ctlops(hp->ahi_common.ah_dip, hp->ahi_common.ah_dip,
	    cmd, &cautacc_ctlops_arg, NULL);
}

uint8_t
i_ddi_caut_get8(ddi_acc_impl_t *hp, uint8_t *addr)
{
	uint8_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint8_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint16_t
i_ddi_caut_get16(ddi_acc_impl_t *hp, uint16_t *addr)
{
	uint16_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint16_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint32_t
i_ddi_caut_get32(ddi_acc_impl_t *hp, uint32_t *addr)
{
	uint32_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint32_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint64_t
i_ddi_caut_get64(ddi_acc_impl_t *hp, uint64_t *addr)
{
	uint64_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint64_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

void
i_ddi_caut_put8(ddi_acc_impl_t *hp, uint8_t *addr, uint8_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint8_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put16(ddi_acc_impl_t *hp, uint16_t *addr, uint16_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint16_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put32(ddi_acc_impl_t *hp, uint32_t *addr, uint32_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint32_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put64(ddi_acc_impl_t *hp, uint64_t *addr, uint64_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint64_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_get8(ddi_acc_impl_t *hp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint8_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get16(ddi_acc_impl_t *hp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint16_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get32(ddi_acc_impl_t *hp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint32_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get64(ddi_acc_impl_t *hp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint64_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_put8(ddi_acc_impl_t *hp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint8_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put16(ddi_acc_impl_t *hp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint16_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put32(ddi_acc_impl_t *hp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint32_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put64(ddi_acc_impl_t *hp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint64_t), repcount, flags, DDI_CTLOPS_POKE);
}

int
i_ddi_add_softint(ddi_softint_hdl_impl_t *hdlp)
{
	int ret;

	ASSERT(RW_LOCK_HELD(&hdlp->ih_rwlock));

	ret = add_avsoftintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func,
	    DEVI(hdlp->ih_dip)->devi_name, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2);
	return (ret ? DDI_SUCCESS : DDI_FAILURE);
}

void
i_ddi_remove_softint(ddi_softint_hdl_impl_t *hdlp)
{
	ASSERT(RW_LOCK_HELD(&hdlp->ih_rwlock));
	(void) rem_avsoftintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func);
}



/*
 * Return the device node that claims ownership of this interrupt domain
 * following "interrupt-parent" as necessary.  It is returned held.
 *
 * In practical terms, this is the node with the "#interrupt-cells" which
 * applies to `pdip`.  This may be `pdip` itself.
 *
 * As I read the 1275 PCI bindings, I believe we don't need to handle
 * "interrupt-map" here, because we should always have an "#interrupt-cells"
 * on that same node.
 */
static dev_info_t *
i_ddi_interrupt_domain(dev_info_t *pdip)
{
	dev_info_t *ret = NULL;
	dev_info_t *p = pdip;

	ndi_hold_devi(pdip);

	while (p != NULL) {
		phandle_t phandle;

		/* If we have "#interrupt-cells", we're what we want */
		if (ddi_prop_exists(DDI_DEV_T_ANY, p, DDI_PROP_DONTPASS,
		    OBP_INTERRUPT_CELLS) != 0) {
			return (p);
		}

		ndi_rele_devi(p);

		/* If not, if there's an interrupt-parent follow it */
		if ((phandle = ddi_prop_get_int(DDI_DEV_T_ANY, p,
		    DDI_PROP_DONTPASS, OBP_INTERRUPT_PARENT, -1)) != -1) {
			p = e_ddi_nodeid_to_dip(phandle); /* Holds p */
			VERIFY3P(p, !=, NULL);
			continue;
		} else {
			/* If that didn't work, follow the tree itself */
			p = ddi_get_parent(p);
			if (p != NULL)
				ndi_hold_devi(p);
		}
	}

	/* Unreachable */
	return (NULL);
}

/*
 * i_ddi_get_interrupt - Get the interrupt property from the specified device
 * for a given interrupt. Note that this function is called only for the FIXED
 * interrupt type.
 *
 * This is enough to fully specify an interrupt, but is only intelligible by
 * the controller, or someone who checks and knows the bus binding.
 */
static size_t
i_ddi_get_interrupt(dev_info_t *dip, uint_t inumber, int **ret)
{
	int32_t			max_intrs;
	int			*ip;
	uint_t			ip_sz;
	uint32_t		intr = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_INTERRUPTS, &ip, &ip_sz) == DDI_SUCCESS) {
		dev_info_t *id = i_ddi_interrupt_domain(dip);

		VERIFY3P(id, !=, NULL);

		int intr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, id,
		    DDI_PROP_DONTPASS, OBP_INTERRUPT_CELLS, 1);

		ndi_rele_devi(id);

		if (inumber >= ip_sz / intr_cells) {
			return (0); /* failure */
		}

		int *intrp = ip + (inumber * intr_cells);

		*ret = kmem_zalloc(CELLS_1275_TO_BYTES(intr_cells),
		    KM_SLEEP);
		memcpy(*ret, intrp, CELLS_1275_TO_BYTES(intr_cells));

		ddi_prop_free(ip);
		return (intr_cells);
	}

	return (0);
}

/*
 * i_ddi_get_intr_pri - Get the interrupt-priorities property from
 * the specified device. Note that this function is called only for
 * the FIXED interrupt type.
 */
uint32_t
i_ddi_get_intr_pri(dev_info_t *dip, uint_t inumber)
{
	int	*intr_prio_p;
	uint_t	intr_prio_num;
	/* XXXARM: hard-code the default interrupt-priorities property to 5 */
	uint32_t	pri = 5;

	/*
	 * Use the "interrupt-priorities" property to determine the pil/ipl
	 * for the interrupt handler.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_INTERRUPT_PRIORITIES, &intr_prio_p,
	    &intr_prio_num) == DDI_SUCCESS) {
		if (inumber < intr_prio_num)
			pri = intr_prio_p[inumber];
		ddi_prop_free(intr_prio_p);
	}

	return (pri);
}

static int
process_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int		ret = DDI_FAILURE;

	if (NEXUS_HAS_INTR_OP(pdip)) {
		ret = (*(DEVI(pdip)->devi_ops->devo_bus_ops->
		    bus_intr_op)) (pdip, rdip, op, hdlp, result);
	} else {
		cmn_err(CE_WARN, "Failed to process interrupt "
		    "for %s%d due to down-rev nexus driver %s%d",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    ddi_get_name(pdip), ddi_get_instance(pdip));
	}

	return (ret);
}

extern void (*setsoftint)(int, struct av_softinfo *);
extern boolean_t av_check_softint_pending(struct av_softinfo *, boolean_t);

int
i_ddi_trigger_softint(ddi_softint_hdl_impl_t *hdlp, void *arg2)
{
	ASSERT(RW_LOCK_HELD(&hdlp->ih_rwlock));

	if (av_check_softint_pending(hdlp->ih_pending, B_FALSE))
		return (DDI_EPENDING);

	update_avsoftintr_args((void *)hdlp, hdlp->ih_pri, arg2);

	(*setsoftint)(hdlp->ih_pri, hdlp->ih_pending);
	return (DDI_SUCCESS);
}

int
i_ddi_set_softint_pri(ddi_softint_hdl_impl_t *hdlp, uint_t old_pri)
{
	int ret;

	ASSERT(RW_LOCK_HELD(&hdlp->ih_rwlock));

	if (av_check_softint_pending(hdlp->ih_pending, B_TRUE))
		return (DDI_FAILURE);

	ret = av_softint_movepri((void *)hdlp, old_pri);
	return (ret ? DDI_SUCCESS : DDI_FAILURE);
}

void
i_ddi_alloc_intr_phdl(ddi_intr_handle_impl_t *hdlp)
{
	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));
	hdlp->ih_private = kmem_zalloc(sizeof (ihdl_plat_t), KM_SLEEP);
}

void
i_ddi_free_intr_phdl(ddi_intr_handle_impl_t *hdlp)
{
	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	ihdl_plat_t *priv = hdlp->ih_private;

	if (priv != NULL) {
		i_ddi_free_unitintr(priv->ip_unitintr);
	}

	kmem_free(hdlp->ih_private, sizeof (ihdl_plat_t));
	hdlp->ih_private = NULL;
}

/*
 * Pull a unitaddress for dip from reg[0], and put it in *out.
 * Returns the actual number of address cells, or -1 on failure
 */
static int
i_ddi_unitaddr(dev_info_t *dip, uint_t *out, size_t out_cells)
{
	int *reg;
	uint_t reg_cells;

	int addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);

	if (addr_cells == 0)
		return (0);

	if (addr_cells > out_cells)
		return (-1);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_REG, &reg, &reg_cells) != DDI_SUCCESS) {
		/*
		 * If we have address cells, but no registers to fill them
		 * from.  Fill with 0.  This feels like the wrong thing to do
		 * but for eg QEMU,virt has a / node with #address-cells=2 but
		 * no registers, and the / node has an interrupt-parent, and
		 * so takes part in mapping.
		 */
		memset(out, 0, CELLS_1275_TO_BYTES(out_cells));
	} else {
		memcpy(out, reg, CELLS_1275_TO_BYTES(out_cells));
		ddi_prop_free(reg);
	}

	return (addr_cells);
}

static unit_intr_t *
i_ddi_alloc_unitintr(size_t addrcells, size_t intrcells)
{
	size_t nelems = addrcells + intrcells;

	ASSERT3U(intrcells, !=, 0);
	ASSERT3U(nelems, >=, intrcells);

	unit_intr_t *ui = kmem_zalloc(sizeof (*ui) +
	    CELLS_1275_TO_BYTES(nelems), KM_SLEEP);
	ui->ui_nelems = nelems;
	ui->ui_addrcells = addrcells;
	ui->ui_intrcells = intrcells;

	return (ui);
}

static void
i_ddi_free_unitintr(unit_intr_t *ui)
{
	if (ui == NULL)
		return;

	kmem_free(ui, sizeof (*ui) + CELLS_1275_TO_BYTES(ui->ui_nelems));
}

/*
 * Update ui to have the address of dip, the interrupt portion is unchanged
 */
static unit_intr_t *
i_ddi_update_unitintr_unit(unit_intr_t *ui, dev_info_t *dip)
{
	dev_info_t *idom = i_ddi_interrupt_domain(dip);

	int new_intr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, idom,
	    DDI_PROP_DONTPASS, OBP_INTERRUPT_CELLS, 1);
	int new_addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);

	ndi_rele_devi(idom);

	VERIFY3U(new_intr_cells, ==, ui->ui_intrcells);

	if (new_addr_cells == ui->ui_addrcells) {
		if (i_ddi_unitaddr(dip, ui->ui_v, ui->ui_addrcells) !=
		    ui->ui_addrcells) {
			ndi_rele_devi(dip);
			dev_err(dip, CE_PANIC, "couldn't interpret "
			    "unit address");
			return (NULL);	/* Unreachable */
		}

		return (ui);
	} else {
		/* Different size, we need a replacement */
		unit_intr_t *new = i_ddi_alloc_unitintr(new_addr_cells,
		    new_intr_cells);

		if (i_ddi_unitaddr(dip, new->ui_v, new->ui_addrcells)
		    != new->ui_addrcells) {
			ndi_rele_devi(dip);
			dev_err(dip, CE_PANIC, "couldn't interpret "
			    "unit address");
			return (NULL);	/* Unreachable */
		}

		/* Use the same interrupt specifier as before. */
		memcpy(new->ui_v + new->ui_addrcells,
		    ui->ui_v + ui->ui_addrcells,
		    CELLS_1275_TO_BYTES(new->ui_intrcells));
		i_ddi_free_unitintr(ui);
		return (new);
	}
}

static unit_intr_t *
i_ddi_unitintr(dev_info_t *dip, uint_t inum)
{
	unit_intr_t *ui;
	int addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);

	int *intrs = NULL;
	int intr_cells = i_ddi_get_interrupt(dip, inum, &intrs);

	VERIFY3U(intr_cells, >, 0);

	ui = i_ddi_alloc_unitintr(addr_cells, intr_cells);
	if (i_ddi_unitaddr(dip, ui->ui_v, addr_cells) != addr_cells) {
		dev_err(dip, CE_PANIC, "couldn't interpret unit address");
		return (NULL);	/* Unreachable */
	}

	memcpy(ui->ui_v + ui->ui_addrcells, intrs,
	    CELLS_1275_TO_BYTES(ui->ui_intrcells));
	kmem_free(intrs, CELLS_1275_TO_BYTES(intr_cells));

	return (ui);
}

/*
 * map hdlp through dip following "interrupt-parent" or the device parent.
 */
static dev_info_t *
map_interrupt_parent(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp)
{
	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	ihdl_plat_t *priv = (ihdl_plat_t *)hdlp->ih_private;
	VERIFY3P(priv, !=, NULL);
	VERIFY3P(priv->ip_unitintr, !=, NULL);

	phandle_t ip = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_INTERRUPT_PARENT, -1);

	/*
	 * If we have no explicit interrupt-parent and we're an
	 * interrupt-controller, we're done.
	 */
	if ((ip == -1) && ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_INTERRUPT_CONTROLLER)) {
		return (NULL);
	}

	/*
	 * Otherwise follow "interrupt-parent" if set, or the tree if not and
	 * update the unit interrupt descriptor.
	 */
	dev_info_t *ipdip = NULL;
	if (ip != -1) {
		ipdip = e_ddi_nodeid_to_dip(ip);
	} else {
		ipdip = ddi_get_parent(dip);
		VERIFY3P(ipdip, !=, NULL);
		ndi_hold_devi(ipdip);
	}

	priv->ip_unitintr = i_ddi_update_unitintr_unit(priv->ip_unitintr, dip);

	return (ipdip);
}

/*
 * map an interrupt through a devicetree/1275 "interrupt-map" property.
 * see: https://www.devicetree.org/open-firmware/practice/imap/imap0_9d.html
 */
static dev_info_t *
map_interrupt_map(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp)
{
	int *intr_map, *intr_mask;
	uint_t intr_map_sz, intr_mask_sz;

	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	/*
	 * By definition, if we have an interrupt-map we're the interrupt
	 * domain
	 */
#ifdef DEBUG
	dev_info_t *idom = i_ddi_interrupt_domain(dip);
	ASSERT3P(idom, ==, dip);
	ndi_rele_devi(idom);
#endif

	ihdl_plat_t *priv = (ihdl_plat_t *)hdlp->ih_private;

	VERIFY3P(priv, !=, NULL);
	VERIFY3P(priv->ip_unitintr, !=, NULL);

	unit_intr_t *ui = priv->ip_unitintr;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_INTERRUPT_MAP, &intr_map,
	    &intr_map_sz) != DDI_SUCCESS) {
		dev_err(dip, CE_PANIC, "searching non-existent "
		    "interrupt map");
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_INTERRUPT_MAP_MASK,
	    &intr_mask, &intr_mask_sz) != DDI_SUCCESS) {
		/*
		 * If we have no mask, convention is that it is all 0.  The
		 * SPARC implementation instead unilaterally declared this
		 * invalid.
		 */
		intr_mask_sz = 0;
	}

	VERIFY((intr_mask_sz == ui->ui_nelems) ||
	    (intr_mask_sz == 0));

	/* Apply the mask if we have one */
	for (int i = 0; i < intr_mask_sz; i++) {
		ui->ui_v[i] &= intr_mask[i];
	}

	/*
	 * The effective stride through the table, the width
	 * of the row we're reading as we're reading it.
	 */
	int effective_stride = 0;
	for (int *scan = intr_map;
	    scan < intr_map + intr_map_sz;
	    scan += effective_stride) {
		dev_info_t *parent;

		/*
		 * Our stride is at least as far as our own
		 * unit-interrupt specifier plus the parent
		 * phandle
		 */
		effective_stride = ui->ui_nelems + 1;

		parent = e_ddi_nodeid_to_dip(scan[effective_stride - 1]);
		VERIFY3P(parent, !=, NULL);

#ifdef DEBUG
		dev_info_t *idom = i_ddi_interrupt_domain(parent);
		ASSERT3P(idom, ==, parent);
		ndi_rele_devi(idom);
#endif

		int par_addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY,
		    parent, DDI_PROP_DONTPASS,
		    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);
		int par_intr_cells = ddi_prop_get_int(DDI_DEV_T_ANY,
		    parent, DDI_PROP_DONTPASS, OBP_INTERRUPT_CELLS,
		    1);

		if (memcmp(ui->ui_v, scan,
		    CELLS_1275_TO_BYTES(ui->ui_nelems)) == 0) {
			/*
			 * Re-create `ui` in terms of the parent information
			 * in the table
			 */
			i_ddi_free_unitintr(ui);
			ui = i_ddi_alloc_unitintr(par_addr_cells,
			    par_intr_cells);
			memcpy(ui->ui_v, scan + effective_stride,
			    CELLS_1275_TO_BYTES(ui->ui_nelems));
			priv->ip_unitintr = ui;

			ddi_prop_free(intr_map);
			if (intr_mask != NULL)
				ddi_prop_free(intr_mask);

			/* This was held by e_ddi_nodeid_to_dip() */
			return (parent);
		}

		effective_stride += par_addr_cells + par_intr_cells;
	}

	/*
	 * If there's an interrupt-map and we have not found our entry in it,
	 * something is very wrong and further progress will only be worse
	 */
	dev_err(dip, CE_PANIC, "interrupt-map entry not found");

	ddi_prop_free(intr_map);
	if (intr_mask != NULL)
		ddi_prop_free(intr_mask);

	return (NULL);
}

/*
 * Map the interrupt described by hdlp, through the device in dip, updating
 * hdlp and returning the new interrupt domain.
 *
 * This is how we take a device interrupt and transform it, ultimately, into
 * an interrupt for the appropriate interrupt controller.
 *
 * The returned dip (the interrupt domain) is returned held.
 */
static dev_info_t *
map_interrupt(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp)
{
	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	ihdl_plat_t *priv = (ihdl_plat_t *)hdlp->ih_private;
	VERIFY3P(priv, !=, NULL);

	/*
	 * Our first pass only, initialize the unitintr for the rest
	 * of the work.  If we already have one stashed in the handle, keep
	 * using it, we're recursing up the interrupt tree.
	 *
	 * This outlives mapping and is used to communicate vector and sense
	 * information to the interrupt controller.  It is cleaned up in
	 * i_ddi_intr_ops().
	 */
	if (priv->ip_unitintr == NULL)
		priv->ip_unitintr = i_ddi_unitintr(dip, hdlp->ih_inum);

	dev_info_t *par = NULL;

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_INTERRUPT_MAP)) {
		par = map_interrupt_map(dip, hdlp);
	} else {
		par = map_interrupt_parent(dip, hdlp);
	}

	if (i_ddi_attach_node_hierarchy(par) != DDI_SUCCESS) {
		ndi_rele_devi(par);
		dev_err(par, CE_PANIC, "no driver for interrupt "
		    "controller?");
		return (NULL); /* Unreachable */
	}

	return (par);
}

int
i_ddi_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void * result)
{
	dev_info_t	*pdip = ddi_get_parent(dip);
	int		ret = DDI_FAILURE;

	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	/*
	 * If we don't know the interrupt type yet, we can't tell which path
	 * it must take to an interrupt controller.
	 *
	 * These are, by definition, in the group of verbs that operate on the
	 * system, and are passed up the device tree.
	 *
	 * It is in fact, true that we cannot try to map an interrupt that
	 * has not been configured even this far.
	 */
	if (hdlp->ih_type == DDI_INTR_TYPE_UNKNOWN) {
		if (pdip == NULL)
			return (DDI_FAILURE);

		return (process_intr_ops(pdip, rdip, op, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		if (hdlp->ih_pri == 0)
			hdlp->ih_pri = i_ddi_get_intr_pri(rdip, hdlp->ih_inum);
	}

	/*
	 * These operations are verbs specific per-interrupt controller (or,
	 * in fact, a hierarchy of them in the case of, for eg, GPIO), map the
	 * handle onto its interrupt parent and call it to perform any
	 * necessary programming.
	 *
	 * Other operations are verbs acting upon the system itself, and
	 * follow the device tree to the root nexus.
	 */
	switch (op) {
	case DDI_INTROP_ADDISR:
	case DDI_INTROP_REMISR:
	case DDI_INTROP_GETTARGET:
	case DDI_INTROP_SETTARGET:
	case DDI_INTROP_ENABLE:
	case DDI_INTROP_DISABLE:
	case DDI_INTROP_BLOCKENABLE:
	case DDI_INTROP_BLOCKDISABLE:
		/*
		 * Try and determine our interrupt domain and possibly an
		 * interrupt translation
		 */
		if ((pdip = map_interrupt(dip, hdlp)) == NULL) {
			dev_err(dip, CE_WARN, "could not find interrupt "
			    "domain");
			goto done;
		}
	}

	ret = process_intr_ops(pdip, rdip, op, hdlp, result);

done:
	/*
	 * Operations which were mapped toward an interrupt controller must
	 * now release their hold on the controller.
	 */
	switch (op) {
	case DDI_INTROP_ADDISR:
	case DDI_INTROP_REMISR:
	case DDI_INTROP_ENABLE:
	case DDI_INTROP_DISABLE:
	case DDI_INTROP_BLOCKENABLE:
	case DDI_INTROP_BLOCKDISABLE:
		if (pdip != NULL)
			ndi_rele_devi(pdip);
		break;
	}

	/*
	 * The vector, and the unit interrupt descriptor in the platform
	 * private data are specific to a single pass of interrupt mapping
	 * and must be cleared on the way back down the tree.
	 */
	hdlp->ih_vector = 0;

	ihdl_plat_t *priv = hdlp->ih_private;
	if (priv != NULL) {
		i_ddi_free_unitintr(priv->ip_unitintr);
		priv->ip_unitintr = NULL;
	}

	return (ret);
}

int
i_ddi_get_intx_nintrs(dev_info_t *dip)
{
	uint_t intrlen;
	int intr_sz;
	int *ip;
	int ret = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_INTERRUPTS, &ip, &intrlen) == DDI_SUCCESS) {
		dev_info_t *intrd = i_ddi_interrupt_domain(dip);

		VERIFY3P(intrd, !=, NULL);

		intr_sz = ddi_prop_get_int(DDI_DEV_T_ANY, intrd,
		    DDI_PROP_DONTPASS, OBP_INTERRUPT_CELLS, -1);

		ndi_rele_devi(intrd);

		VERIFY3S(intr_sz, !=, -1);

		ret = intrlen / intr_sz;

		ddi_prop_free(ip);
	}

	return (ret);
}

void
i_ddi_intr_redist_all_cpus()
{
	/* nothing (yet) */
}

uint_t
impl_assign_instance(dev_info_t *dip)
{
	return ((uint_t)-1);
}

int
impl_keep_instance(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

int
impl_free_instance(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

int
impl_check_cpu(dev_info_t *devi)
{
	return (DDI_SUCCESS);
}

void
impl_fix_props(dev_info_t *dip, dev_info_t *ch_dip, char *name,
    int len, caddr_t buffer)
{
	/* nothing (yet) */
}

/*
 * We're prepared for either 2 or 1 address cells and 2 or 1 size cells.
 *
 * The derived address is expected to fit into 56 bits (the LPA2 maximum), as
 * is the derived size.
 *
 * We warn separately for >56-bit values (exceeding architectural maximums
 * for physical address-space) and >48-bit sizes (exceeding current
 * illumos limitations for physical address-space).
 */
static int
impl_xlate_regs(dev_info_t *child, uint32_t *in, size_t in_len,
    struct ddi_parent_private_data *pdptr)
{
	struct regspec *rp = NULL;
	dev_info_t *parent = NULL;

	parent = ddi_get_parent(child);

	if (parent == NULL) {
		return (-1);
	}

	int parent_addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
	    0, OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);
	int parent_size_cells = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
	    0, OBP_SIZE_CELLS, OBP_DEFAULT_SIZE_CELLS);

	if (parent_size_cells < 1 || parent_size_cells > 2) {
		dev_err(child, CE_WARN, "regspec: unsupported size cells %d",
		    parent_size_cells);
		return (1);
	}

	if (parent_addr_cells < 1 || parent_addr_cells > 2) {
		dev_err(child, CE_WARN, "regspec: unsupported addr cells %d",
		    parent_addr_cells);
		return (1);
	}

	int reg_size = parent_addr_cells + parent_size_cells;
	ASSERT(in_len % reg_size == 0);
	int nregs = in_len / reg_size;

	if (nregs > 0) {
		rp = pdptr->par_reg =
		    kmem_zalloc(nregs * sizeof (struct regspec), KM_SLEEP);
		pdptr->par_nreg = nregs;

		for (int i = 0; i < nregs; i++, rp++) {
			uint64_t addr = 0;
			uint64_t size = 0;

			for (int j = 0; j < parent_addr_cells; j++) {
				addr = (addr << 32) | in[(reg_size * i) + j];
			}

			for (int j = 0; j < parent_size_cells; j++) {
				size = (size << 32) | in[(reg_size * i) +
				    (parent_addr_cells + j)];
			}

			if ((addr & 0x00fffffffffffffful) != addr) {
				dev_err(child, CE_WARN, "regspec %d needs "
				    ">56bit addressing", i);
			} else if ((addr & 0x0000fffffffffffful) != addr) {
				dev_err(child, CE_WARN, "regspec %d needs "
				    ">48bit addressing", i);
			}

			if ((size & 0x00fffffffffffffful) != size) {
				dev_err(child, CE_WARN, "regspec %d needs "
				    ">56bit sizing", i);
			} else if ((size & 0x0000fffffffffffful) != size) {
				dev_err(child, CE_WARN, "regspec %d needs "
				    ">48bit sizing", i);
			}

			rp->regspec_addr = addr;
			rp->regspec_size = size;
		}
	}

	return (0);
}

/*
 * We're prepared for 3, 2 or 1 address cells and 2 or 1 size cells.
 *
 * We only support 3 address cells when the child format is known to contain
 * the 64-bit address in the last two address cells.
 *
 * The derived addresses are expected to fit into 56 bits (the LPA2 maximum),
 * while the derived sizes are expected to fit into 32 bits.
 *
 * We warn separately for >56-bit addressing (exceeding architectural maximums
 * for physical address-space) and >48-bit addressing (exceeding current
 * illumos limitations for physical address-space).
 */
static int
impl_xlate_ranges(dev_info_t *child, uint32_t *in, size_t in_len,
    struct ddi_parent_private_data *pdptr)
{
	dev_info_t		*pdip;
	struct rangespec	*data;	/* normalised data */
	int			dlen;	/* length of normalised data */
	int			cac;	/* child #address-cells */
	int			pac;	/* parent #address-cells */
	int			csc;	/* child #size-cells */
	int			n;
	int			i;
	uint64_t		caddr;
	uint64_t		paddr;
	uint64_t		size;
	char			**compats;
	int			ncompats;
	int			max_cac = 2;
	static const char	*known_3cell[] = {
		"pciex_root_complex",
	};
	static const int	num_known_3cell =
	    (int)(sizeof (known_3cell) / sizeof (known_3cell[0]));

	/* zero-length input means identity mapping */
	if (in_len == 0) {
		pdptr->par_rng = kmem_zalloc(
		    sizeof (struct rangespec) * 1, KM_SLEEP);
		pdptr->par_nrng = 1;
		return (0);
	}

	VERIFY3P(child, !=, NULL);
	if (child == ddi_root_node())
		return (1);	/* ranges on the root node make no sense */
	pdip = ddi_get_parent(child);
	VERIFY3P(pdip, !=, NULL);

	/*
	 * Explicitly allow children with a known 3 address-cell format, such
	 * as PCIe root complexes. Our code will just shift the extra data off
	 * the end of the child address.
	 */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, OBP_COMPATIBLE,
	    &compats, (uint_t *)&ncompats) == DDI_PROP_SUCCESS) {
		for (n = 0; n < ncompats; ++n) {
			for (i = 0; i < num_known_3cell; ++i) {
				if (strcmp(compats[n], known_3cell[i]) == 0) {
					max_cac = 3;
					break;
				}

				if (max_cac == 3)
					break;
			}
		}

		ddi_prop_free(compats);
	}

	pac = ddi_prop_get_int(DDI_DEV_T_ANY, pdip, 0,
	    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);
	cac = ddi_prop_get_int(DDI_DEV_T_ANY, child, 0,
	    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);
	csc = ddi_prop_get_int(DDI_DEV_T_ANY, child, 0,
	    OBP_SIZE_CELLS, OBP_DEFAULT_SIZE_CELLS);

	if (csc < 1 || csc > 2) {
		dev_err(child, CE_WARN,
		    "rangespec: unsupported child size cells %d", csc);
		return (1);
	}

	if (cac < 1 || cac > max_cac) {
		dev_err(child, CE_WARN,
		    "rangespec: unsupported child addr cells %d", cac);
		return (1);
	}

	if (pac < 1 || pac > 2) {
		dev_err(pdip, CE_WARN,
		    "rangespec: unsupported parent addr cells %d", pac);
		return (1);
	}

	if (in_len % (cac + pac + csc) != 0) {
		dev_err(child, CE_WARN, "invalid ranges data");
		return (1);
	}

	dlen = in_len / (cac + pac + csc);
	data = kmem_zalloc(sizeof (struct rangespec) * dlen, KM_SLEEP);

	for (n = 0; n < dlen; ++n) {
		caddr = paddr = size = 0;

		for (i = 0; i < cac; ++i) {
			caddr <<= 32;
			caddr |= in[((cac + pac + csc) * n) + i];
		}

		for (i = 0; i < pac; ++i) {
			paddr <<= 32;
			paddr |= in[((cac + pac + csc) * n) + cac + i];
		}

		for (i = 0; i < csc; ++i) {
			size <<= 32;
			size |= in[((cac + pac + csc) * n) + cac + pac + i];
		}

		if ((caddr & 0x00fffffffffffffful) != caddr) {
			dev_err(child, CE_WARN, "rangespec %d needs >56bit "
			    "child addressing", n);
		} else if ((caddr & 0x0000fffffffffffful) != caddr) {
			dev_err(child, CE_WARN, "rangespec %d needs >48bit "
			    "child addressing", n);
		}

		if ((paddr & 0x00fffffffffffffful) != paddr) {
			dev_err(child, CE_WARN, "rangespec %d needs >56bit "
			    "parent addressing", n);
		} else if ((paddr & 0x0000fffffffffffful) != paddr) {
			dev_err(child, CE_WARN, "rangespec %d needs >48bit "
			    "parent addressing", n);
		}

		if ((size & 0x00fffffffffffffful) != size) {
			dev_err(child, CE_WARN, "rangespec %d needs >56bit "
			    "sizing", n);
		} else if ((size & 0x0000fffffffffffful) != size) {
			dev_err(child, CE_WARN, "rangespec %d needs >48bit "
			    "sizing", n);
		}

		data[n].rng_coffset = caddr;
		data[n].rng_offset = paddr;
		data[n].rng_size = size;
	}

	pdptr->par_rng = data;
	pdptr->par_nrng = dlen;
	return (0);
}

/*
 * Create a ddi_parent_private_data structure from the ddi properties of
 * the dev_info node.
 *
 * The "reg" and "interrupts" properties are required
 * if the driver wishes to create mappings or field interrupts on behalf
 * of the device.
 *
 * The "reg" property is in a firmware-defined shape and converted into
 * `struct regspec`.
 *
 * The "ranges" property is in a firmware-defined shape and converted into
 * `struct rangespec`.
 */
void
make_ddi_ppd(dev_info_t *child, struct ddi_parent_private_data **ppd)
{
	struct ddi_parent_private_data *pdptr;
	int n;
	int *reg_prop, *rng_prop, *irupts_prop;
	uint_t reg_len, rng_len, irupts_len;
	dev_info_t *parent;
	int parent_addr_cells, parent_size_cells;
	int child_addr_cells, child_size_cells;

	*ppd = pdptr = kmem_zalloc(sizeof (*pdptr), KM_SLEEP);

	/* The root node has no PPD */
	if ((parent = ddi_get_parent(child)) == NULL)
		return;

	/*
	 * Handle the 'reg' property.
	 */
	if (((n = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, OBP_REG, &reg_prop, &reg_len))
	    == DDI_PROP_SUCCESS) && (reg_len != 0)) {
		if (impl_xlate_regs(child, (uint32_t *)reg_prop, reg_len,
		    pdptr) != 0) {
			dev_err(child, CE_WARN, "couldn't initialize regs in "
			    "parent data");
		}

		ddi_prop_free(reg_prop);
	} else {
		if (n != DDI_PROP_NOT_FOUND && n != DDI_PROP_UNDEFINED) {
			dev_err(child, CE_WARN,
			    "unable to read %s property: %d", OBP_REG, n);
		}
	}

	/*
	 * Ranges, of of which we only handle certain shapes.
	 */
	if ((n = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, OBP_RANGES, &rng_prop, &rng_len))
	    == DDI_PROP_SUCCESS) {
		if (impl_xlate_ranges(child, (uint32_t *)rng_prop, rng_len,
		    pdptr) != 0) {
			dev_err(child, CE_WARN, "couldn't initialize ranges in "
			    "parent data");
		}

		if (rng_prop)
			ddi_prop_free(rng_prop);
	} else {
		if (n == DDI_PROP_END_OF_DATA) {
			/* empty ranges property means identity mapping */
			if (impl_xlate_ranges(child, NULL, 0, pdptr) != 0) {
				dev_err(child, CE_WARN, "couldn't initialize "
				    "ranges in parent data");
			}
		} else if (n != DDI_PROP_NOT_FOUND && n != DDI_PROP_UNDEFINED) {
			dev_err(child, CE_WARN,
			    "unable to read %s property: %d", OBP_RANGES, n);
		}
	}
}

static int
impl_sunbus_name_child(dev_info_t *child, char *name, int namelen)
{
	/* Fill in parent-private data */
	if (ddi_get_parent_data(child) == NULL) {
		struct ddi_parent_private_data *pdptr;
		make_ddi_ppd(child, &pdptr);
		ddi_set_parent_data(child, pdptr);
	}

	name[0] = '\0';

	if (i_ddi_pd_getnreg(child) > 0) {
		/*
		 * Note that unlike other platforms, we don't include the
		 * bustype, to match practice in devicetree.
		 */
		(void) snprintf(name, namelen, "%lx",
		    i_ddi_pd_getreg(child, 0)->regspec_addr);
	}

	return (DDI_SUCCESS);
}

int
impl_ddi_sunbus_initchild(dev_info_t *child)
{
	void impl_ddi_sunbus_removechild(dev_info_t *);
	char name[MAXNAMELEN] = {0};

	impl_sunbus_name_child(child, name, MAXNAMELEN);
	ddi_set_name_addr(child, name);

	if ((ndi_dev_is_persistent_node(child) == 0) &&
	    (ndi_merge_node(child, impl_sunbus_name_child) == DDI_SUCCESS)) {
		impl_ddi_sunbus_removechild(child);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
impl_free_ddi_ppd(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;
	size_t n;

	if ((pdptr = ddi_get_parent_data(dip)) == NULL)
		return;

	if ((n = (size_t)pdptr->par_nrng) != 0)
		kmem_free(pdptr->par_rng, n * sizeof (struct rangespec));

	if ((n = pdptr->par_nreg) != 0) {
		kmem_free(pdptr->par_reg, n * sizeof (struct regspec));
	}

	kmem_free(pdptr, sizeof (*pdptr));
	ddi_set_parent_data(dip, NULL);
}

void
impl_ddi_sunbus_removechild(dev_info_t *dip)
{
	impl_free_ddi_ppd(dip);
	ddi_set_name_addr(dip, NULL);
	impl_rem_dev_props(dip);
}

/*
 * Copy name to property_name, since name
 * is in the low address range below kernelbase.
 */
static void
copy_boot_str(const char *boot_str, char *kern_str, int len)
{
	int i = 0;

	while (i < len - 1 && boot_str[i] != '\0') {
		kern_str[i] = boot_str[i];
		i++;
	}

	kern_str[i] = 0;	/* null terminate */
	if (boot_str[i] != '\0')
		cmn_err(CE_WARN,
		    "boot property string is truncated to %s", kern_str);
}

static void
get_boot_properties(void)
{
	extern char hw_provider[];
	dev_info_t *devi;
	char *name;
	int length, flags;
	char property_name[50], property_val[50];
	void *bop_staging_area;

	bop_staging_area = kmem_zalloc(MMU_PAGESIZE, KM_NOSLEEP);

	/*
	 * Import "root" properties from the boot.
	 *
	 * We do this by invoking BOP_NEXTPROP until the list
	 * is completely copied in.
	 */

	devi = ddi_root_node();
	for (name = BOP_NEXTPROP(bootops, "");		/* get first */
	    name;					/* NULL => DONE */
	    name = BOP_NEXTPROP(bootops, name)) {	/* get next */

		/* copy string to memory above kernelbase */
		copy_boot_str(name, property_name, 50);

		/*
		 * Skip vga properties. They will be picked up later
		 * by get_vga_properties.
		 */
		if (strcmp(property_name, "display-edif-block") == 0 ||
		    strcmp(property_name, "display-edif-id") == 0) {
			continue;
		}

		length = BOP_GETPROPLEN(bootops, property_name);
		if (length < 0)
			continue;
		if (length > MMU_PAGESIZE) {
			cmn_err(CE_NOTE,
			    "boot property %s longer than 0x%lx, ignored\n",
			    property_name, MMU_PAGESIZE);
			continue;
		}
		BOP_GETPROP(bootops, property_name, bop_staging_area);
		flags = do_bsys_getproptype(bootops, property_name);

		/*
		 * special properties:
		 * si-machine, si-hw-provider
		 *	goes to kernel data structures.
		 * bios-boot-device and stdout
		 *	goes to hardware property list so it may show up
		 *	in the prtconf -vp output. This is needed by
		 *	Install/Upgrade. Once we fix install upgrade,
		 *	this can be taken out.
		 * XXXARM: It's unclear whether we need bios-boot-device.
		 */
		if (strcmp(name, "si-machine") == 0) {
			(void) strncpy(utsname.machine, bop_staging_area,
			    SYS_NMLN);
			utsname.machine[SYS_NMLN - 1] = '\0';
			continue;
		}
		if (strcmp(name, "si-hw-provider") == 0) {
			(void) strncpy(hw_provider, bop_staging_area, SYS_NMLN);
			hw_provider[SYS_NMLN - 1] = '\0';
			continue;
		}
		if (strcmp(name, "bios-boot-device") == 0) {
			copy_boot_str(bop_staging_area, property_val, 50);
			(void) ndi_prop_update_string(DDI_DEV_T_NONE, devi,
			    property_name, property_val);
			continue;
		}
		if (strcmp(name, "stdout") == 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, devi,
			    property_name, *((int *)bop_staging_area));
			continue;
		}

		/* Boolean property */
		if (length == 0) {
			(void) e_ddi_prop_create(DDI_DEV_T_NONE, devi,
			    DDI_PROP_CANSLEEP, property_name, NULL, 0);
			continue;
		}

		/* Now anything else based on type. */
		switch (flags) {
		case DDI_PROP_TYPE_INT:
			if (length == sizeof (int)) {
				(void) e_ddi_prop_update_int(DDI_DEV_T_NONE,
				    devi, property_name,
				    *((int *)bop_staging_area));
			} else {
				(void) e_ddi_prop_update_int_array(
				    DDI_DEV_T_NONE, devi, property_name,
				    bop_staging_area, length / sizeof (int));
			}
			break;
		case DDI_PROP_TYPE_STRING:
			(void) e_ddi_prop_update_string(DDI_DEV_T_NONE, devi,
			    property_name, bop_staging_area);
			break;
		case DDI_PROP_TYPE_BYTE:
			(void) e_ddi_prop_update_byte_array(DDI_DEV_T_NONE,
			    devi, property_name, bop_staging_area, length);
			break;
		case DDI_PROP_TYPE_INT64:
			if (length == sizeof (int64_t)) {
				(void) e_ddi_prop_update_int64(DDI_DEV_T_NONE,
				    devi, property_name,
				    *((int64_t *)bop_staging_area));
			} else {
				(void) e_ddi_prop_update_int64_array(
				    DDI_DEV_T_NONE, devi, property_name,
				    bop_staging_area,
				    length / sizeof (int64_t));
			}
			break;
		default:
			/* Property type unknown, use old prop interface */
			(void) e_ddi_prop_create(DDI_DEV_T_NONE, devi,
			    DDI_PROP_CANSLEEP, property_name, bop_staging_area,
			    length);
		}
	}

	kmem_free(bop_staging_area, MMU_PAGESIZE);
}

/*
 * Copy console font to kernel memory. The temporary font setup
 * to use font module was done in early console setup, using low
 * memory and data from font module. Now we need to allocate
 * kernel memory and copy data over, so the low memory can be freed.
 * We can have at most one entry in font list from early boot.
 */
static void
get_console_font(void)
{
	struct fontlist *fp, *fl;
	bitmap_data_t *bd;
	struct font *fd, *tmp;
	int i;

	if (STAILQ_EMPTY(&fonts))
		return;

	fl = STAILQ_FIRST(&fonts);
	STAILQ_REMOVE_HEAD(&fonts, font_next);
	fp = kmem_zalloc(sizeof (*fp), KM_SLEEP);
	bd = kmem_zalloc(sizeof (*bd), KM_SLEEP);
	fd = kmem_zalloc(sizeof (*fd), KM_SLEEP);

	fp->font_name = NULL;
	fp->font_flags = FONT_BOOT;
	fp->font_data = bd;

	bd->width = fl->font_data->width;
	bd->height = fl->font_data->height;
	bd->uncompressed_size = fl->font_data->uncompressed_size;
	bd->font = fd;

	tmp = fl->font_data->font;
	fd->vf_width = tmp->vf_width;
	fd->vf_height = tmp->vf_height;
	for (i = 0; i < VFNT_MAPS; i++) {
		if (tmp->vf_map_count[i] == 0)
			continue;
		fd->vf_map_count[i] = tmp->vf_map_count[i];
		fd->vf_map[i] = kmem_alloc(fd->vf_map_count[i] *
		    sizeof (*fd->vf_map[i]), KM_SLEEP);
		bcopy(tmp->vf_map[i], fd->vf_map[i], fd->vf_map_count[i] *
		    sizeof (*fd->vf_map[i]));
	}
	fd->vf_bytes = kmem_alloc(bd->uncompressed_size, KM_SLEEP);
	bcopy(tmp->vf_bytes, fd->vf_bytes, bd->uncompressed_size);
	STAILQ_INSERT_HEAD(&fonts, fp, font_next);
}

/*
 * If loader(7) has passed us a UEFI framebuffer we create a node for the
 * efifb driver to attach to.
 *
 * Must be called after the DDI root node has been created.
 */
static void
create_efifb(void)
{
	dev_info_t *xdip;
	int err;
	char *compatible[2];
	char compat0[] = "efifb";
	char compat1[] = "vgatext";

	if (fb_info.paddr == 0 ||
	    (fb_info.fb_type != FB_TYPE_INDEXED &&
	    fb_info.fb_type != FB_TYPE_RGB))
		return;

	ndi_devi_alloc_sleep(ddi_root_node(), "efifb",
	    (pnode_t)DEVI_SID_NODEID, &xdip);

	compatible[0] = compat0;
	compatible[1] = compat1;
	err = ndi_prop_update_string_array(DDI_DEV_T_NONE, xdip,
	    "compatible", compatible, 2);
	VERIFY3U(err, ==, DDI_SUCCESS);

	err = ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
	    OBP_DEVICETYPE, OBP_DISPLAY);
	VERIFY3U(err, ==, DDI_SUCCESS);

	err = ndi_devi_bind_driver(xdip, 0);
	VERIFY3U(err, ==, NDI_SUCCESS);
}

void
impl_setup_ddi(void)
{
	dev_info_t *xdip;
	rd_existing_t rd_mem_prop;
	int err;

	ndi_devi_alloc_sleep(
	    ddi_root_node(), "ramdisk", (pnode_t)DEVI_SID_NODEID, &xdip);
	(void) BOP_GETPROP(bootops, "ramdisk_start", (void *)&ramdisk_start);
	(void) BOP_GETPROP(bootops, "ramdisk_end", (void *)&ramdisk_end);

	rd_mem_prop.phys = ramdisk_start;
	rd_mem_prop.size = ramdisk_end - ramdisk_start + 1;

	ndi_prop_update_byte_array(DDI_DEV_T_NONE, xdip, RD_EXISTING_PROP_NAME,
	    (uchar_t *)&rd_mem_prop, sizeof (rd_mem_prop));
	err = ndi_devi_bind_driver(xdip, 0);
	ASSERT(err == 0);

	/*
	 * Read in the properties from the boot.
	 */
	get_boot_properties();

	/*
	 * Copy console font if provided by boot.
	 */
	get_console_font();

	/*
	 * Create the UEFI framebuffer device tree node if appropriate.
	 */
	create_efifb();

	/* do bus dependent probes. */
	impl_bus_initialprobe();
}


/*
 * DDI Memory/DMA
 */

/*
 * Support for allocating DMAable memory to implement
 * ddi_dma_mem_alloc(9F) interface.
 */

#define	KA_ALIGN_SHIFT	7
#define	KA_ALIGN	(1 << KA_ALIGN_SHIFT)
#define	KA_NCACHE	(PAGESHIFT + 1 - KA_ALIGN_SHIFT)

/*
 * Dummy DMA attribute template for kmem_io[].kmem_io_attr.  We only
 * care about addr_lo, addr_hi, and align.  addr_hi will be dynamically set.
 */

static ddi_dma_attr_t kmem_io_attr = {
	DMA_ATTR_V0,
	0x0000000000000000ULL,		/* dma_attr_addr_lo */
	0x0000000000000000ULL,		/* dma_attr_addr_hi */
	0x00ffffff,
	0x1000,				/* dma_attr_align */
	1, 1, 0xffffffffULL, 0xffffffffULL, 0x1, 1, 0
};

/* kmem io memory ranges and indices */
enum {
	IO_4P, IO_64G, IO_4G, IO_2G, IO_1G, IO_512M,
	IO_256M, IO_128M, IO_64M, IO_32M, IO_16M, MAX_MEM_RANGES
};

static struct {
	vmem_t		*kmem_io_arena;
	kmem_cache_t	*kmem_io_cache[KA_NCACHE];
	ddi_dma_attr_t	kmem_io_attr;
} kmem_io[MAX_MEM_RANGES];

static int kmem_io_idx;		/* index of first populated kmem_io[] */

static page_t *
page_create_io_wrapper(void *addr, size_t len, int vmflag, void *arg)
{
	extern page_t *page_create_io(vnode_t *, u_offset_t, uint_t,
	    uint_t, struct as *, caddr_t, ddi_dma_attr_t *);

	return (page_create_io(&kvp, (u_offset_t)(uintptr_t)addr, len,
	    PG_EXCL | ((vmflag & VM_NOSLEEP) ? 0 : PG_WAIT), &kas, addr, arg));
}

static void *
segkmem_alloc_io_4P(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_4P].kmem_io_attr));
}

static void *
segkmem_alloc_io_64G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_64G].kmem_io_attr));
}

static void *
segkmem_alloc_io_4G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_4G].kmem_io_attr));
}

static void *
segkmem_alloc_io_2G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_2G].kmem_io_attr));
}

static void *
segkmem_alloc_io_1G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_1G].kmem_io_attr));
}

static void *
segkmem_alloc_io_512M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_512M].kmem_io_attr));
}

static void *
segkmem_alloc_io_256M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_256M].kmem_io_attr));
}

static void *
segkmem_alloc_io_128M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_128M].kmem_io_attr));
}

static void *
segkmem_alloc_io_64M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_64M].kmem_io_attr));
}

static void *
segkmem_alloc_io_32M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_32M].kmem_io_attr));
}

static void *
segkmem_alloc_io_16M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_16M].kmem_io_attr));
}

struct {
	uint64_t	io_limit;
	char		*io_name;
	void		*(*io_alloc)(vmem_t *, size_t, int);
	int		io_initial;	/* kmem_io_init during startup */
} io_arena_params[MAX_MEM_RANGES] = {
	{0x000fffffffffffffULL,	"kmem_io_4P",	segkmem_alloc_io_4P,	1},
	{0x0000000fffffffffULL,	"kmem_io_64G",	segkmem_alloc_io_64G,	0},
	{0x00000000ffffffffULL,	"kmem_io_4G",	segkmem_alloc_io_4G,	1},
	{0x000000007fffffffULL,	"kmem_io_2G",	segkmem_alloc_io_2G,	1},
	{0x000000003fffffffULL,	"kmem_io_1G",	segkmem_alloc_io_1G,	0},
	{0x000000001fffffffULL,	"kmem_io_512M",	segkmem_alloc_io_512M,	0},
	{0x000000000fffffffULL,	"kmem_io_256M",	segkmem_alloc_io_256M,	0},
	{0x0000000007ffffffULL,	"kmem_io_128M",	segkmem_alloc_io_128M,	0},
	{0x0000000003ffffffULL,	"kmem_io_64M",	segkmem_alloc_io_64M,	0},
	{0x0000000001ffffffULL,	"kmem_io_32M",	segkmem_alloc_io_32M,	0},
	{0x0000000000ffffffULL,	"kmem_io_16M",	segkmem_alloc_io_16M,	1}
};

void
kmem_io_init(int a)
{
	int	c;
	char name[40];

	kmem_io[a].kmem_io_arena = vmem_create(io_arena_params[a].io_name,
	    NULL, 0, PAGESIZE, io_arena_params[a].io_alloc,
	    segkmem_free,
	    heap_arena, 0, VM_SLEEP);

	for (c = 0; c < KA_NCACHE; c++) {
		size_t size = KA_ALIGN << c;
		(void) sprintf(name, "%s_%lu",
		    io_arena_params[a].io_name, size);
		kmem_io[a].kmem_io_cache[c] = kmem_cache_create(name,
		    size, size, NULL, NULL, NULL, NULL,
		    kmem_io[a].kmem_io_arena, 0);
	}
}

/*
 * Return the index of the highest memory range for addr.
 */
static int
kmem_io_index(uint64_t addr)
{
	int n;

	for (n = kmem_io_idx; n < MAX_MEM_RANGES; n++) {
		if (kmem_io[n].kmem_io_attr.dma_attr_addr_hi <= addr) {
			if (kmem_io[n].kmem_io_arena == NULL)
				kmem_io_init(n);
			return (n);
		}
	}
	panic("kmem_io_index: invalid addr - must be at least 16m");

	/*NOTREACHED*/
}

/*
 * Return the index of the next kmem_io populated memory range
 * after curindex.
 */
static int
kmem_io_index_next(int curindex)
{
	int n;

	for (n = curindex + 1; n < MAX_MEM_RANGES; n++) {
		if (kmem_io[n].kmem_io_arena)
			return (n);
	}
	return (-1);
}

/*
 * allow kmem to be mapped in with different PTE cache attribute settings.
 * Used by i_ddi_mem_alloc()
 */
int
kmem_override_cache_attrs(caddr_t kva, size_t size, uint_t order)
{
	uint_t hat_flags;
	caddr_t kva_end;
	uint_t hat_attr;
	pfn_t pfn;

	if (hat_getattr(kas.a_hat, kva, &hat_attr) == -1) {
		return (-1);
	}

	hat_attr &= ~HAT_ORDER_MASK;
	hat_attr |= order | HAT_NOSYNC;
	hat_flags = HAT_LOAD_LOCK;

	kva_end = (caddr_t)(((uintptr_t)kva + size + PAGEOFFSET) &
	    (uintptr_t)PAGEMASK);
	kva = (caddr_t)((uintptr_t)kva & (uintptr_t)PAGEMASK);

	while (kva < kva_end) {
		pfn = hat_getpfnum(kas.a_hat, kva);
		hat_unload(kas.a_hat, kva, PAGESIZE, HAT_UNLOAD_UNLOCK);
		hat_devload(kas.a_hat, kva, PAGESIZE, pfn, hat_attr, hat_flags);
		kva += MMU_PAGESIZE;
	}

	return (0);
}

static int
ctgcompare(const void *a1, const void *a2)
{
	/* we just want to compare virtual addresses */
	a1 = ((struct ctgas *)a1)->ctg_addr;
	a2 = ((struct ctgas *)a2)->ctg_addr;
	return (a1 == a2 ? 0 : (a1 < a2 ? -1 : 1));
}

void
ka_init(void)
{
	int a;
	paddr_t maxphysaddr;
	extern pfn_t physmax;

	maxphysaddr = mmu_ptob((paddr_t)physmax) + MMU_PAGEOFFSET;

	ASSERT(maxphysaddr <= io_arena_params[0].io_limit);

	for (a = 0; a < MAX_MEM_RANGES; a++) {
		if (maxphysaddr >= io_arena_params[a + 1].io_limit) {
			if (maxphysaddr > io_arena_params[a + 1].io_limit)
				io_arena_params[a].io_limit = maxphysaddr;
			else
				a++;
			break;
		}
	}
	kmem_io_idx = a;

	for (; a < MAX_MEM_RANGES; a++) {
		kmem_io[a].kmem_io_attr = kmem_io_attr;
		kmem_io[a].kmem_io_attr.dma_attr_addr_hi =
		    io_arena_params[a].io_limit;
		/*
		 * initialize kmem_io[] arena/cache corresponding to
		 * maxphysaddr and to the "common" io memory ranges that
		 * have io_initial set to a non-zero value.
		 */
		if (io_arena_params[a].io_initial || a == kmem_io_idx)
			kmem_io_init(a);
	}

	/* initialize ctgtree */
	avl_create(&ctgtree, ctgcompare, sizeof (struct ctgas),
	    offsetof(struct ctgas, ctg_link));
}

/*
 * put contig address/size
 */
static void *
putctgas(void *addr, size_t size)
{
	struct ctgas    *ctgp;
	if ((ctgp = kmem_zalloc(sizeof (*ctgp), KM_NOSLEEP)) != NULL) {
		ctgp->ctg_addr = addr;
		ctgp->ctg_size = size;
		CTGLOCK();
		avl_add(&ctgtree, ctgp);
		CTGUNLOCK();
	}
	return (ctgp);
}

/*
 * get contig size by addr
 */
static size_t
getctgsz(void *addr)
{
	struct ctgas    *ctgp;
	struct ctgas    find;
	size_t		sz = 0;

	find.ctg_addr = addr;
	CTGLOCK();
	if ((ctgp = avl_find(&ctgtree, &find, NULL)) != NULL) {
		avl_remove(&ctgtree, ctgp);
	}
	CTGUNLOCK();

	if (ctgp != NULL) {
		sz = ctgp->ctg_size;
		kmem_free(ctgp, sizeof (*ctgp));
	}

	return (sz);
}

/*
 * contig_alloc:
 *
 *	allocates contiguous memory to satisfy the 'size' and dma attributes
 *	specified in 'attr'.
 *
 *	Not all of memory need to be physically contiguous if the
 *	scatter-gather list length is greater than 1.
 */

/*ARGSUSED*/
static void *
contig_alloc(size_t size, ddi_dma_attr_t *attr, uintptr_t align, int cansleep)
{
	pgcnt_t		pgcnt = btopr(size);
	size_t		asize = pgcnt * PAGESIZE;
	page_t		*ppl;
	int		pflag;
	void		*addr;

	extern page_t *page_create_io(vnode_t *, u_offset_t, uint_t,
	    uint_t, struct as *, caddr_t, ddi_dma_attr_t *);

	/* segkmem_xalloc */

	if (align <= PAGESIZE)
		addr = vmem_alloc(heap_arena, asize,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	else
		addr = vmem_xalloc(heap_arena, asize, align, 0, 0, NULL, NULL,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	if (addr) {
		ASSERT(!((uintptr_t)addr & (align - 1)));

		if (page_resv(pgcnt, (cansleep) ? KM_SLEEP : KM_NOSLEEP) == 0) {
			vmem_free(heap_arena, addr, asize);
			return (NULL);
		}
		pflag = PG_EXCL;

		if (cansleep)
			pflag |= PG_WAIT;

		/* 4k req gets from freelists rather than pfn search */
		if (pgcnt > 1 || align > PAGESIZE)
			pflag |= PG_PHYSCONTIG;

		ppl = page_create_io(&kvp, (u_offset_t)(uintptr_t)addr,
		    asize, pflag, &kas, (caddr_t)addr, attr);

		if (!ppl) {
			vmem_free(heap_arena, addr, asize);
			page_unresv(pgcnt);
			return (NULL);
		}

		while (ppl != NULL) {
			page_t	*pp = ppl;
			page_sub(&ppl, pp);
			ASSERT(page_iolock_assert(pp));
			page_io_unlock(pp);
			page_downgrade(pp);
			hat_memload(kas.a_hat, (caddr_t)(uintptr_t)pp->p_offset,
			    pp, (PROT_ALL & ~PROT_USER) |
			    HAT_NOSYNC, HAT_LOAD_LOCK);
		}
	}
	return (addr);
}

static void
contig_free(void *addr, size_t size)
{
	pgcnt_t	pgcnt = btopr(size);
	size_t	asize = pgcnt * PAGESIZE;
	caddr_t	a, ea;
	page_t	*pp;

	hat_unload(kas.a_hat, addr, asize, HAT_UNLOAD_UNLOCK);

	for (a = addr, ea = a + asize; a < ea; a += PAGESIZE) {
		pp = page_find(&kvp, (u_offset_t)(uintptr_t)a);
		if (!pp)
			panic("contig_free: contig pp not found");

		if (!page_tryupgrade(pp)) {
			page_unlock(pp);
			pp = page_lookup(&kvp,
			    (u_offset_t)(uintptr_t)a, SE_EXCL);
			if (pp == NULL)
				panic("contig_free: page freed");
		}
		page_destroy(pp, 0);
	}

	page_unresv(pgcnt);
	vmem_free(heap_arena, addr, asize);
}

/*
 * Allocate from the system, aligned on a specific boundary.
 * The alignment, if non-zero, must be a power of 2.
 */
static void *
kalloca(size_t size, size_t align, int cansleep, int physcontig,
    ddi_dma_attr_t *attr)
{
	size_t *addr, *raddr, rsize;
	size_t hdrsize = 4 * sizeof (size_t);	/* must be power of 2 */
	int a, i, c;
	vmem_t *vmp;
	kmem_cache_t *cp = NULL;

	align = MAX(align, hdrsize);
	ASSERT((align & (align - 1)) == 0);

	/*
	 * All of our allocators guarantee 16-byte alignment, so we don't
	 * need to reserve additional space for the header.
	 * To simplify picking the correct kmem_io_cache, we round up to
	 * a multiple of KA_ALIGN.
	 */
	rsize = P2ROUNDUP_TYPED(size + align, KA_ALIGN, size_t);

	if (physcontig && rsize > PAGESIZE) {
		if (addr = contig_alloc(size, attr, align, cansleep)) {
			if (!putctgas(addr, size))
				contig_free(addr, size);
			else
				return (addr);
		}
		return (NULL);
	}

	a = kmem_io_index(attr->dma_attr_addr_hi);

	if (rsize > PAGESIZE) {
		vmp = kmem_io[a].kmem_io_arena;
		raddr = vmem_alloc(vmp, rsize,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	} else {
		c = highbit((rsize >> KA_ALIGN_SHIFT) - 1);
		cp = kmem_io[a].kmem_io_cache[c];
		raddr = kmem_cache_alloc(cp, (cansleep) ? KM_SLEEP :
		    KM_NOSLEEP);
	}

	if (raddr == NULL) {
		int	na;

		ASSERT(cansleep == 0);
		if (rsize > PAGESIZE)
			return (NULL);
		/*
		 * System does not have memory in the requested range.
		 * Try smaller kmem io ranges and larger cache sizes
		 * to see if there might be memory available in
		 * these other caches.
		 */

		for (na = kmem_io_index_next(a); na >= 0;
		    na = kmem_io_index_next(na)) {
			ASSERT(kmem_io[na].kmem_io_arena);
			cp = kmem_io[na].kmem_io_cache[c];
			raddr = kmem_cache_alloc(cp, KM_NOSLEEP);
			if (raddr)
				goto kallocdone;
		}
		/* now try the larger kmem io cache sizes */
		for (na = a; na >= 0; na = kmem_io_index_next(na)) {
			for (i = c + 1; i < KA_NCACHE; i++) {
				cp = kmem_io[na].kmem_io_cache[i];
				raddr = kmem_cache_alloc(cp, KM_NOSLEEP);
				if (raddr)
					goto kallocdone;
			}
		}
		return (NULL);
	}

kallocdone:
	ASSERT(!P2BOUNDARY((uintptr_t)raddr, rsize, PAGESIZE) ||
	    rsize > PAGESIZE);

	addr = (size_t *)P2ROUNDUP((uintptr_t)raddr + hdrsize, align);
	ASSERT((uintptr_t)addr + size - (uintptr_t)raddr <= rsize);

	addr[-4] = (size_t)cp;
	addr[-3] = (size_t)vmp;
	addr[-2] = (size_t)raddr;
	addr[-1] = rsize;

	return (addr);
}

static void
kfreea(void *addr)
{
	size_t		size;

	if (!((uintptr_t)addr & PAGEOFFSET) && (size = getctgsz(addr))) {
		contig_free(addr, size);
	} else {
		size_t	*saddr = addr;
		if (saddr[-4] == 0)
			vmem_free((vmem_t *)saddr[-3], (void *)saddr[-2],
			    saddr[-1]);
		else
			kmem_cache_free((kmem_cache_t *)saddr[-4],
			    (void *)saddr[-2]);
	}
}

/*ARGSUSED*/
void
i_ddi_devacc_to_hatacc(const ddi_device_acc_attr_t *devaccp, uint_t *hataccp)
{
}

/*
 * Check if the specified cache attribute is supported on the platform.
 * This function must be called before i_ddi_cacheattr_to_hatacc().
 */
boolean_t
i_ddi_check_cache_attr(uint_t flags)
{
	/*
	 * The cache attributes are mutually exclusive. Any combination of
	 * the attributes leads to a failure.
	 */
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);
	if ((cache_attr != 0) && !ISP2(cache_attr))
		return (B_FALSE);

	/* All cache attributes are supported on X86/X64 */
	if (cache_attr & (IOMEM_DATA_UNCACHED | IOMEM_DATA_CACHED |
	    IOMEM_DATA_UC_WR_COMBINE))
		return (B_TRUE);

	/* undefined attributes */
	return (B_FALSE);
}

/* set HAT cache attributes from the cache attributes */
void
i_ddi_cacheattr_to_hatacc(uint_t flags, uint_t *hataccp)
{
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);
	static char *fname = "i_ddi_cacheattr_to_hatacc";

	/*
	 * set HAT attrs according to the cache attrs.
	 */
	switch (cache_attr) {
	case IOMEM_DATA_UNCACHED:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= (HAT_STRICTORDER | HAT_PLAT_NOCACHE);
		break;
	case IOMEM_DATA_UC_WR_COMBINE:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= (HAT_MERGING_OK | HAT_PLAT_NOCACHE);
		break;
	case IOMEM_DATA_CACHED:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= (HAT_STORECACHING_OK | HAT_PLAT_NOCACHE);
		break;
	/*
	 * This case must not occur because the cache attribute is scrutinized
	 * before this function is called.
	 */
	default:
		/*
		 * set cacheable to hat attrs.
		 */
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= HAT_STORECACHING_OK;
		cmn_err(CE_WARN, "%s: cache_attr=0x%x is ignored.",
		    fname, cache_attr);
	}
}

struct dma_range {
	uint64_t cpu_addr;
	uint64_t bus_addr;
	size_t size;
};

static int
get_dma_ranges(dev_info_t *dip, struct dma_range **range, int *nrange)
{
	int dma_range_num = 0;
	struct dma_range *dma_ranges = NULL;
	boolean_t *update = NULL;
	int ret = DDI_SUCCESS;

	if (dip == NULL)
		goto err_exit;

	for (;;) {
		int n;
		int *rng_prop;
		uint_t rng_len;
		uint32_t *cells;

		if ((dip = ddi_get_parent(dip)) == NULL)
			break;
		if (dip == ddi_root_node())
			break;

		if ((n = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, OBP_DMA_RANGES, &rng_prop, &rng_len)) !=
		    DDI_PROP_SUCCESS) {
			/* empty dma-ranges means identity mapping */
			if (n == DDI_PROP_END_OF_DATA)
				continue;
			/*
			 * To maintain functional equivalence with the prior
			 * code we just skip nodes with no dma-ranges.
			 */
			if (n == DDI_PROP_NOT_FOUND || n == DDI_PROP_UNDEFINED)
				continue;

			dev_err(dip, CE_WARN,
			    "failed to read %s property", OBP_DMA_RANGES);
			ret = DDI_FAILURE;
			goto err_exit;
		}

		int bus_address_cells;
		int bus_size_cells;
		int parent_address_cells;

		bus_address_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);
		bus_size_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    OBP_SIZE_CELLS, OBP_DEFAULT_SIZE_CELLS);
		parent_address_cells = ddi_prop_get_int(DDI_DEV_T_ANY,
		    ddi_get_parent(dip), 0,
		    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);

		if ((rng_len % (bus_address_cells + bus_size_cells +
		    parent_address_cells)) != 0) {
			dev_err(dip, CE_WARN, "%s property length is "
			    "invalid. bus_address_cells %d, "
			    "parent_address_cells %d, "
			    "bus_size_cells %d, rng_len %d",
			    OBP_DMA_RANGES, bus_address_cells,
			    parent_address_cells, bus_size_cells, rng_len);
			ddi_prop_free(rng_prop);
			ret = DDI_FAILURE;
			goto err_exit;
		}

		int num = rng_len /
		    (bus_address_cells + bus_size_cells + parent_address_cells);
		cells = (uint32_t *)rng_prop;

		boolean_t first = (dma_ranges == NULL);
		if (first) {
			dma_range_num = num;
			dma_ranges = kmem_zalloc(
			    sizeof (struct dma_range) * dma_range_num,
			    KM_SLEEP);
			update = kmem_zalloc(sizeof (boolean_t) * dma_range_num,
			    KM_SLEEP);
		} else {
			memset(update, 0, sizeof (boolean_t) * dma_range_num);
		}

		for (int i = 0; i < num; i++) {
			uint64_t bus_address = 0;
			uint64_t parent_address = 0;
			uint64_t bus_size = 0;

			for (int j = 0; j < bus_address_cells; j++) {
				bus_address <<= 32;
				bus_address += cells[(
				    bus_address_cells + parent_address_cells +
				    bus_size_cells) * i + j];
			}

			for (int j = 0; j < parent_address_cells; j++) {
				parent_address <<= 32;
				parent_address +=
				    cells[(bus_address_cells +
				    parent_address_cells + bus_size_cells) *
				    i + bus_address_cells + j];
			}

			for (int j = 0; j < bus_size_cells; j++) {
				bus_size <<= 32;
				bus_size += cells[(bus_address_cells +
				    parent_address_cells + bus_size_cells) *
				    i + bus_address_cells +
				    parent_address_cells + j];
			}

			if (first) {
				dma_ranges[i].cpu_addr = parent_address;
				dma_ranges[i].bus_addr = bus_address;
				dma_ranges[i].size = bus_size;
				update[i] = B_TRUE;
			} else {
				for (int j = 0; j < dma_range_num; j++) {
					if (bus_address <=
					    dma_ranges[j].cpu_addr &&
					    dma_ranges[j].cpu_addr +
					    dma_ranges[j].size - 1 <=
					    bus_address + bus_size - 1) {
						dma_ranges[j].cpu_addr +=
						    (parent_address -
						    bus_address);
						update[j] = B_TRUE;
						break;
					}
				}
			}
		}

		ddi_prop_free(rng_prop);
		rng_prop = NULL;
		rng_len = 0;

		for (int i = 0; i < dma_range_num; i++) {
			if (!update[i]) {
				dev_err(dip, CE_WARN,
				    "%s property is invalid", OBP_DMA_RANGES);
				ret = DDI_FAILURE;
				goto err_exit;
			}
		}
	}

	*nrange = dma_range_num;
	*range = dma_ranges;
err_exit:
	if (ret != DDI_SUCCESS && dma_ranges) {
		kmem_free(
		    dma_ranges, sizeof (struct dma_range) * dma_range_num);
	}
	if (update) {
		kmem_free(update, sizeof (boolean_t) * dma_range_num);
	}

	return (ret);
}

int
i_ddi_convert_dma_attr(
    ddi_dma_attr_t *dst, dev_info_t *dip, const ddi_dma_attr_t *src)
{
	*dst = *src;

	int dma_range_num = 0;
	struct dma_range *dma_ranges = NULL;
	int ret = get_dma_ranges(dip, &dma_ranges, &dma_range_num);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (dma_range_num > 0) {
		int i;
		for (i = 0; i < dma_range_num; i++) {
			if (dma_ranges[i].bus_addr <= dst->dma_attr_addr_lo &&
			    dst->dma_attr_addr_hi <=
			    dma_ranges[i].bus_addr + dma_ranges[i].size - 1) {
				dst->dma_attr_addr_lo +=
				    (dma_ranges[i].cpu_addr -
				    dma_ranges[i].bus_addr);
				dst->dma_attr_addr_hi +=
				    (dma_ranges[i].cpu_addr -
				    dma_ranges[i].bus_addr);
				break;
			}
		}
		if (i == dma_range_num) {
			cmn_err(CE_WARN,
			    "%s: ddi_dma_attr_t is invalid range", __func__);
			ret = DDI_FAILURE;
		}
	}

	if (dma_ranges) {
		kmem_free(
		    dma_ranges, sizeof (struct dma_range) * dma_range_num);
	}
	return (ret);
}

int
i_ddi_update_dma_attr(dev_info_t *dip, ddi_dma_attr_t *attr)
{
	int dma_range_num = 0;
	struct dma_range *dma_ranges = NULL;
	int ret = get_dma_ranges(dip, &dma_ranges, &dma_range_num);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (dma_range_num > 0) {
		int dma_range_index = 0;
		for (int i = 0; i < dma_range_num; i++) {
			if (dma_ranges[i].cpu_addr <
			    dma_ranges[dma_range_index].cpu_addr) {
				dma_range_index = i;
			}
		}

		attr->dma_attr_addr_lo = dma_ranges[dma_range_index].bus_addr;
		attr->dma_attr_addr_hi =
		    dma_ranges[dma_range_index].bus_addr +
		    dma_ranges[dma_range_index].size - 1;
	} else {
		ret = DDI_FAILURE;
	}

	if (dma_ranges) {
		kmem_free(
		    dma_ranges, sizeof (struct dma_range) * dma_range_num);
	}

	return (ret);
}

/*
 * This should actually be called i_ddi_dma_mem_alloc. There should
 * also be an i_ddi_pio_mem_alloc. i_ddi_dma_mem_alloc should call
 * through the device tree with the DDI_CTLOPS_DMA_ALIGN ctl ops to
 * get alignment requirements for DMA memory. i_ddi_pio_mem_alloc
 * should use DDI_CTLOPS_PIO_ALIGN. Since we only have i_ddi_mem_alloc
 * so far which is used for both, DMA and PIO, we have to use the DMA
 * ctl ops to make everybody happy.
 */
/*ARGSUSED*/
int
i_ddi_mem_alloc(dev_info_t *dip, ddi_dma_attr_t *oattr,
    size_t length, int cansleep, int flags,
    const ddi_device_acc_attr_t *accattrp, caddr_t *kaddrp,
    size_t *real_length, ddi_acc_hdl_t *ap)
{
	caddr_t a;
	int iomin;
	ddi_acc_impl_t *iap;
	int physcontig = 0;
	pgcnt_t npages;
	pgcnt_t minctg;
	uint_t order;
	int e;
	/*
	 * Check legality of arguments
	 */
	if (length == 0 || kaddrp == NULL || oattr == NULL) {
		return (DDI_FAILURE);
	}

	ddi_dma_attr_t data;
	ddi_dma_attr_t *attr = &data;
	if (i_ddi_convert_dma_attr(attr, dip, oattr) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (attr->dma_attr_minxfer == 0 || attr->dma_attr_align == 0 ||
	    !ISP2(attr->dma_attr_align) || !ISP2(attr->dma_attr_minxfer)) {
		return (DDI_FAILURE);
	}

	/*
	 * figure out most restrictive alignment requirement
	 */
	iomin = attr->dma_attr_minxfer;
	iomin = maxbit(iomin, attr->dma_attr_align);
	if (iomin == 0)
		return (DDI_FAILURE);

	ASSERT((iomin & (iomin - 1)) == 0);

	/*
	 * if we allocate memory with IOMEM_DATA_UNCACHED or
	 * IOMEM_DATA_UC_WR_COMBINE, make sure we allocate a page aligned
	 * memory that ends on a page boundry.
	 * Don't want to have to different cache mappings to the same
	 * physical page.
	 */
	if (OVERRIDE_CACHE_ATTR(flags)) {
		iomin = (iomin + MMU_PAGEOFFSET) & MMU_PAGEMASK;
		length = (length + MMU_PAGEOFFSET) & (size_t)MMU_PAGEMASK;
	}

	/*
	 * Determine if we need to satisfy the request for physically
	 * contiguous memory or alignments larger than pagesize.
	 */
	npages = btopr(length + attr->dma_attr_align);
	minctg = howmany(npages, attr->dma_attr_sgllen);

	if (minctg > 1) {
		uint64_t pfnseg = attr->dma_attr_seg >> PAGESHIFT;
		/*
		 * verify that the minimum contig requirement for the
		 * actual length does not cross segment boundary.
		 */
		length = P2ROUNDUP_TYPED(length, attr->dma_attr_minxfer,
		    size_t);
		npages = btopr(length);
		minctg = howmany(npages, attr->dma_attr_sgllen);
		if (minctg > pfnseg + 1)
			return (DDI_FAILURE);
		physcontig = 1;
	} else {
		length = P2ROUNDUP_TYPED(length, iomin, size_t);
	}

	/*
	 * Allocate the requested amount from the system.
	 */
	a = kalloca(length, iomin, cansleep, physcontig, attr);

	if ((*kaddrp = a) == NULL)
		return (DDI_FAILURE);

	/*
	 * if we to modify the cache attributes, go back and muck with the
	 * mappings.
	 */
	if (OVERRIDE_CACHE_ATTR(flags)) {
		order = 0;
		i_ddi_cacheattr_to_hatacc(flags, &order);
		e = kmem_override_cache_attrs(a, length, order);
		if (e != 0) {
			kfreea(a);
			return (DDI_FAILURE);
		}
	}

	if (real_length) {
		*real_length = length;
	}
	if (ap) {
		/*
		 * initialize access handle
		 */
		iap = (ddi_acc_impl_t *)ap->ah_platform_private;
		iap->ahi_acc_attr |= DDI_ACCATTR_CPU_VADDR;
		impl_acc_hdl_init(ap);
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
void
i_ddi_mem_free(caddr_t kaddr, ddi_acc_hdl_t *ap)
{
	if (ap != NULL) {
		/*
		 * if we modified the cache attributes on alloc, go back and
		 * fix them since this memory could be returned to the
		 * general pool.
		 */
		if (OVERRIDE_CACHE_ATTR(ap->ah_xfermodes)) {
			uint_t order = 0;
			int e;
			i_ddi_cacheattr_to_hatacc(IOMEM_DATA_CACHED, &order);
			e = kmem_override_cache_attrs(kaddr, ap->ah_len, order);
			if (e != 0) {
				cmn_err(CE_WARN, "i_ddi_mem_free() failed to "
				    "override cache attrs, memory leaked\n");
				return;
			}
		}
	}
	kfreea(kaddr);
}


void
translate_devid(dev_info_t *dip)
{
}

pfn_t
i_ddi_paddr_to_pfn(paddr_t paddr)
{
	pfn_t pfn;

	pfn = mmu_btop(paddr);

	return (pfn);
}


/*
 * Perform a copy from a memory mapped device (whose devinfo pointer is devi)
 * separately mapped at devaddr in the kernel to a kernel buffer at kaddr.
 */
/*ARGSUSED*/
int
e_ddi_copyfromdev(dev_info_t *devi,
    off_t off, const void *devaddr, void *kaddr, size_t len)
{
	bcopy(devaddr, kaddr, len);
	return (0);
}

/*
 * Perform a copy to a memory mapped device (whose devinfo pointer is devi)
 * separately mapped at devaddr in the kernel from a kernel buffer at kaddr.
 */
/*ARGSUSED*/
int
e_ddi_copytodev(dev_info_t *devi,
    off_t off, const void *kaddr, void *devaddr, size_t len)
{
	bcopy(kaddr, devaddr, len);
	return (0);
}

static int
getlongprop_buf(int id, char *name, char *buf, int maxlen)
{
	int size;

	size = prom_getproplen((pnode_t)id, name);
	if (size <= 0 || (size > maxlen - 1))
		return (-1);

	if (-1 == prom_getprop((pnode_t)id, name, buf))
		return (-1);

	if (strcmp(OBP_NAME, name) == 0) {
		if (buf[size - 1] != '\0') {
			buf[size] = '\0';
			size += 1;
		}
	}

	return (size);
}
/*
 * The "status" property indicates the operational status of a device.
 * If this property is present, the value is a string indicating the
 * status of the device as follows:
 *
 *	"okay"		operational.
 *	"disabled"	not operational.
 *	"fail"		not operational because a fault has been detected,
 *			and it is unlikely that the device will become
 *			operational without repair. no additional details
 *			are available.
 *	"fail-xxx"	not operational because a fault has been detected,
 *			and it is unlikely that the device will become
 *			operational without repair. "xxx" is additional
 *			human-readable information about the particular
 *			fault condition that was detected.
 *
 * The absence of this property means that the operational status is
 * unknown or okay.
 *
 * This routine checks the status property of the specified device node
 * and returns 0 if the operational status indicates failure, and 1 otherwise.
 *
 * The property may exist on plug-in cards the existed before IEEE 1275-1994.
 * And, in that case, the property may not even be a string. So we carefully
 * check for the value "fail" or "disabled", in the beginning of the string,
 * noting the property length.
 */
int
status_okay(int id, char *buf, int buflen)
{
	char status_buf[OBP_MAXPROPNAME];
	char *bufp = buf;
	int len = buflen;
	int proplen;
	static const char *status = OBP_STATUS;
	static const char *fail = "fail";
	static const char *disabled = "disabled";
	int fail_len = (int)strlen(fail);
	int dis_len = (int)strlen(disabled);

	/*
	 * Get the proplen ... if it's smaller than "fail",
	 * or doesn't exist ... then we don't care, since
	 * the value can't begin with the char string "fail" or be "disabled"
	 *
	 * NB: proplen, if it's a string, includes the NULL in the
	 * the size of the property, and fail_len does not.
	 */
	proplen = prom_getproplen((pnode_t)id, (caddr_t)status);
	if (proplen <= fail_len)	/* nonexistant or uninteresting len */
		return (1);

	/*
	 * if a buffer was provided, use it
	 */
	if (buf == NULL || buflen <= 0) {
		bufp = status_buf;
		len = sizeof (status_buf);
	}
	*bufp = '\0';

	/*
	 * Get the property into the buffer, to the extent of the buffer,
	 * and in case the buffer is smaller than the property size,
	 * NULL terminate the buffer. (This handles the case where
	 * a buffer was passed in and the caller wants to print the
	 * value, but the buffer was too small).
	 */
	(void) prom_bounded_getprop((pnode_t)id, (caddr_t)status,
	    (caddr_t)bufp, len);
	*(bufp + len - 1) = '\0';

	/*
	 * If the value begins with the char string "fail" or is "disabled",
	 * then it means the node is failed. We don't care
	 * about any other values.
	 */
	if (strncmp(bufp, fail, fail_len) == 0 ||
	    strncmp(bufp, disabled, dis_len) == 0) {
		return (0);
	}

	return (1);
}

/*
 * Check the status of the device node passed as an argument.
 *
 *	if ((status is OKAY) || (status is DISABLED))
 *		return DDI_SUCCESS
 *	else
 *		print a warning and return DDI_FAILURE
 */
/*ARGSUSED1*/
int
check_status(int id, char *name, dev_info_t *parent)
{
	char status_buf[64];
	char devtype_buf[OBP_MAXPROPNAME];
	int retval = DDI_FAILURE;

	/*
	 * is the status okay?
	 */
	if (status_okay(id, status_buf, sizeof (status_buf)))
		return (DDI_SUCCESS);

	/*
	 * a status property indicating bad memory will be associated
	 * with a node which has a "device_type" property with a value of
	 * "memory-controller". in this situation, return DDI_SUCCESS
	 */
	if (getlongprop_buf(id, OBP_DEVICETYPE, devtype_buf,
	    sizeof (devtype_buf)) > 0) {
		if (strcmp(devtype_buf, "memory-controller") == 0)
			retval = DDI_SUCCESS;
	}

	/*
	 * print the status property information
	 */
	cmn_err(CE_WARN, "status '%s' for '%s'", status_buf, name);
	return (retval);
}

static int
poke_mem(peekpoke_ctlops_t *in_args)
{
	volatile int err = DDI_SUCCESS;
	on_trap_data_t otd;

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		switch (in_args->size) {
		case sizeof (uint8_t):
			*(uint8_t *)(in_args->dev_addr) =
			    *(uint8_t *)in_args->host_addr;
			break;

		case sizeof (uint16_t):
			*(uint16_t *)(in_args->dev_addr) =
			    *(uint16_t *)in_args->host_addr;
			break;

		case sizeof (uint32_t):
			*(uint32_t *)(in_args->dev_addr) =
			    *(uint32_t *)in_args->host_addr;
			break;

		case sizeof (uint64_t):
			*(uint64_t *)(in_args->dev_addr) =
			    *(uint64_t *)in_args->host_addr;
			break;

		default:
			err = DDI_FAILURE;
			break;
		}
	} else
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();

	return (err);
}

static int
peek_mem(peekpoke_ctlops_t *in_args)
{
	volatile int err = DDI_SUCCESS;
	on_trap_data_t otd;

	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		switch (in_args->size) {
		case sizeof (uint8_t):
			*(uint8_t *)in_args->host_addr =
			    *(uint8_t *)in_args->dev_addr;
			break;

		case sizeof (uint16_t):
			*(uint16_t *)in_args->host_addr =
			    *(uint16_t *)in_args->dev_addr;
			break;

		case sizeof (uint32_t):
			*(uint32_t *)in_args->host_addr =
			    *(uint32_t *)in_args->dev_addr;
			break;

		case sizeof (uint64_t):
			*(uint64_t *)in_args->host_addr =
			    *(uint64_t *)in_args->dev_addr;
			break;

		default:
			err = DDI_FAILURE;
			break;
		}
	} else
		err = DDI_FAILURE;

	no_trap();
	return (err);
}

int
peekpoke_mem(ddi_ctl_enum_t cmd, peekpoke_ctlops_t *in_args)
{
	return (cmd == DDI_CTLOPS_PEEK ? peek_mem(in_args) : poke_mem(in_args));
}

uint_t
softlevel1(caddr_t arg1, caddr_t arg2)
{
	softint();
	return (1);
}

void
configure(void)
{
	extern void i_ddi_init_root();

	i_ddi_init_root();
	impl_bus_reprobe();	/* Reprogram devices not set up by firmware */
}

dev_t
getrootdev(void)
{
	/*
	 * Usually rootfs.bo_name is initialized by the
	 * the bootpath property from bootenv.rc, but
	 * defaults to "/ramdisk:a" otherwise.
	 */
	return (ddi_pathname_to_dev_t(rootfs.bo_name));
}

static struct bus_probe {
	struct bus_probe *next;
	void (*probe)(int);
} *bus_probes;

/*
 * impl_bus_initialprobe
 *	Modload the prom simulator, then let it probe to verify existence
 *	and type of PCI support.
 */
static void
impl_bus_initialprobe(void)
{
	struct bus_probe *probe;

	probe = bus_probes;
	while (probe) {
		/* run the probe functions */
		(*probe->probe)(0);
		probe = probe->next;
	}
}

/*
 * impl_bus_reprobe
 *	Reprogram devices not set up by firmware.
 */
static void
impl_bus_reprobe(void)
{
	struct bus_probe *probe;

	probe = bus_probes;
	while (probe) {
		/* run the probe function */
		(*probe->probe)(1);
		probe = probe->next;
	}
}

void
impl_bus_add_probe(void (*func)(int))
{
	struct bus_probe *probe;
	struct bus_probe *lastprobe = NULL;

	probe = kmem_alloc(sizeof (*probe), KM_SLEEP);
	probe->probe = func;
	probe->next = NULL;

	if (!bus_probes) {
		bus_probes = probe;
		return;
	}

	lastprobe = bus_probes;
	while (lastprobe->next)
		lastprobe = lastprobe->next;
	lastprobe->next = probe;
}

/*ARGSUSED*/
void
impl_bus_delete_probe(void (*func)(int))
{
	struct bus_probe *prev = NULL;
	struct bus_probe *probe = bus_probes;

	while (probe) {
		if (probe->probe == func)
			break;
		prev = probe;
		probe = probe->next;
	}

	if (probe == NULL)
		return;

	if (prev)
		prev->next = probe->next;
	else
		bus_probes = probe->next;

	kmem_free(probe, sizeof (struct bus_probe));
}

boolean_t
i_ddi_copybuf_required(ddi_dma_attr_t *attrp)
{
	uint64_t hi_pa;

	hi_pa = ((uint64_t)physmax + 1ull) << PAGESHIFT;
	if (attrp->dma_attr_addr_hi < hi_pa) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

size_t
i_ddi_copybuf_size()
{
	return (dma_max_copybuf_size);
}

/*
 * i_ddi_dma_max()
 *    returns the maximum DMA size which can be performed in a single DMA
 *    window taking into account the devices DMA contraints (attrp), the
 *    maximum copy buffer size (if applicable), and the worse case buffer
 *    fragmentation.
 */
/*ARGSUSED*/
uint32_t
i_ddi_dma_max(dev_info_t *dip, ddi_dma_attr_t *attrp)
{
	uint64_t maxxfer;


	/*
	 * take the min of maxxfer and the the worse case fragementation
	 * (e.g. every cookie <= 1 page)
	 */
	maxxfer = MIN(attrp->dma_attr_maxxfer,
	    ((uint64_t)(attrp->dma_attr_sgllen - 1) << PAGESHIFT));

	/*
	 * If the DMA engine can't reach all off memory, we also need to take
	 * the max size of the copybuf into consideration.
	 */
	if (i_ddi_copybuf_required(attrp)) {
		maxxfer = MIN(i_ddi_copybuf_size(), maxxfer);
	}

	/*
	 * we only return a 32-bit value. Make sure it's not -1. Round to a
	 * page so it won't be mistaken for an error value during debug.
	 */
	if (maxxfer >= 0xFFFFFFFF) {
		maxxfer = 0xFFFFF000;
	}

	/*
	 * make sure the value we return is a whole multiple of the
	 * granlarity.
	 */
	if (attrp->dma_attr_granular > 1) {
		maxxfer = maxxfer - (maxxfer % attrp->dma_attr_granular);
	}

	return ((uint32_t)maxxfer);
}
