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
 * Copyright 2025 Michael van der Westhuizen
 */

/*
 * Boot "syscalls" for the platform bringup UART.
 */

#include <sys/types.h>
#include <sys/null.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>

#include "boot_early_uart.h"

#define	SBSA_UARTDR			0x00
#define	SBSA_UARTFR			0x18
#define	SBSA_UARTFR_TXFE		(1 << 7)
#define	SBSA_UARTFR_TXFF		(1 << 5)
#define	SBSA_UARTFR_RXFE		(1 << 4)

static caddr_t boot_uart_mmio_base = NULL;
static xbi_bsvc_uart_type_t boot_uart_type = XBI_BSVC_UART_NONE;

static void
boot_uart_writereg32(uint32_t reg, uint32_t val)
{
	*((volatile uint32_t *)(boot_uart_mmio_base + reg)) = val;
}

static uint32_t
boot_uart_readreg32(uint32_t reg)
{
	return (*((volatile uint32_t *)(boot_uart_mmio_base + reg)));
}

static void
boot_uart_yield(void)
{
	/*
	 * The "yield" instruction on aarch64 is a no-op when on a non-SMT
	 * CPU (which is basically everything), and the resulting nop is
	 * simply discarded by the frontend (nop is for padding, not for
	 * execution).
	 *
	 * Without the WFxT extension (which gives us the wfet instruction)
	 * the best we can do is an instruction sync barrier.
	 */
	__asm__ volatile("isb sy":::"memory");
}

/*
 * SBSA UART implementation.
 *
 * Arm's SystemReady insists that an SBSA UART is implemented, and most
 * UART implementations are vaguely compatible in that they have compatible
 * data and flags registers for the bits positions we care about.
 */

int
boot_uart_ischar(void)
{
	if (boot_uart_mmio_base == NULL)
		return (0);

	return (!(boot_uart_readreg32(SBSA_UARTFR) & SBSA_UARTFR_RXFE));
}

int
boot_uart_getchar(void)
{
	if (boot_uart_mmio_base == NULL)
		return (0);

	while (!boot_uart_ischar())
		boot_uart_yield();

	return (boot_uart_readreg32(SBSA_UARTDR) & 0xff);
}

void
boot_uart_putchar(int c)
{
	if (boot_uart_mmio_base == NULL)
		return;

	while (boot_uart_readreg32(SBSA_UARTFR) & SBSA_UARTFR_TXFF)
		boot_uart_yield();

	if ((c & 0xff) == '\n')
		boot_uart_putchar('\r');

	boot_uart_writereg32(SBSA_UARTDR, c & 0xff);
	while (!(boot_uart_readreg32(SBSA_UARTFR) & SBSA_UARTFR_TXFE))
		boot_uart_yield();
}

/*
 * Boot services initialisation
 */
void
boot_uart_init(struct xboot_info *xbp)
{
	if (xbp == NULL) {
#if defined(_EARLY_DBG_UART) && _EARLY_DBG_UART > 0
		boot_uart_mmio_base = (caddr_t)(EARLY_UART_PA);
		boot_uart_type = (xbi_bsvc_uart_type_t)(EARLY_UART_TYPE);

		switch (boot_uart_type) {
		case XBI_BSVC_UART_PL011:	/* fallthrough */
		case XBI_BSVC_UART_SBSA2X:	/* fallthrough */
		case XBI_BSVC_UART_SBSA:	/* fallthrough */
		case XBI_BSVC_UART_BCM2835:
			break;
		default:
			boot_uart_mmio_base = NULL;
			boot_uart_type = XBI_BSVC_UART_NONE;
			break;
		}

		if (boot_uart_mmio_base == NULL ||
		    boot_uart_type == XBI_BSVC_UART_NONE) {
			boot_uart_mmio_base = NULL;
			boot_uart_type = XBI_BSVC_UART_NONE;
		}
#endif
		return;
	}

	if (xbp->bi_bsvc_uart_mmio_base == 0) {
#if (defined(EARLY_UART_PA) && (EARLY_UART_PA > 0))
		boot_uart_mmio_base = (caddr_t)(EARLY_UART_PA);
#endif
	} else {
		boot_uart_mmio_base = (caddr_t)(xbp->bi_bsvc_uart_mmio_base);
	}

	if (xbp->bi_bsvc_uart_type == XBI_BSVC_UART_NONE) {
#if (defined(EARLY_UART_TYPE) && (EARLY_UART_TYPE != XBI_BSVC_UART_NONE))
		boot_uart_type = (xbi_bsvc_uart_type_t)(EARLY_UART_TYPE);
#endif
	} else {
		boot_uart_type = xbp->bi_bsvc_uart_type;
	}

	if (boot_uart_mmio_base == NULL ||
	    boot_uart_type == XBI_BSVC_UART_NONE) {
		boot_uart_mmio_base = NULL;
		boot_uart_type = XBI_BSVC_UART_NONE;
		return;
	}

	switch (boot_uart_type) {
	case XBI_BSVC_UART_PL011:	/* fallthrough */
	case XBI_BSVC_UART_SBSA2X:	/* fallthrough */
	case XBI_BSVC_UART_SBSA:	/* fallthrough */
	case XBI_BSVC_UART_BCM2835:
		break;
	default:
		boot_uart_mmio_base = NULL;
		boot_uart_type = XBI_BSVC_UART_NONE;
		break;
	}
}

#if !defined(_BOOT)
#include <sys/machparam.h>
#include <sys/param.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <vm/hat.h>
#include <vm/as.h>

/*
 * Boot services relocation
 *
 * Called after kernel memory is up and running to relocate the boot services
 * UART base address to the device arena.
 *
 * XXXARM: we should not need this... there's an (unused) switcheroo in i86pc
 * that makes sense for us.
 */
void
boot_uart_relocate(void)
{
	pgcnt_t npages;
	uint_t pgoffset;
	paddr_t base;
	caddr_t cvaddr;
	int prot;
	uint_t attr;
	static int relocated = 0;

	extern void *device_arena_alloc(size_t size, int vm_flag);

	if (relocated)
		return;

	/* if we have no address we can't relocate */
	if (boot_uart_mmio_base == NULL)
		return;

	pgoffset = ((paddr_t)boot_uart_mmio_base) & MMU_PAGEOFFSET;
	base = (paddr_t)boot_uart_mmio_base;

	npages = mmu_btopr(MMU_PAGESIZE + pgoffset);

	cvaddr = device_arena_alloc(ptob(npages), VM_NOSLEEP);
	if (cvaddr == NULL)
		return;

	prot = PROT_READ|PROT_WRITE;
	attr = HAT_LOAD_LOCK|HAT_LOAD_NOCONSIST;
	hat_devload(kas.a_hat, cvaddr, mmu_ptob(npages),
	    mmu_btop(base), prot, attr);
	boot_uart_mmio_base = (caddr_t)(cvaddr + pgoffset);
}
#endif
