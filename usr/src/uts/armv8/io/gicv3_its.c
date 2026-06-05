/*
 * Derived from:
 * $OpenBSD: agintc.c,v 1.65 2025/12/15 12:59:24 dlg Exp $
 *
 * Copyright (c) 2007, 2009, 2011, 2017 Dale Rahn <drahn@dalerahn.com>
 * Copyright (c) 2018 Mark Kettenis <kettenis@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * GICv3 Interrupt Translation Service (ITS) Driver
 *
 * The ITS translates MSI/MSI-X writes from PCI devices into LPI interrupts
 * on the GICv3 redistributor.  A PCI device writes an EventID to the
 * GITS_TRANSLATER doorbell register; the ITS uses its device and interrupt
 * translation tables to map the (DeviceID, EventID) pair to an (LPI INTID,
 * target CPU) pair, which it forwards to the appropriate redistributor.
 *
 * Key hardware structures owned by this driver:
 *
 *   Command Queue   - ring buffer of 32-byte commands in DMA memory.
 *                     Software writes commands and advances GITS_CWRITER;
 *                     hardware reads commands and advances GITS_CREADR.
 *
 *   Device Table    - flat array indexed by DeviceID, pointing to per-device
 *                     Interrupt Translation Tables (ITTs).  Programmed via
 *                     GITS_BASERn and updated by MAPD commands.
 *
 *   Collection Table - maps CollectionIDs to redistributor targets.
 *                      Programmed via GITS_BASERn (if HCC==0) or held
 *                      internally by the ITS (if HCC>0).  Updated by MAPC.
 *
 *   ITT (per device) - maps EventIDs to (LPI, Collection) pairs.  Allocated
 *                      by software in DMA memory; contents written by the
 *                      ITS hardware via MAPTI/DISCARD commands.
 *
 * DeviceID arrives via hdlp->ih_private->ip_msi_devid.  The doorbell address
 * and event data are set on the handle for framework use.
 *
 * Lock ordering
 * =============
 * The following lock ordering must be observed.  Never acquire in reverse.
 *
 *   cpu_lock  -->  its_dev_lock  -->  its_cmd_lock
 *   its_dev_lock  -->  syspic_intrs_lock
 *
 * its_cmd_lock is acquired internally by the gicv3_its_cmd_* helper
 * functions.  Callers that hold its_dev_lock and then issue commands
 * follow the correct nesting order.
 *
 * cpu_lock is held by the framework when invoking cpu_setup_func callbacks.
 * The callback acquires its_dev_lock (for migration) then issues commands
 * (acquiring its_cmd_lock).
 *
 * syspic_intrs_lock is acquired via syspic_get_state() before add_avintr.
 * It must not be held when calling ITS command functions.
 *
 * gc_lpi_prop_lock (in gicthree.c) is acquired independently via
 * gicv3_lpi_set_config() - it is not nested with any ITS lock.
 *
 * Stall recovery
 * ==============
 * If the ITS encounters an unprocessable command, it sets
 * GITS_CREADR.Stalled and halts.  We implement the "skip" recovery
 * model from IHI 0069 §8.19.19: advance CREADR to CWRITER (skipping
 * the entire pending batch), clear the Stalled bit, and return EIO
 * to the caller.  This sacrifices the current command sequence but
 * keeps the ITS alive for all other devices.  The stall count is
 * tracked in its_stall_count for diagnostic and (future) FMA
 * integration.
 */

#include <sys/types.h>
#include <sys/stddef.h>
#include <sys/inttypes.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/list.h>
#include <sys/mutex.h>
#include <sys/avintr.h>
#include <sys/syspic.h>
#include <sys/syspic_impl.h>
#include <sys/gic_v3.h>
#include <sys/gic_reg.h>
#include <sys/byteorder.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/mach_intr.h>
#include <sys/sysmacros.h>

/* Command queue constants */
#define	GICV3_ITS_CMDQ_SIZE		(64 * 1024)	/* 64KiB */
#define	GICV3_ITS_CMDQ_NSLOTS		(GICV3_ITS_CMDQ_SIZE / 32)

/* ITT minimum alignment (spec requirement) */
#define	GICV3_ITS_ITT_ALIGN		256

/* Timeout for command queue operations (microseconds) */
#define	GICV3_ITS_CMD_TIMEOUT_US	1000000		/* 1 second */

/* Timeout for ITS quiesce (microseconds) */
#define	GICV3_ITS_QUIESCE_TIMEOUT_US	1000000		/* 1 second */

/*
 * ITS command opcodes
 */
#define	GITS_CMD_MOVI			0x01
#define	GITS_CMD_INT			0x03
#define	GITS_CMD_CLEAR			0x04
#define	GITS_CMD_SYNC			0x05
#define	GITS_CMD_MAPD			0x08
#define	GITS_CMD_MAPC			0x09
#define	GITS_CMD_MAPTI			0x0a
#define	GITS_CMD_MAPI			0x0b
#define	GITS_CMD_INV			0x0c
#define	GITS_CMD_INVALL			0x0d
#define	GITS_CMD_DISCARD		0x0f

/*
 * ITS command: 32 bytes, 4 DWORDs (little-endian).
 * Built on stack, bcopy'd to queue.
 */
typedef struct gicv3_its_cmd {
	uint64_t	raw[4];
} gicv3_its_cmd_t;

/*
 * Per-vector state within a device's MSI allocation.
 */
typedef struct gicits_vec {
	uint32_t	gv_eventid;	/* EventID for this vector */
	uint32_t	gv_lpi;		/* LPI INTID */
	processorid_t	gv_target_cpu;	/* current target CPU */
	boolean_t	gv_enabled;	/* B_TRUE if MAPTI'd and active */
} gicits_vec_t;

/*
 * Per-device MSI state.
 *
 * Tracks the ITT, LPI allocations, and per-vector mappings for a single
 * PCI device.  ALLOC creates one and links it onto the ITS's device list.
 * ENABLE/DISABLE manipulate individual vectors.  FREE tears it all down.
 *
 * Only one ALLOC per device is permitted (enforced with VERIFY).
 */
typedef struct gicits_dev_state {
	list_node_t		ds_node;	/* linkage on its_devs */
	dev_info_t		*ds_rdip;	/* owning PCI device */
	uint32_t		ds_devid;	/* DeviceID */
	int			ds_type;	/* DDI_INTR_TYPE_MSI[X] */
	uint32_t		ds_nalloc;	/* vectors allocated */
	uint32_t		ds_inum_base;	/* starting inum from ALLOC */

	/* ITT (DMA memory, 256-byte aligned, hardware-opaque) */
	caddr_t			ds_itt;		/* ITT VA */
	uint64_t		ds_itt_pa;	/* ITT PA */
	size_t			ds_itt_sz;	/* allocation size (bytes) */
	uint8_t			ds_itt_bits;	/* log2(entries) for MAPD */
	ddi_dma_handle_t	ds_itt_dmah;
	ddi_acc_handle_t	ds_itt_acch;

	/* Per-vector state (one per allocated interrupt) */
	gicits_vec_t		*ds_vecs;
	size_t			ds_vecs_sz;
} gicits_dev_state_t;

/*
 * Soft state for each ITS instance.
 */
typedef struct gicv3_its_state {
	dev_info_t		*its_dip;
	dev_info_t		*its_gic_dip;		/* parent GICv3 */

	/* MMIO */
	caddr_t			its_base;		/* GITS register VA */
	ddi_acc_handle_t	its_regh;
	uint64_t		its_doorbell_pa;	/* PA of TRANSLATER */

	/* GITS_TYPER parsed fields */
	uint64_t		its_typer;		/* raw GITS_TYPER */
	boolean_t		its_pta;		/* use PA for targets */
	uint32_t		its_devbits;
	uint32_t		its_idbits;
	uint32_t		its_itt_entry_sz;
	uint32_t		its_hcc;
	uint32_t		its_max_colls;		/* usable collections */

	/* Command queue */
	caddr_t			its_cmd_base;		/* queue VA */
	uint64_t		its_cmd_pa;		/* queue PA */
	size_t			its_cmd_sz;		/* queue size */
	uint32_t		its_cmd_write;		/* write offset */
	kmutex_t		its_cmd_lock;
	ddi_dma_handle_t	its_cmd_dmah;
	ddi_acc_handle_t	its_cmd_acch;
	boolean_t		its_cmd_needs_flush;
	/* stall recoveries (its_cmd_lock) */
	uint32_t		its_stall_count;

	/* Device table (flat, 2^Devbits entries) */
	caddr_t			its_devtab;
	uint64_t		its_devtab_pa;
	size_t			its_devtab_sz;
	ddi_dma_handle_t	its_devtab_dmah;
	ddi_acc_handle_t	its_devtab_acch;

	/* Collection table (external, only if HCC == 0) */
	caddr_t			its_colltab;
	uint64_t		its_colltab_pa;
	size_t			its_colltab_sz;
	ddi_dma_handle_t	its_colltab_dmah;
	ddi_acc_handle_t	its_colltab_acch;

	/* Per-device state */
	list_t			its_devs;		/* gicits_dev_state_t */
	kmutex_t		its_dev_lock;

	/* Global list linkage (in parent GICv3's its_list) */
	list_node_t		its_node;
} gicv3_its_state_t;

static void *gicv3_its_soft_state;

/* Forward declarations */
static int gicv3_its_attach(dev_info_t *, ddi_attach_cmd_t);
static int gicv3_its_detach(dev_info_t *, ddi_detach_cmd_t);
static int gicv3_its_intr_ops(dev_info_t *, dev_info_t *,
    ddi_intr_op_t, ddi_intr_handle_impl_t *, void *);
static int gicv3_its_cpu_callback(cpu_setup_t, int, void *);

/*
 * Return B_TRUE if cpuid can be an ITS interrupt target.
 *
 * When HCC > 0, the ITS has a fixed number of internal collections
 * and we use cpuid as the collection ID.  CPUs with IDs beyond the
 * hardware limit cannot own a collection and therefore cannot be
 * direct ITS targets.  When HCC == 0 we provide a software table
 * sized for max_ncpus, so all CPUs are eligible (this is the common
 * case on hardware that is not deeply embedded).
 */
static boolean_t
gicv3_its_cpu_can_target(gicv3_its_state_t *sc, processorid_t cpuid)
{
	return ((uint32_t)cpuid < sc->its_max_colls);
}

/*
 * MMIO helpers
 */

static inline uint32_t
its_read32(gicv3_its_state_t *sc, uint32_t off)
{
	return (ddi_get32(sc->its_regh,
	    (uint32_t *)(sc->its_base + off)));
}

static inline uint64_t
its_read64(gicv3_its_state_t *sc, uint32_t off)
{
	return (ddi_get64(sc->its_regh,
	    (uint64_t *)(sc->its_base + off)));
}

static inline void
its_write32(gicv3_its_state_t *sc, uint32_t off, uint32_t val)
{
	ddi_put32(sc->its_regh,
	    (uint32_t *)(sc->its_base + off), val);
}

static inline void
its_write64(gicv3_its_state_t *sc, uint32_t off, uint64_t val)
{
	ddi_put64(sc->its_regh,
	    (uint64_t *)(sc->its_base + off), val);
}

/*
 * Per-device state lookup
 */

/*
 * Find the per-device state for a given PCI device.
 * Caller must hold sc->its_dev_lock.
 */
static gicits_dev_state_t *
gicv3_its_find_dev(gicv3_its_state_t *sc, dev_info_t *rdip)
{
	gicits_dev_state_t *ds;

	ASSERT(MUTEX_HELD(&sc->its_dev_lock));

	for (ds = list_head(&sc->its_devs); ds != NULL;
	    ds = list_next(&sc->its_devs, ds)) {
		if (ds->ds_rdip == rdip)
			return (ds);
	}

	return (NULL);
}

/*
 * ITS command builder functions
 *
 * Each function populates a gicv3_its_cmd_t (on the caller's stack, passed
 * in via a pointer).
 *
 * Wrapping the data in LE_64 is somewhat unnecessary, but free on the
 * platforms we run on and useful as exposition.
 */

static void
gicv3_its_cmd_build_mapd(gicv3_its_cmd_t *cmd, uint32_t devid,
    uint8_t size, uint64_t itt_pa, boolean_t valid)
{
	bzero(cmd, sizeof (*cmd));
	cmd->raw[0] = LE_64(((uint64_t)devid << 32) | GITS_CMD_MAPD);
	cmd->raw[1] = LE_64((uint64_t)(size & 0x1f));
	cmd->raw[2] = LE_64((valid ? (1ULL << 63) : 0) |
	    (itt_pa & GITS_MAPD_ITT_ADDR));
}

static void
gicv3_its_cmd_build_mapc(gicv3_its_cmd_t *cmd, uint16_t collid,
    uint64_t target, boolean_t valid, boolean_t pta)
{
	bzero(cmd, sizeof (*cmd));
	cmd->raw[0] = LE_64((uint64_t)GITS_CMD_MAPC);
	if (pta) {
		/* PTA=1: target is PA >> 16 in bits [51:16] */
		cmd->raw[2] = LE_64((valid ? (1ULL << 63) : 0) |
		    ((target & 0xFFFFFFFFFULL) << 16) | collid);
	} else {
		/* PTA=0: target is processor number in bits [15:0] */
		cmd->raw[2] = LE_64((valid ? (1ULL << 63) : 0) |
		    ((target & 0xFFFF) << 16) | collid);
	}
}

static void
gicv3_its_cmd_build_mapti(gicv3_its_cmd_t *cmd, uint32_t devid,
    uint32_t eventid, uint32_t pintid, uint16_t collid)
{
	bzero(cmd, sizeof (*cmd));
	cmd->raw[0] = LE_64(((uint64_t)devid << 32) | GITS_CMD_MAPTI);
	cmd->raw[1] = LE_64(((uint64_t)pintid << 32) | eventid);
	cmd->raw[2] = LE_64((uint64_t)collid);
}

static void
gicv3_its_cmd_build_movi(gicv3_its_cmd_t *cmd, uint32_t devid,
    uint32_t eventid, uint16_t collid)
{
	bzero(cmd, sizeof (*cmd));
	cmd->raw[0] = LE_64(((uint64_t)devid << 32) | GITS_CMD_MOVI);
	cmd->raw[1] = LE_64((uint64_t)eventid);
	cmd->raw[2] = LE_64((uint64_t)collid);
}

static void
gicv3_its_cmd_build_discard(gicv3_its_cmd_t *cmd, uint32_t devid,
    uint32_t eventid)
{
	bzero(cmd, sizeof (*cmd));
	cmd->raw[0] = LE_64(((uint64_t)devid << 32) | GITS_CMD_DISCARD);
	cmd->raw[1] = LE_64((uint64_t)eventid);
}

static void
gicv3_its_cmd_build_inv(gicv3_its_cmd_t *cmd, uint32_t devid,
    uint32_t eventid)
{
	bzero(cmd, sizeof (*cmd));
	cmd->raw[0] = LE_64(((uint64_t)devid << 32) | GITS_CMD_INV);
	cmd->raw[1] = LE_64((uint64_t)eventid);
}

static void
gicv3_its_cmd_build_sync(gicv3_its_cmd_t *cmd, uint64_t target,
    boolean_t pta)
{
	bzero(cmd, sizeof (*cmd));
	cmd->raw[0] = LE_64((uint64_t)GITS_CMD_SYNC);
	if (pta) {
		cmd->raw[2] = LE_64((target & 0xFFFFFFFFFULL) << 16);
	} else {
		cmd->raw[2] = LE_64((target & 0xFFFF) << 16);
	}
}

/*
 * Command queue submission and completion
 */

/*
 * Recover from a command queue stall by skipping all pending commands.
 *
 * When the ITS encounters an unprocessable command, it sets
 * GITS_CREADR.Stalled and halts.  We advance CREADR to the current
 * CWRITER offset with Stalled=0, discarding all commands between the
 * stalled entry and the write pointer.  This is the "skip" recovery
 * model from the GICv3 specification (IHI 0069 §8.19.19).
 *
 * Skipping the entire batch (rather than advancing by one command) is
 * deliberate: our command sequences (e.g. MAPTI+INV+SYNC) are submitted
 * and polled for as atomic units under its_cmd_lock; if one command
 * stalled, the remaining commands in the batch may depend on state it
 * was meant to establish.
 *
 * The caller still receives EIO and propagates the failure through the
 * DDI framework.  The ITS itself is left functional for subsequent
 * commands from other devices.
 *
 * Caller must hold its_cmd_lock.
 */
static void
gicv3_its_cmd_recover_stall(gicv3_its_state_t *sc, uint64_t creadr)
{
	uint64_t stall_offset = creadr & GITS_CREADR_Offset;
	uint64_t cwriter = (uint64_t)sc->its_cmd_write;

	ASSERT(MUTEX_HELD(&sc->its_cmd_lock));
	ASSERT(creadr & GITS_CREADR_Stalled);

	/*
	 * Log the stalled command contents for post-mortem diagnosis.
	 * The stall offset points at the command the hardware choked on.
	 */
	if (stall_offset < sc->its_cmd_sz) {
		uint64_t *raw = (uint64_t *)(sc->its_cmd_base + stall_offset);
		dev_err(sc->its_dip, CE_WARN,
		    "ITS stall recovery: offset=0x%" PRIx64
		    " CWRITER=0x%" PRIx64
		    " cmd={0x%" PRIx64 ", 0x%" PRIx64
		    ", 0x%" PRIx64 ", 0x%" PRIx64 "}",
		    stall_offset, cwriter,
		    raw[0], raw[1], raw[2], raw[3]);
	}

	/*
	 * Advance CREADR to CWRITER with Stalled=0.
	 * This discards all queued commands and clears the stall.
	 */
	its_write64(sc, GITS_CREADR, cwriter);

	sc->its_stall_count++;

	dev_err(sc->its_dip, CE_WARN,
	    "ITS command queue stall cleared (recovery #%u)",
	    sc->its_stall_count);
}

/*
 * Submit a single 32-byte command to the ITS command queue.
 * Caller must hold its_cmd_lock.
 *
 * Returns 0 on success, EIO if the queue is stalled, EBUSY if the
 * queue did not drain within the timeout.
 */
static int
gicv3_its_cmd_submit(gicv3_its_state_t *sc, gicv3_its_cmd_t *cmd)
{
	uint32_t next;
	uint64_t creadr;
	int timeout_us = GICV3_ITS_CMD_TIMEOUT_US;

	ASSERT(MUTEX_HELD(&sc->its_cmd_lock));

	/* Check for stall before writing, recover the queue if stalled */
	creadr = its_read64(sc, GITS_CREADR);
	if (creadr & GITS_CREADR_Stalled) {
		gicv3_its_cmd_recover_stall(sc, creadr);
		return (EIO);
	}

	next = (sc->its_cmd_write + sizeof (gicv3_its_cmd_t)) %
	    sc->its_cmd_sz;

	/* If queue is full, wait for hardware to consume entries */
	while (next == (its_read64(sc, GITS_CREADR) & GITS_CREADR_Offset)) {
		if (timeout_us <= 0) {
			dev_err(sc->its_dip, CE_WARN,
			    "command queue full timeout");
			return (EBUSY);
		}
		drv_usecwait(10);
		timeout_us -= 10;
	}

	/* Write command to queue slot */
	bcopy(cmd, sc->its_cmd_base + sc->its_cmd_write,
	    sizeof (gicv3_its_cmd_t));

	/* Cache maintenance if shareability was downgraded */
	if (sc->its_cmd_needs_flush) {
		(void) ddi_dma_sync(sc->its_cmd_dmah,
		    sc->its_cmd_write, sizeof (gicv3_its_cmd_t),
		    DDI_DMA_SYNC_FORDEV);
	}

	/* Ensure command is visible before advancing CWRITER */
	membar_producer();

	/* Advance write pointer */
	sc->its_cmd_write = next;
	its_write64(sc, GITS_CWRITER, (uint64_t)next);

	return (0);
}

/*
 * Wait for the command queue to fully drain (CREADR == CWRITER).
 * Caller must hold its_cmd_lock.
 */
static int
gicv3_its_cmd_poll_completion(gicv3_its_state_t *sc)
{
	uint64_t creadr;
	int timeout_us = GICV3_ITS_CMD_TIMEOUT_US;

	ASSERT(MUTEX_HELD(&sc->its_cmd_lock));

	for (;;) {
		creadr = its_read64(sc, GITS_CREADR);

		/*
		 * Stall detected: recover by skipping all pending
		 * commands to CWRITER.  The current batch is lost,
		 * but the ITS remains usable for subsequent operations.
		 */
		if (creadr & GITS_CREADR_Stalled) {
			gicv3_its_cmd_recover_stall(sc, creadr);
			return (EIO);
		}

		if ((creadr & GITS_CREADR_Offset) == sc->its_cmd_write)
			return (0);

		if (timeout_us <= 0) {
			dev_err(sc->its_dip, CE_WARN,
			    "command queue timeout: CREADR=0x%" PRIx64
			    " CWRITER=0x%x",
			    creadr, sc->its_cmd_write);
			return (ETIMEDOUT);
		}

		drv_usecwait(10);
		timeout_us -= 10;
	}
}

/*
 * High-level command wrappers
 *
 * These acquire the command lock, build and submit the command(s),
 * issue SYNC where appropriate, wait for drain, and release the lock.
 */

/*
 * Compute the SYNC target value for a given CPU.
 */
static uint64_t
gicv3_its_sync_target(gicv3_its_state_t *sc, processorid_t cpuid)
{
	if (sc->its_pta)
		return (gicv3_redist_pa(sc->its_gic_dip, cpuid) >> 16);
	else
		return ((uint64_t)gicv3_redist_procnum(sc->its_gic_dip,
		    cpuid));
}

static int
gicv3_its_do_mapd(gicv3_its_state_t *sc, uint32_t devid, uint8_t size,
    uint64_t itt_pa, boolean_t valid)
{
	gicv3_its_cmd_t cmd;
	int ret;

	mutex_enter(&sc->its_cmd_lock);

	gicv3_its_cmd_build_mapd(&cmd, devid, size, itt_pa, valid);
	ret = gicv3_its_cmd_submit(sc, &cmd);
	if (ret == 0)
		ret = gicv3_its_cmd_poll_completion(sc);

	mutex_exit(&sc->its_cmd_lock);
	return (ret);
}

static int
gicv3_its_do_mapc(gicv3_its_state_t *sc, processorid_t cpuid,
    boolean_t valid)
{
	gicv3_its_cmd_t cmd;
	uint64_t target;
	int ret;

	target = gicv3_its_sync_target(sc, cpuid);

	mutex_enter(&sc->its_cmd_lock);

	gicv3_its_cmd_build_mapc(&cmd, (uint16_t)cpuid, target, valid,
	    sc->its_pta);
	ret = gicv3_its_cmd_submit(sc, &cmd);
	if (ret == 0) {
		gicv3_its_cmd_build_sync(&cmd, target, sc->its_pta);
		ret = gicv3_its_cmd_submit(sc, &cmd);
	}
	if (ret == 0)
		ret = gicv3_its_cmd_poll_completion(sc);

	mutex_exit(&sc->its_cmd_lock);
	return (ret);
}

static int
gicv3_its_do_mapti(gicv3_its_state_t *sc, uint32_t devid, uint32_t eventid,
    uint32_t lpi, uint16_t collid, processorid_t target_cpu)
{
	gicv3_its_cmd_t cmd;
	uint64_t target;
	int ret;

	target = gicv3_its_sync_target(sc, target_cpu);

	mutex_enter(&sc->its_cmd_lock);

	gicv3_its_cmd_build_mapti(&cmd, devid, eventid, lpi, collid);
	ret = gicv3_its_cmd_submit(sc, &cmd);
	if (ret == 0) {
		gicv3_its_cmd_build_inv(&cmd, devid, eventid);
		ret = gicv3_its_cmd_submit(sc, &cmd);
	}
	if (ret == 0) {
		gicv3_its_cmd_build_sync(&cmd, target, sc->its_pta);
		ret = gicv3_its_cmd_submit(sc, &cmd);
	}
	if (ret == 0)
		ret = gicv3_its_cmd_poll_completion(sc);

	mutex_exit(&sc->its_cmd_lock);
	return (ret);
}

static int
gicv3_its_do_discard(gicv3_its_state_t *sc, uint32_t devid,
    uint32_t eventid, processorid_t target_cpu)
{
	gicv3_its_cmd_t cmd;
	uint64_t target;
	int ret;

	target = gicv3_its_sync_target(sc, target_cpu);

	mutex_enter(&sc->its_cmd_lock);

	gicv3_its_cmd_build_discard(&cmd, devid, eventid);
	ret = gicv3_its_cmd_submit(sc, &cmd);
	if (ret == 0) {
		gicv3_its_cmd_build_sync(&cmd, target, sc->its_pta);
		ret = gicv3_its_cmd_submit(sc, &cmd);
	}
	if (ret == 0)
		ret = gicv3_its_cmd_poll_completion(sc);

	mutex_exit(&sc->its_cmd_lock);
	return (ret);
}

static int
gicv3_its_do_movi(gicv3_its_state_t *sc, uint32_t devid,
    uint32_t eventid, processorid_t new_cpu)
{
	gicv3_its_cmd_t cmd;
	uint64_t target;
	int ret;

	target = gicv3_its_sync_target(sc, new_cpu);

	mutex_enter(&sc->its_cmd_lock);

	gicv3_its_cmd_build_movi(&cmd, devid, eventid, (uint16_t)new_cpu);
	ret = gicv3_its_cmd_submit(sc, &cmd);
	if (ret == 0) {
		gicv3_its_cmd_build_sync(&cmd, target, sc->its_pta);
		ret = gicv3_its_cmd_submit(sc, &cmd);
	}
	if (ret == 0)
		ret = gicv3_its_cmd_poll_completion(sc);

	mutex_exit(&sc->its_cmd_lock);
	return (ret);
}

/*
 * bus_intr_op handlers
 */

/*
 * ALLOC: allocate LPIs and ITT for a PCI device.
 *
 * Creates per-device state, allocates LPI INTIDs from the parent GICv3's
 * vmem arena, allocates the ITT via DMA, and issues MAPD to bind the
 * device table entry to the ITT.
 */
static int
gicv3_its_alloc(gicv3_its_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int count = hdlp->ih_scratch1;
	int actual = 0;
	ihdl_plat_t *priv = hdlp->ih_private;
	uint32_t devid = priv->ip_msi_devid;
	gicits_dev_state_t *ds;
	int i;

	/*
	 * Validate that the DeviceID fits within the ITS device table.
	 * GITS_TYPER.Devbits defines the supported range.
	 */
	if (devid >= (1U << sc->its_devbits)) {
		dev_err(sc->its_dip, CE_WARN,
		    "DeviceID 0x%x exceeds ITS limit (%u bits)",
		    devid, sc->its_devbits);
		return (DDI_FAILURE);
	}

	ds = kmem_zalloc(sizeof (*ds), KM_SLEEP);
	ds->ds_rdip = rdip;
	ds->ds_devid = devid;
	ds->ds_type = hdlp->ih_type;
	ds->ds_inum_base = hdlp->ih_inum;

	/*
	 * Allocate LPI INTIDs from the parent GICv3's vmem arena.
	 *
	 * Unlike v2m where SPIs must be contiguous for MSI, ITS EventIDs
	 * are always 0..N-1 and MAPTI maps each EventID to an arbitrary
	 * LPI.  Contiguity is not required for either MSI or MSI-X.
	 */
	ds->ds_vecs_sz = count * sizeof (gicits_vec_t);
	ds->ds_vecs = kmem_zalloc(ds->ds_vecs_sz, KM_SLEEP);

	for (actual = 0; actual < count; actual++) {
		uint32_t lpi;

		if (gicv3_alloc_lpi(sc->its_gic_dip, &lpi) != 0)
			break;
		ds->ds_vecs[actual].gv_lpi = lpi;
		ds->ds_vecs[actual].gv_eventid = actual;
		ds->ds_vecs[actual].gv_enabled = B_FALSE;
	}

	if (actual == 0) {
		kmem_free(ds->ds_vecs, ds->ds_vecs_sz);
		kmem_free(ds, sizeof (*ds));
		return (DDI_INTR_NOTFOUND);
	}

	ds->ds_nalloc = actual;

	/*
	 * Allocate the Interrupt Translation Table (ITT) via DDI DMA.
	 *
	 * Size: 2^itt_bits entries * its_itt_entry_sz bytes per entry.
	 * Minimum alignment: 256 bytes (spec requirement).
	 *
	 * We round up to page size to ensure the ITT gets its own
	 * physical page(s).  Sub-page DMA allocations can share a
	 * physical page with kmem, and the ITS hardware writing to
	 * the ITT would corrupt adjacent kmem buffers on that page.
	 */
	ds->ds_itt_bits = highbit(actual);
	if (actual == (1U << (ds->ds_itt_bits - 1)))
		ds->ds_itt_bits--;	/* exact power of 2 */
	if (ds->ds_itt_bits < 1)
		ds->ds_itt_bits = 1;

	ds->ds_itt_sz = P2ROUNDUP(
	    (size_t)(1U << ds->ds_itt_bits) * sc->its_itt_entry_sz,
	    PAGESIZE);

	if (gicv3_contig_alloc(sc->its_dip, ds->ds_itt_sz,
	    PAGESIZE, &ds->ds_itt, &ds->ds_itt_pa,
	    &ds->ds_itt_dmah, &ds->ds_itt_acch) != DDI_SUCCESS) {
		for (i = 0; i < actual; i++)
			gicv3_free_lpi(sc->its_gic_dip,
			    ds->ds_vecs[i].gv_lpi);
		kmem_free(ds->ds_vecs, ds->ds_vecs_sz);
		kmem_free(ds, sizeof (*ds));
		return (DDI_FAILURE);
	}

	/* Tell the ITS about this device */
	if (gicv3_its_do_mapd(sc, devid, ds->ds_itt_bits - 1,
	    ds->ds_itt_pa, B_TRUE) != 0) {
		gicv3_contig_free(&ds->ds_itt_dmah, &ds->ds_itt_acch);
		for (i = 0; i < actual; i++)
			gicv3_free_lpi(sc->its_gic_dip,
			    ds->ds_vecs[i].gv_lpi);
		kmem_free(ds->ds_vecs, ds->ds_vecs_sz);
		kmem_free(ds, sizeof (*ds));
		return (DDI_FAILURE);
	}

	/* Only one ALLOC per device — assert under the same lock as insert */
	mutex_enter(&sc->its_dev_lock);
	VERIFY3P(gicv3_its_find_dev(sc, rdip), ==, NULL);
	list_insert_tail(&sc->its_devs, ds);
	mutex_exit(&sc->its_dev_lock);

	*(int *)result = actual;
	return (DDI_SUCCESS);
}

/*
 * FREE: release all MSI resources for a PCI device.
 *
 * Invalidates the device table entry, frees the ITT DMA memory, returns
 * LPI INTIDs to the parent GICv3's vmem arena, and frees the per-device
 * state structure.
 */
static int
gicv3_its_free(gicv3_its_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	gicits_dev_state_t *ds;
	uint32_t i;

	mutex_enter(&sc->its_dev_lock);
	ds = gicv3_its_find_dev(sc, rdip);
	if (ds == NULL) {
		/* Already freed by a prior handle */
		mutex_exit(&sc->its_dev_lock);
		return (DDI_SUCCESS);
	}
	list_remove(&sc->its_devs, ds);
	mutex_exit(&sc->its_dev_lock);

	/* Invalidate device table entry */
	(void) gicv3_its_do_mapd(sc, ds->ds_devid, 0, 0, B_FALSE);

	/* Free ITT DMA memory (safe now - ITS won't access it) */
	gicv3_contig_free(&ds->ds_itt_dmah, &ds->ds_itt_acch);

	/*
	 * Defensive: DDI requires DISABLE before FREE, so all vectors
	 * should already be disabled and their LPI config scrubbed.
	 * Assert and scrub anyway to catch driver bugs and ensure LPIs
	 * go back to the arena in a clean state.
	 */
	for (i = 0; i < ds->ds_nalloc; i++) {
		ASSERT3S(ds->ds_vecs[i].gv_enabled, ==, B_FALSE);
		gicv3_lpi_set_config(sc->its_gic_dip,
		    ds->ds_vecs[i].gv_lpi, 0, B_FALSE);
		gicv3_free_lpi(sc->its_gic_dip, ds->ds_vecs[i].gv_lpi);
	}

	kmem_free(ds->ds_vecs, ds->ds_vecs_sz);
	kmem_free(ds, sizeof (*ds));
	return (DDI_SUCCESS);
}

/*
 * ENABLE: activate a single MSI/MSI-X vector.
 *
 * 1. Set ih_vector to the LPI INTID for dispatch lookup.
 * 2. Register the handler via add_avintr (addspl guard skips distributor
 *    programming for LPI INTIDs >= 8192).  No hardware is touched.
 * 3. Enable the LPI in the PROPBASER configuration table.
 * 4. Issue MAPTI + INV + SYNC to create the ITS translation.
 *    From this point interrupts can flow; the handler is already in place.
 * 5. Set ip_msi_addr/data on the handle for framework use.
 *
 * Installing the handler (step 2) before enabling the hardware (steps 3-4)
 * ensures there is no window where an LPI can be delivered without a
 * registered handler in autovect.  In reality this is never a concern
 * anyway, as programming of the MSI producer can only happen after
 * this driver code has run, so this is purely defensive.
 */
static int
gicv3_its_enable(gicv3_its_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	gicits_dev_state_t *ds;
	gicits_vec_t *vec;
	ihdl_plat_t *priv = hdlp->ih_private;
	syspic_intr_state_t *state;
	uint32_t idx, lpi, eventid, devid;
	processorid_t target_cpu;

	mutex_enter(&sc->its_dev_lock);
	ds = gicv3_its_find_dev(sc, rdip);
	if (ds == NULL) {
		mutex_exit(&sc->its_dev_lock);
		dev_err(sc->its_dip, CE_WARN,
		    "no MSI state for %s%d",
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);
	}

	idx = hdlp->ih_inum - ds->ds_inum_base;
	VERIFY3U(idx, <, ds->ds_nalloc);
	vec = &ds->ds_vecs[idx];
	lpi = vec->gv_lpi;
	eventid = vec->gv_eventid;
	devid = ds->ds_devid;
	mutex_exit(&sc->its_dev_lock);

	target_cpu = CPU->cpu_id;

	/*
	 * If the current CPU cannot be an ITS target (HCC limit),
	 * fall back to CPU 0 which is always within range.
	 */
	if (!gicv3_its_cpu_can_target(sc, target_cpu))
		target_cpu = 0;

	/* Set ih_vector so av_dispatch_autovect can find the handler */
	hdlp->ih_vector = lpi;

	/*
	 * Register handler in autovect table.  The addspl guard skips
	 * distributor programming for LPI INTIDs (>= 8192), so this
	 * is a pure software operation - no hardware is touched.
	 *
	 * syspic_get_state() acquires syspic_intrs_lock and creates
	 * the tracking record for this LPI - we must release the lock
	 * after add_avintr.
	 */
	state = syspic_get_state(lpi);
	VERIFY3P(state, !=, NULL);
	state->si_edge_triggered = B_TRUE;
	state->si_prio = hdlp->ih_pri;

	if (!add_avintr((void *)hdlp, hdlp->ih_pri,
	    hdlp->ih_cb_func, DEVI(rdip)->devi_name,
	    lpi, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2,
	    NULL, rdip)) {
		syspic_remove_state(lpi);
		mutex_exit(&syspic_intrs_lock);
		return (DDI_FAILURE);
	}
	mutex_exit(&syspic_intrs_lock);

	/* Enable LPI in PROPBASER: set priority and enable */
	gicv3_lpi_set_config(sc->its_gic_dip, lpi,
	    GIC_IPL_TO_PRIO(hdlp->ih_pri), B_TRUE);

	/* Program ITS translation: EventID -> (LPI, Collection) */
	if (gicv3_its_do_mapti(sc, devid, eventid, lpi,
	    (uint16_t)target_cpu, target_cpu) != 0) {
		gicv3_lpi_set_config(sc->its_gic_dip, lpi,
		    GIC_IPL_TO_PRIO(hdlp->ih_pri), B_FALSE);
		rem_avintr((void *)hdlp, hdlp->ih_pri,
		    hdlp->ih_cb_func, lpi);
		return (DDI_FAILURE);
	}

	/*
	 * Set MSI address/data on the handle for framework use.
	 *
	 * Address = GITS_TRANSLATER PA (same for all vectors on this ITS).
	 * Data = EventID (ITS translates EventID -> LPI via the ITT).
	 *
	 * For MSI, the PCI device computes data as
	 * (base_data & ~(count-1)) | vector_offset.  Since base EventID
	 * is 0 and count is a power of 2, this yields vector_offset,
	 * which equals our EventID.
	 */
	priv->ip_msi_addr = sc->its_doorbell_pa;
	priv->ip_msi_data = eventid;

	/*
	 * PCI capability programming is handled by the pcierc nexus
	 * (pci_common_intr_ops ENABLE) using ip_msi_addr/ip_msi_data.
	 */

	/*
	 * Publish the vector as enabled and record its target CPU.
	 *
	 * Must hold its_dev_lock to be atomic with respect to
	 * gicv3_its_cpu_offline()'s migration scan.
	 */
	mutex_enter(&sc->its_dev_lock);
	vec->gv_target_cpu = target_cpu;
	vec->gv_enabled = B_TRUE;
	mutex_exit(&sc->its_dev_lock);

	return (DDI_SUCCESS);
}

/*
 * DISABLE: deactivate a single MSI/MSI-X vector.
 *
 * Order: stop device -> remove handler -> disable LPI -> remove translation.
 * No window for handler-less interrupt delivery.
 */
static int
gicv3_its_disable(gicv3_its_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	gicits_dev_state_t *ds;
	gicits_vec_t *vec;
	uint32_t lpi, idx, eventid, devid;
	processorid_t target_cpu;

	lpi = hdlp->ih_vector;

	mutex_enter(&sc->its_dev_lock);
	ds = gicv3_its_find_dev(sc, rdip);
	VERIFY3P(ds, !=, NULL);
	idx = hdlp->ih_inum - ds->ds_inum_base;
	VERIFY3U(idx, <, ds->ds_nalloc);
	vec = &ds->ds_vecs[idx];
	devid = ds->ds_devid;
	eventid = vec->gv_eventid;
	target_cpu = vec->gv_target_cpu;
	mutex_exit(&sc->its_dev_lock);

	/*
	 * PCI capability deconfiguration is handled by the pcierc nexus
	 * (pci_common_intr_ops DISABLE) prior to calling us.
	 */

	/* Remove handler from autovect */
	rem_avintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func, lpi);

	/* Disable LPI in PROPBASER */
	gicv3_lpi_set_config(sc->its_gic_dip, lpi,
	    GIC_IPL_TO_PRIO(hdlp->ih_pri), B_FALSE);

	/*
	 * Mark the vector disabled and re-read target_cpu under the
	 * lock.  This must be atomic with respect to
	 * gicv3_its_cpu_offline()'s migration scan: once gv_enabled
	 * is B_FALSE, the offline scan will skip this vector.
	 * Re-reading gv_target_cpu ensures we DISCARD to the correct
	 * collection if a concurrent MOVI moved the vector.
	 */
	mutex_enter(&sc->its_dev_lock);
	vec->gv_enabled = B_FALSE;
	target_cpu = vec->gv_target_cpu;
	mutex_exit(&sc->its_dev_lock);

	/* Remove ITS translation and flush */
	(void) gicv3_its_do_discard(sc, devid, eventid, target_cpu);

	return (DDI_SUCCESS);
}

/*
 * SETTARGET: move a single vector to a different CPU.
 */
static int
gicv3_its_settarget(gicv3_its_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	gicits_dev_state_t *ds;
	gicits_vec_t *vec;
	processorid_t new_cpu;
	uint32_t idx;

	new_cpu = *(processorid_t *)result;

	/* Reject targets beyond the hardware collection limit */
	if (!gicv3_its_cpu_can_target(sc, new_cpu))
		return (DDI_EINVAL);

	mutex_enter(&sc->its_dev_lock);
	ds = gicv3_its_find_dev(sc, rdip);
	VERIFY3P(ds, !=, NULL);
	idx = hdlp->ih_inum - ds->ds_inum_base;
	VERIFY3U(idx, <, ds->ds_nalloc);
	vec = &ds->ds_vecs[idx];

	if (!vec->gv_enabled) {
		mutex_exit(&sc->its_dev_lock);
		return (DDI_FAILURE);
	}

	if (vec->gv_target_cpu == new_cpu) {
		mutex_exit(&sc->its_dev_lock);
		return (DDI_SUCCESS);
	}

	if (gicv3_its_do_movi(sc, ds->ds_devid, vec->gv_eventid,
	    new_cpu) != 0) {
		mutex_exit(&sc->its_dev_lock);
		return (DDI_FAILURE);
	}

	vec->gv_target_cpu = new_cpu;
	mutex_exit(&sc->its_dev_lock);
	return (DDI_SUCCESS);
}

/*
 * GETTARGET: return the current target CPU for a vector.
 */
static int
gicv3_its_gettarget(gicv3_its_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	gicits_dev_state_t *ds;
	uint32_t idx;

	mutex_enter(&sc->its_dev_lock);
	ds = gicv3_its_find_dev(sc, rdip);
	VERIFY3P(ds, !=, NULL);
	idx = hdlp->ih_inum - ds->ds_inum_base;
	VERIFY3U(idx, <, ds->ds_nalloc);
	*(processorid_t *)result = ds->ds_vecs[idx].gv_target_cpu;
	mutex_exit(&sc->its_dev_lock);

	return (DDI_SUCCESS);
}

/*
 * Return the pending state of an LPI from the redistributor's
 * PENDBASER table.
 *
 * The LPI INTID and target CPU are looked up from the per-device
 * vector state, then the pending bit is read from the target
 * redistributor's pending table via gicv3_lpi_ispending().
 */
static int
gicv3_its_getpending(gicv3_its_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	gicits_dev_state_t *ds;
	uint32_t idx;
	uint32_t lpi;
	processorid_t target_cpu;

	mutex_enter(&sc->its_dev_lock);
	ds = gicv3_its_find_dev(sc, rdip);
	if (ds == NULL) {
		mutex_exit(&sc->its_dev_lock);
		return (DDI_FAILURE);
	}

	idx = hdlp->ih_inum - ds->ds_inum_base;
	VERIFY3U(idx, <, ds->ds_nalloc);
	lpi = ds->ds_vecs[idx].gv_lpi;
	target_cpu = ds->ds_vecs[idx].gv_target_cpu;
	mutex_exit(&sc->its_dev_lock);

	*(int *)result = gicv3_lpi_ispending(sc->its_gic_dip,
	    lpi, target_cpu) ? 1 : 0;
	return (DDI_SUCCESS);
}

/*
 * bus_intr_op entry point - dispatches interrupt operations from the
 * DDI framework to per-operation handlers.
 */
static int
gicv3_its_intr_ops(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	gicv3_its_state_t *sc = ddi_get_soft_state(gicv3_its_soft_state,
	    ddi_get_instance(dip));
	VERIFY3P(sc, !=, NULL);

	switch (intr_op) {
	case DDI_INTROP_ALLOC:
		return (gicv3_its_alloc(sc, rdip, hdlp, result));
	case DDI_INTROP_FREE:
		return (gicv3_its_free(sc, rdip, hdlp));
	case DDI_INTROP_ENABLE:
		return (gicv3_its_enable(sc, rdip, hdlp));
	case DDI_INTROP_DISABLE:
		return (gicv3_its_disable(sc, rdip, hdlp));
	case DDI_INTROP_BLOCKENABLE:
		return (DDI_ENOTSUP);
	case DDI_INTROP_BLOCKDISABLE:
		return (DDI_ENOTSUP);
	case DDI_INTROP_SETTARGET:
		return (gicv3_its_settarget(sc, rdip, hdlp, result));
	case DDI_INTROP_GETTARGET:
		return (gicv3_its_gettarget(sc, rdip, hdlp, result));
	case DDI_INTROP_SETPRI: {
		int shared;
		uint_t curpri;
		uint_t newpri;
		uint32_t lpi = hdlp->ih_vector;

		DDI_INTR_NEXDBG((CE_CONT, "gicv3_its_intr_ops: SETPRI "
		    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x, "
		    "is 0x%x\n",
		    (void *)rdip, (void *)hdlp, hdlp->ih_inum,
		    *(int *)result));
		if (*(int *)result > LOCK_LEVEL) {
			DDI_INTR_NEXDBG((CE_CONT,
			    "gicv3_its_intr_ops: SETPRI "
			    "for rdip = 0x%p: new pri %d exceeds "
			    "LOCK_LEVEL %d\n",
			    (void *)rdip, *(int *)result, LOCK_LEVEL));
			return (DDI_FAILURE);
		}

		shared = av_get_shared(lpi, &curpri);
		newpri = (uint_t)(*(int *)result);
		if (shared > 0 && newpri != curpri) {
			dev_err(rdip, CE_NOTE,
			    "!%s%d: refusing to set pri 0x%x on "
			    "shared LPI %u with pri 0x%x",
			    ddi_node_name(rdip), ddi_get_instance(rdip),
			    newpri, lpi, curpri);
			return (DDI_FAILURE);
		}

		ASSERT3U(*(int *)result, !=, 0);
		hdlp->ih_pri = *(int *)result;
		return (DDI_SUCCESS);
	}
	case DDI_INTROP_ADDISR:
	case DDI_INTROP_REMISR:
		return (DDI_SUCCESS);
	case DDI_INTROP_SUPPORTED_TYPES:
		*(int *)result = DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX;
		return (DDI_SUCCESS);
	case DDI_INTROP_NAVAIL:
		*(int *)result =
		    (int)gicv3_lpi_navail(sc->its_gic_dip);
		return (DDI_SUCCESS);
	case DDI_INTROP_GETPENDING:
		return (gicv3_its_getpending(sc, rdip, hdlp, result));
	case DDI_INTROP_GETCAP:
		*(int *)result &= ~DDI_INTR_FLAG_BLOCK;
		*(int *)result |= DDI_INTR_FLAG_PENDING;
		*(int *)result |= DDI_INTR_FLAG_EDGE;
		*(int *)result &= ~DDI_INTR_FLAG_LEVEL;
		return (DDI_SUCCESS);
	case DDI_INTROP_GETPOOL: {
		ddi_irm_pool_t *pool;

		pool = gicv3_get_lpi_irm_pool(sc->its_gic_dip);
		if (pool == NULL) {
			return (DDI_ENOTSUP);
		}
		*(ddi_irm_pool_t **)result = pool;
		return (DDI_SUCCESS);
	}
	default:
		return (DDI_ENOTSUP);
	}
}

/*
 * CPU hotplug
 */

/*
 * Pick a migration target for LPIs when a CPU goes offline.
 * Policy: CPU 0 always (simple, safe, always online).
 */
static processorid_t
gicv3_its_pick_migration_cpu(gicv3_its_state_t *sc, processorid_t dying)
{
	cpu_t *cp;

	/*
	 * Walk the online CPU list.  Pick the first one that isn't
	 * the dying CPU and can be an ITS target (within collection
	 * limit).  cpu_active is safe to walk here because we are
	 * called under cpu_lock (from cpu_setup_func).
	 */
	cp = cpu_active;
	do {
		if (cp->cpu_id != dying &&
		    gicv3_its_cpu_can_target(sc, cp->cpu_id))
			return (cp->cpu_id);
	} while ((cp = cp->cpu_next_onln) != cpu_active);

	/* Should never happen - can't offline the last CPU */
	panic("gicv3_its: no migration target for CPU %d", dying);
	/* NOTREACHED */
	return (0);
}

static int
gicv3_its_cpu_online(gicv3_its_state_t *sc, processorid_t cpuid)
{
	/* No collection slot for this CPU — it just can't be an ITS target */
	if (!gicv3_its_cpu_can_target(sc, cpuid))
		return (0);
	return (gicv3_its_do_mapc(sc, cpuid, B_TRUE));
}

static int
gicv3_its_cpu_offline(gicv3_its_state_t *sc, processorid_t cpuid)
{
	gicits_dev_state_t *ds;
	processorid_t dest;
	uint32_t i;

	/* This CPU never had a collection — nothing to tear down */
	if (!gicv3_its_cpu_can_target(sc, cpuid))
		return (0);

	dest = gicv3_its_pick_migration_cpu(sc, cpuid);

	/*
	 * Walk all devices on this ITS.  For each enabled vector
	 * targeting the dying CPU, issue MOVI to the new target.
	 */
	mutex_enter(&sc->its_dev_lock);
	for (ds = list_head(&sc->its_devs); ds != NULL;
	    ds = list_next(&sc->its_devs, ds)) {
		for (i = 0; i < ds->ds_nalloc; i++) {
			gicits_vec_t *vec = &ds->ds_vecs[i];

			if (!vec->gv_enabled)
				continue;
			if (vec->gv_target_cpu != cpuid)
				continue;

			if (gicv3_its_do_movi(sc, ds->ds_devid,
			    vec->gv_eventid, dest) == 0) {
				vec->gv_target_cpu = dest;
			} else {
				cmn_err(CE_WARN, "gicv3_its: failed to "
				    "migrate devid 0x%x eventid %u from "
				    "CPU %d to CPU %d",
				    ds->ds_devid, vec->gv_eventid,
				    cpuid, dest);
			}
		}
	}
	mutex_exit(&sc->its_dev_lock);

	/* Invalidate the collection for the dead CPU */
	(void) gicv3_its_do_mapc(sc, cpuid, B_FALSE);

	return (0);
}

/*
 * CPU setup callback, registered via register_cpu_setup_func().
 * Called under cpu_lock by the framework.
 */
static int
gicv3_its_cpu_callback(cpu_setup_t what, int cpuid, void *arg)
{
	gicv3_its_state_t *sc = arg;

	switch (what) {
	case CPU_SETUP:		/* boot-time secondary CPUs (aarch64) */
	case CPU_ON:		/* DR-onlined CPUs */
		return (gicv3_its_cpu_online(sc, (processorid_t)cpuid));
	case CPU_OFF:
		return (gicv3_its_cpu_offline(sc, (processorid_t)cpuid));
	default:
		return (0);
	}
}

/*
 * ITS table allocation (BASERn)
 *
 * Scans GITS_BASERn[0..7] for the Device and Collection tables.
 * For each, allocates DMA memory with page size escalation
 * (4K -> 16K -> 64K) if the table doesn't fit in 256 pages.
 * Programs the BASERn register with shareability/cacheability,
 * reads back to check for downgrade, and retries if needed.
 */

static size_t
gicv3_its_pgsz_to_bytes(uint32_t pgsz)
{
	switch (pgsz) {
	case GITS_BASER_PGSZ_4K:
		return (4096);
	case GITS_BASER_PGSZ_16K:
		return (16384);
	case GITS_BASER_PGSZ_64K:
		return (65536);
	default:
		return (4096);
	}
}

/*
 * Allocate and program a single BASERn table.
 * Returns 0 on success, -1 on failure.
 */
static int
gicv3_its_alloc_table(gicv3_its_state_t *sc, uint32_t baser_idx,
    size_t num_entries, caddr_t *vap, uint64_t *pap, size_t *szp,
    ddi_dma_handle_t *dma_hdlp, ddi_acc_handle_t *acc_hdlp)
{
	uint64_t baser_val, readback;
	uint32_t pgsz_idx;
	size_t entry_sz, table_sz, page_sz;
	uint32_t num_pages;

	baser_val = its_read64(sc, GITS_BASERn(baser_idx));
	entry_sz = GITS_BASERn_ENTRY_SZ_VAL(baser_val);

	/*
	 * Try page sizes in order: 4K, 16K, 64K.
	 * Each BASERn.Size field is 8 bits, encoding (num_pages - 1),
	 * so the maximum is 256 pages at the chosen page size.
	 */
	for (pgsz_idx = GITS_BASER_PGSZ_4K;
	    pgsz_idx <= GITS_BASER_PGSZ_64K; pgsz_idx++) {
		page_sz = gicv3_its_pgsz_to_bytes(pgsz_idx);
		table_sz = P2ROUNDUP(num_entries * entry_sz, page_sz);
		num_pages = table_sz / page_sz;
		if (num_pages <= 256)
			break;
	}

	if (num_pages > 256) {
		dev_err(sc->its_dip, CE_WARN,
		    "BASERn[%u]: table too large (%zu entries * %zu bytes)",
		    baser_idx, num_entries, entry_sz);
		return (-1);
	}

	if (gicv3_contig_alloc(sc->its_dip, table_sz, page_sz,
	    vap, pap, dma_hdlp, acc_hdlp) != DDI_SUCCESS) {
		dev_err(sc->its_dip, CE_WARN,
		    "BASERn[%u]: DMA allocation failed (%zu bytes)",
		    baser_idx, table_sz);
		return (-1);
	}

	*szp = table_sz;

	/*
	 * Construct the BASERn value:
	 *   Valid | InnerCache(RaWaWb) | OuterCache(RaWaWb) |
	 *   Share(IS) | PA | PageSize | (num_pages - 1)
	 * Preserve the Type and Entry_Size fields from the hardware.
	 */
	baser_val = GITS_BASERn_Valid |
	    GITS_BASERn_IC(GIC_CACHE_RaWaWb) |
	    GITS_BASERn_OC(GIC_CACHE_RaWaWb) |
	    GITS_BASERn_SHARE(GIC_SHARE_IS) |
	    (*pap & GITS_BASERn_Physical_Address) |
	    GITS_BASERn_PGSZ(pgsz_idx) |
	    (uint64_t)(num_pages - 1) |
	    (its_read64(sc, GITS_BASERn(baser_idx)) &
	    (GITS_BASERn_Type | GITS_BASERn_Entry_Size));

	its_write64(sc, GITS_BASERn(baser_idx), baser_val);

	/*
	 * Read back to check shareability and page size.
	 *
	 * The hardware may downgrade shareability to non-shareable,
	 * in which case we retry with non-cacheable settings.
	 *
	 * The hardware may also reject the requested page size and
	 * report a smaller one.  If this happens, the DMA memory we
	 * allocated (aligned to the requested page size) doesn't
	 * match what the ITS will use, so we must fail.
	 */
	readback = its_read64(sc, GITS_BASERn(baser_idx));

	if (GITS_BASERn_PGSZ_VAL(readback) != pgsz_idx) {
		dev_err(sc->its_dip, CE_WARN,
		    "BASERn[%u]: hardware rejected page size "
		    "(requested %u, got %lu)",
		    baser_idx, pgsz_idx, GITS_BASERn_PGSZ_VAL(readback));
		gicv3_contig_free(dma_hdlp, acc_hdlp);
		*vap = NULL;
		return (-1);
	}

	if (GITS_BASERn_SHARE_VAL(readback) == GIC_SHARE_NS) {
		baser_val &= ~GITS_BASERn_InnerCache;
		baser_val &= ~GITS_BASERn_OuterCache;
		baser_val &= ~GITS_BASERn_Shareability;
		baser_val |= GITS_BASERn_IC(GIC_CACHE_nC);
		baser_val |= GITS_BASERn_OC(GIC_CACHE_nC);
		baser_val |= GITS_BASERn_SHARE(GIC_SHARE_NS);
		its_write64(sc, GITS_BASERn(baser_idx), baser_val);
	}

	return (0);
}

/*
 * Scan all 8 BASERn registers and allocate the Device and Collection
 * tables.
 */
static int
gicv3_its_init_tables(gicv3_its_state_t *sc)
{
	uint64_t baser_val;
	uint32_t type;
	boolean_t have_devtab = B_FALSE;
	boolean_t have_colltab = B_FALSE;
	boolean_t need_colltab;
	int i;

	need_colltab = (sc->its_hcc == 0);

	for (i = 0; i < 8; i++) {
		baser_val = its_read64(sc, GITS_BASERn(i));
		type = GITS_BASERn_TYPE_VAL(baser_val);

		if (type == GITS_BASER_TYPE_DEVICES && !have_devtab) {
			size_t ndev = 1ULL << sc->its_devbits;

			if (gicv3_its_alloc_table(sc, i, ndev,
			    &sc->its_devtab, &sc->its_devtab_pa,
			    &sc->its_devtab_sz, &sc->its_devtab_dmah,
			    &sc->its_devtab_acch) != 0)
				return (DDI_FAILURE);
			have_devtab = B_TRUE;

		} else if (type == GITS_BASER_TYPE_COLLECTION &&
		    need_colltab && !have_colltab) {
			/*
			 * HCC==0: software must provide a collection table.
			 * Size it for max_ncpus collections.
			 */
			if (gicv3_its_alloc_table(sc, i,
			    (size_t)max_ncpus,
			    &sc->its_colltab, &sc->its_colltab_pa,
			    &sc->its_colltab_sz, &sc->its_colltab_dmah,
			    &sc->its_colltab_acch) != 0)
				return (DDI_FAILURE);
			have_colltab = B_TRUE;
		}
	}

	if (!have_devtab) {
		dev_err(sc->its_dip, CE_WARN,
		    "no Device table found in BASERn registers");
		return (DDI_FAILURE);
	}

	if (need_colltab && !have_colltab) {
		dev_err(sc->its_dip, CE_WARN,
		    "HCC==0 but no Collection table found in BASERn");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Command queue allocation
 *
 * Allocates a 64KB command queue in DMA memory, programs GITS_CBASER
 * with shareability/cacheability, reads back to check for downgrade.
 */

static int
gicv3_its_init_cmdq(gicv3_its_state_t *sc)
{
	uint64_t cbaser_val, readback;

	sc->its_cmd_sz = GICV3_ITS_CMDQ_SIZE;

	if (gicv3_contig_alloc(sc->its_dip, sc->its_cmd_sz,
	    sc->its_cmd_sz,	/* align to queue size */
	    &sc->its_cmd_base, &sc->its_cmd_pa,
	    &sc->its_cmd_dmah, &sc->its_cmd_acch) != DDI_SUCCESS) {
		dev_err(sc->its_dip, CE_WARN,
		    "failed to allocate command queue");
		return (DDI_FAILURE);
	}

	sc->its_cmd_write = 0;

	/*
	 * Program GITS_CBASER:
	 *   Valid | IC(RaWaWb) | OC(RaWaWb) | Share(IS) | PA | Size(15)
	 * Size field = (num_4K_pages - 1) = (16 - 1) = 15
	 */
	cbaser_val = GITS_CBASER_Valid |
	    GITS_CBASER_IC(GIC_CACHE_RaWaWb) |
	    GITS_CBASER_OC(GIC_CACHE_RaWaWb) |
	    GITS_CBASER_SHARE(GIC_SHARE_IS) |
	    (sc->its_cmd_pa & GITS_CBASER_Physical_Address) |
	    (uint64_t)((sc->its_cmd_sz / 4096) - 1);

	its_write64(sc, GITS_CBASER, cbaser_val);

	/*
	 * Read back to check shareability.  If hardware downgraded to
	 * non-shareable, the CPU cache and ITS may not be coherent.
	 * Set the flush flag so submit will call ddi_dma_sync().
	 */
	readback = its_read64(sc, GITS_CBASER);
	if (GITS_CBASER_SHARE_VAL(readback) == GIC_SHARE_NS) {
		sc->its_cmd_needs_flush = B_TRUE;
		cbaser_val &= ~GITS_CBASER_InnerCache;
		cbaser_val &= ~GITS_CBASER_OuterCache;
		cbaser_val &= ~GITS_CBASER_Shareability;
		cbaser_val |= GITS_CBASER_IC(GIC_CACHE_nC);
		cbaser_val |= GITS_CBASER_OC(GIC_CACHE_nC);
		cbaser_val |= GITS_CBASER_SHARE(GIC_SHARE_NS);
		its_write64(sc, GITS_CBASER, cbaser_val);
	} else {
		sc->its_cmd_needs_flush = B_FALSE;
	}

	/* Reset command queue read/write pointers */
	its_write64(sc, GITS_CWRITER, 0);

	return (DDI_SUCCESS);
}

/*
 * Instance lifecycle
 */

static int
gicv3_its_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	int nregs;
	gicv3_its_state_t *sc;
	uint32_t ctlr;
	int timeout_us;
	cpu_t *cp;
	struct regspec *rp;
	struct regspec reg;
	ddi_device_acc_attr_t reg_acc_attr = {
		.devacc_attr_version		= DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder		= DDI_STRICTORDER_ACC,
	};

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	case DDI_PM_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ASSERT3U(cmd, ==, DDI_ATTACH);
	instance = ddi_get_instance(dip);

	/*
	 * Verify required DT properties.
	 *
	 * msi-controller: marks this node as an MSI controller.
	 * #msi-cells: must be 1 (single cell = DeviceID).
	 */
	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_MSI_CONTROLLER)) {
		dev_err(dip, CE_WARN,
		    "ITS node missing required %s property",
		    OBP_MSI_CONTROLLER);
		return (DDI_FAILURE);
	}
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "#msi-cells", -1) != 1) {
		dev_err(dip, CE_WARN,
		    "ITS node #msi-cells must be 1");
		return (DDI_FAILURE);
	}

	if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if (nregs != 1)
		return (DDI_FAILURE);

	if (ddi_soft_state_zalloc(gicv3_its_soft_state,
	    instance) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(gicv3_its_soft_state, instance);
	VERIFY3P(sc, !=, NULL);
	sc->its_dip = dip;
	sc->its_gic_dip = ddi_get_parent(dip);
	VERIFY3P(sc->its_gic_dip, !=, NULL);

	/* Initialise locks */
	mutex_init(&sc->its_cmd_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->its_dev_lock, NULL, MUTEX_DRIVER, NULL);

	/* Initialise per-device state list */
	list_create(&sc->its_devs, sizeof (gicits_dev_state_t),
	    offsetof(gicits_dev_state_t, ds_node));

	/* Map the ITS MMIO frame */
	if (ddi_regs_map_setup(dip, 0, &sc->its_base, 0, 0,
	    &reg_acc_attr, &sc->its_regh) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to map ITS registers");
		goto fail_list;
	}

	/*
	 * Determine the doorbell physical address.
	 *
	 * PCI MSI address registers need the physical address of
	 * GITS_TRANSLATER (offset 0x10040 from the ITS base).  We
	 * obtain the base from the parent-private regspec and apply
	 * the parent's ranges for address translation.
	 */
	rp = i_ddi_rnumber_to_regspec(dip, 0);
	if (rp == NULL) {
		dev_err(dip, CE_WARN,
		    "no reg property for ITS frame");
		goto fail_regs;
	}
	reg = *rp;
	if (i_ddi_apply_range(sc->its_gic_dip, dip, &reg) != 0) {
		dev_err(dip, CE_WARN,
		    "failed to translate ITS register address");
		goto fail_regs;
	}
	sc->its_doorbell_pa = reg.regspec_addr + GITS_TRANSLATER;

	/*
	 * Disable the ITS and wait for quiescence before reconfiguring.
	 */
	ctlr = its_read32(sc, GITS_CTLR);
	if (ctlr & GITS_CTLR_Enabled) {
		its_write32(sc, GITS_CTLR, ctlr & ~GITS_CTLR_Enabled);

		timeout_us = GICV3_ITS_QUIESCE_TIMEOUT_US;
		while (!(its_read32(sc, GITS_CTLR) &
		    GITS_CTLR_Quiescent)) {
			if (timeout_us <= 0) {
				dev_err(dip, CE_WARN,
				    "ITS failed to quiesce");
				goto fail_regs;
			}
			drv_usecwait(10);
			timeout_us -= 10;
		}
	}

	/*
	 * Parse GITS_TYPER.
	 */
	sc->its_typer = its_read64(sc, GITS_TYPER);
	sc->its_pta = GITS_TYPER_PTA_BIT(sc->its_typer);
	sc->its_devbits = GITS_TYPER_DEVBITS(sc->its_typer);
	sc->its_idbits = GITS_TYPER_IDBITS(sc->its_typer);
	sc->its_itt_entry_sz = GITS_TYPER_ITT_ENTRY_SZ(sc->its_typer);
	sc->its_hcc = GITS_TYPER_HCC_VAL(sc->its_typer);

	/*
	 * Compute the maximum usable collection count.  When HCC > 0
	 * the ITS has a fixed number of internal collection slots and
	 * we use cpuid as the collection ID, so CPUs with IDs at or
	 * above HCC simply cannot be ITS interrupt targets.  When
	 * HCC == 0 we allocate a software collection table sized for
	 * max_ncpus.
	 */
	if (sc->its_hcc > 0) {
		sc->its_max_colls = sc->its_hcc;
		if (sc->its_max_colls < (uint32_t)max_ncpus) {
			dev_err(dip, CE_WARN,
			    "ITS has %u hardware collections but system "
			    "supports %d CPUs; LPI targeting limited to "
			    "CPUs 0-%u",
			    sc->its_max_colls, max_ncpus,
			    sc->its_max_colls - 1);
		}
	} else {
		sc->its_max_colls = (uint32_t)max_ncpus;
	}

	/*
	 * Allocate and program the command queue.
	 */
	if (gicv3_its_init_cmdq(sc) != DDI_SUCCESS)
		goto fail_regs;

	/*
	 * Allocate and program the device and collection tables.
	 */
	if (gicv3_its_init_tables(sc) != DDI_SUCCESS)
		goto fail_tables;

	/*
	 * Enable the ITS.
	 */
	ctlr = its_read32(sc, GITS_CTLR);
	its_write32(sc, GITS_CTLR, ctlr | GITS_CTLR_Enabled);

	/*
	 * Issue MAPC for all currently online CPUs and register the
	 * CPU callback atomically under cpu_lock.  Holding cpu_lock
	 * across both the iteration and register_cpu_setup_func()
	 * ensures no CPU can come online in the gap between the two
	 * (pattern from uts/i86pc/os/hma.c).
	 *
	 * NOTE: CPU_SETUP for boot-time secondaries may fire before
	 * the ITS driver loads, in which case the callback never
	 * sees them.  The explicit iteration handles this case.
	 */
	mutex_enter(&cpu_lock);
	cp = cpu_active;
	do {
		if (gicv3_its_cpu_can_target(sc, cp->cpu_id))
			(void) gicv3_its_do_mapc(sc, cp->cpu_id, B_TRUE);
	} while ((cp = cp->cpu_next_onln) != cpu_active);

	register_cpu_setup_func(gicv3_its_cpu_callback, sc);
	mutex_exit(&cpu_lock);

	dev_err(dip, CE_CONT,
	    "!GICv3 ITS: Devbits=%u IDbits=%u ITT_entry=%u HCC=%u "
	    "max_colls=%u PTA=%s doorbell PA 0x%" PRIx64 "\n",
	    sc->its_devbits, sc->its_idbits, sc->its_itt_entry_sz,
	    sc->its_hcc, sc->its_max_colls,
	    sc->its_pta ? "yes" : "no",
	    sc->its_doorbell_pa);

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

fail_tables:
	if (sc->its_devtab != NULL)
		gicv3_contig_free(&sc->its_devtab_dmah,
		    &sc->its_devtab_acch);
	if (sc->its_colltab != NULL)
		gicv3_contig_free(&sc->its_colltab_dmah,
		    &sc->its_colltab_acch);
	gicv3_contig_free(&sc->its_cmd_dmah, &sc->its_cmd_acch);
fail_regs:
	ddi_regs_map_free(&sc->its_regh);
fail_list:
	list_destroy(&sc->its_devs);
	mutex_destroy(&sc->its_dev_lock);
	mutex_destroy(&sc->its_cmd_lock);
	ddi_soft_state_free(gicv3_its_soft_state, instance);
	return (DDI_FAILURE);
}

static int
gicv3_its_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/*
	 * Cannot evacuate an interrupt controller.
	 */
	return (DDI_FAILURE);
}

/*
 * Module plumbing
 *
 * bus_ops is required so that process_intr_ops() can find the bus_intr_op
 * entry point when the DDI framework routes operations to the ITS node.
 *
 * The ITS acts as a nexus for interrupt operations only.  It does not
 * enumerate child devices.
 */
static struct bus_ops gicv3_its_bus_ops = {
	.busops_rev		= BUSO_REV,
	.bus_intr_op		= gicv3_its_intr_ops,
};

static struct dev_ops gicv3_its_ops = {
	.devo_rev		= DEVO_REV,
	.devo_refcnt		= 0,
	.devo_getinfo		= ddi_no_info,
	.devo_identify		= nulldev,
	.devo_probe		= nulldev,
	.devo_attach		= gicv3_its_attach,
	.devo_detach		= gicv3_its_detach,
	.devo_reset		= nodev,
	.devo_cb_ops		= NULL,
	.devo_bus_ops		= &gicv3_its_bus_ops,
	.devo_power		= NULL,
	.devo_quiesce		= ddi_quiesce_not_needed,
};

static struct modldrv modldrv = {
	.drv_modops		= &mod_driverops,
	.drv_linkinfo		= "GICv3 ITS MSI Controller",
	.drv_dev_ops		= &gicv3_its_ops,
};

static struct modlinkage modlinkage = {
	.ml_rev			= MODREV_1,
	.ml_linkage		= { &modldrv, NULL },
};

int
_init(void)
{
	int ret;

	if ((ret = ddi_soft_state_init(&gicv3_its_soft_state,
	    sizeof (gicv3_its_state_t), 1)) != 0) {
		return (ret);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&gicv3_its_soft_state);
		return (ret);
	}

	return (ret);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage)) != 0)
		return (ret);

	ddi_soft_state_fini(&gicv3_its_soft_state);
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
