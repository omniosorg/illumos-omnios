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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Hayashi Naoyuki
 * Copyright 2024 Michael van der Westhuizen
 * Copyright 2026 Oxide Computer Company
 */

/*
 * VIRTIO FRAMEWORK: Operations via the MMIO transport (version 1).
 *
 * MMIO transport version 1 is a legacy-equivalent interface: it uses native
 * endianness and provides 32-bit feature registers. Unlike PCI legacy, the
 * status register is 32-bit and the ISR requires an explicit ACK write.
 *
 * For design and usage documentation, see the comments in "virtio.h".
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

#include "virtio.h"
#include "virtio_impl.h"

/*
 * Reads and writes to the MMIO register space.
 */

static inline uint32_t
virtio_mmio_get32(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get32(vio->vio_barh,
	    (uint32_t *)(vio->vio_bar + offset)));
}

static inline void
virtio_mmio_put32(virtio_t *vio, uintptr_t offset, uint32_t value)
{
	ddi_put32(vio->vio_barh,
	    (uint32_t *)(vio->vio_bar + offset), value);
}

/*
 * Device feature negotiation. MMIO v1 only supports 32-bit features.
 */

static uint64_t
virtio_mmio_device_get_features(virtio_t *vio)
{
	virtio_mmio_put32(vio, VIRTIO_MMIO_HOST_FEATURES_SEL, 0);
	return (virtio_mmio_get32(vio, VIRTIO_MMIO_HOST_FEATURES));
}

static bool
virtio_mmio_device_set_features(virtio_t *vio, uint64_t features)
{
	/* The MMIO v1 interface only supports 32 feature bits */
	VERIFY0(features >> 32);
	virtio_mmio_put32(vio, VIRTIO_MMIO_GUEST_FEATURES_SEL, 0);
	virtio_mmio_put32(vio, VIRTIO_MMIO_GUEST_FEATURES, features);
	return (true);
}

/*
 * Device status register. Unlike PCI legacy (8-bit), MMIO uses 32-bit.
 */

static void
virtio_mmio_set_status_locked(virtio_t *vio, uint8_t status)
{
	VERIFY3U(status, !=, 0);
	VERIFY(MUTEX_HELD(&vio->vio_mutex));

	uint8_t old = virtio_mmio_get32(vio, VIRTIO_MMIO_STATUS);
	virtio_mmio_put32(vio, VIRTIO_MMIO_STATUS, status | old);
}

static uint8_t
virtio_mmio_get_status(virtio_t *vio)
{
	return (virtio_mmio_get32(vio, VIRTIO_MMIO_STATUS));
}

static void
virtio_mmio_device_reset_locked(virtio_t *vio)
{
	VERIFY(MUTEX_HELD(&vio->vio_mutex));
	virtio_mmio_put32(vio, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_RESET);
}

/*
 * Interrupt status. Unlike PCI where reading ISR auto-clears, MMIO
 * requires an explicit ACK write.
 */

static uint8_t
virtio_mmio_isr_status(virtio_t *vio)
{
	uint32_t isr;

	isr = virtio_mmio_get32(vio, VIRTIO_MMIO_INTERRUPT_STATUS);
	virtio_mmio_put32(vio, VIRTIO_MMIO_INTERRUPT_ACK, isr);

	return ((uint8_t)isr);
}

/*
 * MSI-X operations. MMIO has no MSI-X support; these are no-ops.
 */

static void
virtio_mmio_msix_config_set(virtio_t *vio, uint16_t msi)
{
}

static uint16_t
virtio_mmio_msix_config_get(virtio_t *vio)
{
	return (VIRTIO_LEGACY_MSI_NO_VECTOR);
}

static void
virtio_mmio_msix_queue_set(virtio_t *vio, uint16_t qidx, uint16_t msi)
{
}

static uint16_t
virtio_mmio_msix_queue_get(virtio_t *vio, uint16_t qidx)
{
	return (VIRTIO_LEGACY_MSI_NO_VECTOR);
}

/*
 * Queue operations.
 */

static void
virtio_mmio_queue_notify(virtio_queue_t *viq)
{
	virtio_mmio_put32(viq->viq_virtio, VIRTIO_MMIO_QUEUE_NOTIFY,
	    viq->viq_index);
}

static void
virtio_mmio_queue_select(virtio_t *vio, uint16_t qidx)
{
	virtio_mmio_put32(vio, VIRTIO_MMIO_QUEUE_SEL, qidx);
}

static uint16_t
virtio_mmio_queue_size_get(virtio_t *vio, uint16_t qidx)
{
	uint16_t val;

	virtio_acquireq(vio, qidx);
	val = MIN(virtio_mmio_get32(vio, VIRTIO_MMIO_QUEUE_NUM_MAX),
	    MMIO_VQ_MAX);
	virtio_releaseq(vio);

	return (val);
}

static void
virtio_mmio_queue_size_set(virtio_t *vio, uint16_t qidx, uint16_t qsz)
{
	virtio_acquireq(vio, qidx);
	virtio_mmio_put32(vio, VIRTIO_MMIO_QUEUE_ALIGN, MMIO_VQ_ALIGN);
	virtio_mmio_put32(vio, VIRTIO_MMIO_QUEUE_NUM, qsz);
	virtio_releaseq(vio);
}

static bool
virtio_mmio_queue_enable_get(virtio_t *vio, uint16_t qidx)
{
	/* MMIO v1 queues are always enabled once configured (like legacy) */
	return (true);
}

static void
virtio_mmio_queue_enable_set(virtio_t *vio, uint16_t qidx, bool enable)
{
	/* MMIO v1 queues are always enabled once configured (like legacy) */
}

static void
virtio_mmio_queue_addr_set(virtio_t *vio, uint16_t qidx, uint64_t descaddr,
    uint64_t availaddr __unused, uint64_t usedaddr __unused)
{
	virtio_acquireq(vio, qidx);
	virtio_mmio_put32(vio, VIRTIO_MMIO_GUEST_PAGE_SIZE,
	    1 << VIRTIO_PAGE_SHIFT);
	virtio_mmio_put32(vio, VIRTIO_MMIO_QUEUE_PFN,
	    descaddr >> VIRTIO_PAGE_SHIFT);
	virtio_releaseq(vio);
}

/*
 * Device-specific configuration space. MMIO v1 provides direct 32-bit
 * register access at offset VIRTIO_MMIO_CONFIG, using native endianness.
 * There is no configuration generation number.
 */

static uint8_t
virtio_mmio_devcfg_getgen(virtio_t *vio)
{
	/* MMIO v1 has no configuration generation number */
	return (0);
}

static uint8_t
virtio_mmio_devcfg_get8(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get8(vio->vio_barh,
	    (uint8_t *)(vio->vio_bar + VIRTIO_MMIO_CONFIG + offset)));
}

static uint16_t
virtio_mmio_devcfg_get16(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get16(vio->vio_barh,
	    (uint16_t *)(vio->vio_bar + VIRTIO_MMIO_CONFIG + offset)));
}

static uint32_t
virtio_mmio_devcfg_get32(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get32(vio->vio_barh,
	    (uint32_t *)(vio->vio_bar + VIRTIO_MMIO_CONFIG + offset)));
}

static uint64_t
virtio_mmio_devcfg_get64(virtio_t *vio, uintptr_t offset)
{
	/*
	 * On at least some systems, a 64-bit read or write to this region is
	 * not possible. MMIO v1 has no generation number, so we must
	 * continue to read both halves until we get the same value twice.
	 */
	uintptr_t o_lo = VIRTIO_MMIO_CONFIG + offset;
	uintptr_t o_hi = o_lo + 4;

	uint64_t val = ddi_get32(vio->vio_barh,
	    (uint32_t *)(vio->vio_bar + o_lo)) |
	    ((uint64_t)ddi_get32(vio->vio_barh,
	    (uint32_t *)(vio->vio_bar + o_hi)) << 32);

	for (;;) {
		uint64_t tval = ddi_get32(vio->vio_barh,
		    (uint32_t *)(vio->vio_bar + o_lo)) |
		    ((uint64_t)ddi_get32(vio->vio_barh,
		    (uint32_t *)(vio->vio_bar + o_hi)) << 32);

		if (tval == val) {
			break;
		}

		val = tval;
	}

	return (val);
}

static void
virtio_mmio_devcfg_put8(virtio_t *vio, uintptr_t offset, uint8_t value)
{
	ddi_put8(vio->vio_barh,
	    (uint8_t *)(vio->vio_bar + VIRTIO_MMIO_CONFIG + offset), value);
}

static void
virtio_mmio_devcfg_put16(virtio_t *vio, uintptr_t offset, uint16_t value)
{
	ddi_put16(vio->vio_barh,
	    (uint16_t *)(vio->vio_bar + VIRTIO_MMIO_CONFIG + offset), value);
}

static void
virtio_mmio_devcfg_put32(virtio_t *vio, uintptr_t offset, uint32_t value)
{
	ddi_put32(vio->vio_barh,
	    (uint32_t *)(vio->vio_bar + VIRTIO_MMIO_CONFIG + offset), value);
}

/*
 * Ops vector for the MMIO transport.
 */
virtio_ops_t virtio_mmio_ops = {
	.vop_device_get_features = virtio_mmio_device_get_features,
	.vop_device_set_features = virtio_mmio_device_set_features,
	.vop_set_status_locked = virtio_mmio_set_status_locked,
	.vop_get_status = virtio_mmio_get_status,
	.vop_device_reset_locked = virtio_mmio_device_reset_locked,
	.vop_isr_status = virtio_mmio_isr_status,
	.vop_msix_config_get = virtio_mmio_msix_config_get,
	.vop_msix_config_set = virtio_mmio_msix_config_set,
	.vop_queue_notify = virtio_mmio_queue_notify,

	.vop_queue_select = virtio_mmio_queue_select,
	.vop_queue_size_get = virtio_mmio_queue_size_get,
	.vop_queue_size_set = virtio_mmio_queue_size_set,
	/* MMIO v1 doesn't use per-queue notification offsets */
	.vop_queue_noff_get = NULL,
	.vop_queue_enable_get = virtio_mmio_queue_enable_get,
	.vop_queue_enable_set = virtio_mmio_queue_enable_set,
	.vop_queue_addr_set = virtio_mmio_queue_addr_set,
	.vop_msix_queue_get = virtio_mmio_msix_queue_get,
	.vop_msix_queue_set = virtio_mmio_msix_queue_set,

	.vop_device_cfg_gen = virtio_mmio_devcfg_getgen,
	.vop_device_cfg_get8 = virtio_mmio_devcfg_get8,
	.vop_device_cfg_get16 = virtio_mmio_devcfg_get16,
	.vop_device_cfg_get32 = virtio_mmio_devcfg_get32,
	.vop_device_cfg_get64 = virtio_mmio_devcfg_get64,
	.vop_device_cfg_put8 = virtio_mmio_devcfg_put8,
	.vop_device_cfg_put16 = virtio_mmio_devcfg_put16,
	.vop_device_cfg_put32 = virtio_mmio_devcfg_put32,
};
