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
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2024 Michael van der Westhuizen
 * Copyright 2025 Oxide Computer Company
 * Copyright 2026 Hans Rosenfeld
 */

/*
 * VIRTIO FRAMEWORK
 *
 * For design and usage documentation, see the comments in "virtio.h".
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/avintr.h>
#include <sys/spl.h>
#include <sys/list.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/sysmacros.h>
#include <sys/stdbit.h>

#include "virtio.h"
#include "virtio_impl.h"

/*
 * Linkage structures
 */
static struct modlmisc virtio_modlmisc = {
	.misc_modops =			&mod_miscops,
	.misc_linkinfo =		"VIRTIO common routines",
};

static struct modlinkage virtio_modlinkage = {
	.ml_rev =			MODREV_1,
	.ml_linkage =			{ &virtio_modlmisc, NULL }
};

int
_init(void)
{
	return (mod_install(&virtio_modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&virtio_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&virtio_modlinkage, modinfop));
}

static int virtio_chain_append_impl(virtio_chain_t *, uint64_t, size_t,
    uint16_t);
static int virtio_interrupts_setup(virtio_t *, int);
static void virtio_interrupts_teardown(virtio_t *);
static void virtio_interrupts_disable_locked(virtio_t *);

/*
 * We use the same device access attributes for BAR mapping and access to the
 * virtqueue memory.
 */
ddi_device_acc_attr_t virtio_acc_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags =	DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder =	DDI_STORECACHING_OK_ACC,
	.devacc_attr_access =		DDI_DEFAULT_ACC
};


/*
 * DMA attributes for the memory given to the device for queue management.
 */
ddi_dma_attr_t virtio_dma_attr_queue = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x0000000000000000,
	/*
	 * Queue memory is aligned on VIRTIO_PAGE_SIZE with the address shifted
	 * down by VIRTIO_PAGE_SHIFT before being passed to the device in a
	 * 32-bit register.
	 */
	.dma_attr_addr_hi =		0x00000FFFFFFFF000,
	.dma_attr_count_max =		0x00000000FFFFFFFF,
	.dma_attr_align =		VIRTIO_PAGE_SIZE,
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0x00000000FFFFFFFF,
	.dma_attr_seg =			0x00000000FFFFFFFF,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		1,
	.dma_attr_flags =		0
};

/*
 * DMA attributes for the the allocation of indirect descriptor lists.  The
 * indirect list is referenced by a regular descriptor entry: the physical
 * address field is 64 bits wide, but the length field is only 32 bits.  Each
 * descriptor is 16 bytes long.
 */
ddi_dma_attr_t virtio_dma_attr_indirect = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x0000000000000000,
	.dma_attr_addr_hi =		0xFFFFFFFFFFFFFFFF,
	.dma_attr_count_max =		0x00000000FFFFFFFF,
	.dma_attr_align =		sizeof (struct virtio_vq_desc),
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0x00000000FFFFFFFF,
	.dma_attr_seg =			0x00000000FFFFFFFF,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		1,
	.dma_attr_flags =		0
};


uint8_t
virtio_get8(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get8(vio->vio_barh, (uint8_t *)(vio->vio_bar + offset)));
}

uint16_t
virtio_get16(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get16(vio->vio_barh, (uint16_t *)(vio->vio_bar + offset)));
}

uint32_t
virtio_get32(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get32(vio->vio_barh, (uint32_t *)(vio->vio_bar + offset)));
}

void
virtio_put8(virtio_t *vio, uintptr_t offset, uint8_t value)
{
	ddi_put8(vio->vio_barh, (uint8_t *)(vio->vio_bar + offset), value);
}

void
virtio_put16(virtio_t *vio, uintptr_t offset, uint16_t value)
{
	ddi_put16(vio->vio_barh, (uint16_t *)(vio->vio_bar + offset), value);
}

void
virtio_put32(virtio_t *vio, uintptr_t offset, uint32_t value)
{
	ddi_put32(vio->vio_barh, (uint32_t *)(vio->vio_bar + offset), value);
}

virtio_t *
virtio_init(dev_info_t *dip, uint64_t driver_features, boolean_t allow_indirect)
{
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, 0,
	    VIRTIO_MMIO_PROPERTY_NAME) == 1)
		return (virtio_mmio_init(dip, driver_features, allow_indirect));

	return (virtio_pci_init(dip, driver_features, allow_indirect));
}

void
virtio_fini(virtio_t *vio, boolean_t failed)
{
	mutex_enter(&vio->vio_mutex);

	virtio_interrupts_teardown(vio);

	virtio_queue_t *viq;
	while ((viq = list_remove_head(&vio->vio_queues)) != NULL) {
		virtio_queue_free(viq);
	}
	list_destroy(&vio->vio_queues);

	if (failed) {
		/*
		 * Signal to the host that device setup failed.
		 */
		virtio_set_status_locked(vio, VIRTIO_STATUS_FAILED);
	} else {
		virtio_device_reset_locked(vio);
	}

	/*
	 * We don't need to do anything for the provider initlevel, as it
	 * merely records the fact that virtio_init_complete() was called.
	 */
	vio->vio_initlevel &= ~VIRTIO_INITLEVEL_PROVIDER;

	if (vio->vio_initlevel & VIRTIO_INITLEVEL_REGS) {
		/*
		 * Unmap PCI BAR0.
		 */
		ddi_regs_map_free(&vio->vio_barh);

		vio->vio_initlevel &= ~VIRTIO_INITLEVEL_REGS;
	}

	/*
	 * Ensure we have torn down everything we set up.
	 */
	vio->vio_initlevel &= ~VIRTIO_INITLEVEL_SHUTDOWN;
	VERIFY0(vio->vio_initlevel);

	mutex_exit(&vio->vio_mutex);
	mutex_destroy(&vio->vio_mutex);

	kmem_free(vio, sizeof (*vio));
}

void
virtio_set_status_locked(virtio_t *vio, uint8_t status)
{
	ASSERT(vio->vio_implfuncs);
	vio->vio_implfuncs->vi_set_status_locked(vio, status);
}

void
virtio_set_status(virtio_t *vio, uint8_t status)
{
	ASSERT(vio->vio_implfuncs);
	vio->vio_implfuncs->vi_set_status(vio, status);
}

/*
 * Some virtio devices can change their device configuration state at any
 * time. This function may be called by the driver during the initialisation
 * phase - before calling virtio_init_complete() - in order to register a
 * handler function which will be called when the device configuration space
 * is updated.
 */
void
virtio_register_cfgchange_handler(virtio_t *vio, ddi_intr_handler_t *func,
    void *funcarg)
{
	VERIFY(!(vio->vio_initlevel & VIRTIO_INITLEVEL_INT_ADDED));
	VERIFY(!vio->vio_cfgchange_handler_added);

	mutex_enter(&vio->vio_mutex);
	vio->vio_cfgchange_handler = func;
	vio->vio_cfgchange_handlerarg = funcarg;
	mutex_exit(&vio->vio_mutex);
}

/*
 * This function must be called by the driver once it has completed early setup
 * calls.  The value of "allowed_interrupt_types" is a mask of interrupt types
 * (DDI_INTR_TYPE_MSIX, etc) that we'll try to use when installing handlers, or
 * the special value 0 to allow the system to use any available type.
 */
int
virtio_init_complete(virtio_t *vio, int allowed_interrupt_types)
{
	VERIFY(!(vio->vio_initlevel & VIRTIO_INITLEVEL_PROVIDER));
	vio->vio_initlevel |= VIRTIO_INITLEVEL_PROVIDER;

	if (!list_is_empty(&vio->vio_queues) ||
	    vio->vio_cfgchange_handler != NULL) {
		/*
		 * Set up interrupts for the queues that have been registered.
		 */
		if (virtio_interrupts_setup(vio, allowed_interrupt_types) !=
		    DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	/*
	 * We can allocate the mutex once we know the priority.
	 */
	mutex_destroy(&vio->vio_mutex);
	mutex_init(&vio->vio_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	for (virtio_queue_t *viq = list_head(&vio->vio_queues); viq != NULL;
	    viq = list_next(&vio->vio_queues, viq)) {
		mutex_destroy(&viq->viq_mutex);
		mutex_init(&viq->viq_mutex, NULL, MUTEX_DRIVER,
		    virtio_intr_pri(vio));
	}

	virtio_set_status(vio, VIRTIO_STATUS_DRIVER_OK);

	return (DDI_SUCCESS);
}

boolean_t
virtio_features_present(virtio_t *vio, uint64_t feature_mask)
{
	return ((vio->vio_features & feature_mask) == feature_mask);
}

uint32_t
virtio_features(virtio_t *vio)
{
	return (vio->vio_features);
}

void *
virtio_intr_pri(virtio_t *vio)
{
	VERIFY(vio->vio_initlevel & VIRTIO_INITLEVEL_INT_ADDED);

	return (DDI_INTR_PRI(vio->vio_interrupt_priority));
}

void
virtio_device_reset_locked(virtio_t *vio)
{
	ASSERT(vio->vio_implfuncs);
	vio->vio_implfuncs->vi_device_reset_locked(vio);
}

void
virtio_device_reset(virtio_t *vio)
{
	mutex_enter(&vio->vio_mutex);
	virtio_device_reset_locked(vio);
	mutex_exit(&vio->vio_mutex);
}

virtio_queue_t *
virtio_queue_alloc(virtio_t *vio, uint16_t qidx, const char *name,
    ddi_intr_handler_t *func, void *funcarg, boolean_t force_direct,
    uint_t max_segs)
{
	ASSERT(vio->vio_implfuncs);
	return (vio->vio_implfuncs->vi_queue_alloc(vio, qidx, name,
	    func, funcarg, force_direct, max_segs));
}

void
virtio_queue_free(virtio_queue_t *viq)
{
	virtio_t	*vio;

	if (viq == NULL)
		return;

	ASSERT(viq->viq_virtio);
	vio = viq->viq_virtio;
	ASSERT(vio->vio_implfuncs);

	vio->vio_implfuncs->vi_queue_free(viq);
}

/*
 * Some queues are effectively long-polled; the driver submits a series of
 * buffers and the device only returns them when there is data available.
 * During detach, we need to coordinate the return of these buffers.  Calling
 * "virtio_shutdown()" will reset the device, then allow the removal of all
 * buffers that were in flight at the time of shutdown via
 * "virtio_queue_evacuate()".
 */
void
virtio_shutdown(virtio_t *vio)
{
	mutex_enter(&vio->vio_mutex);
	if (vio->vio_initlevel & VIRTIO_INITLEVEL_SHUTDOWN) {
		/*
		 * Shutdown has been performed already.
		 */
		mutex_exit(&vio->vio_mutex);
		return;
	}

	/*
	 * First, mark all of the queues as shutdown.  This will prevent any
	 * further activity.
	 */
	for (virtio_queue_t *viq = list_head(&vio->vio_queues); viq != NULL;
	    viq = list_next(&vio->vio_queues, viq)) {
		mutex_enter(&viq->viq_mutex);
		viq->viq_shutdown = B_TRUE;
		mutex_exit(&viq->viq_mutex);
	}

	/*
	 * Now, reset the device.  This removes any queue configuration on the
	 * device side.
	 */
	virtio_device_reset_locked(vio);
	vio->vio_initlevel |= VIRTIO_INITLEVEL_SHUTDOWN;
	mutex_exit(&vio->vio_mutex);
}

/*
 * Common implementation of quiesce(9E) for simple Virtio-based devices.
 */
int
virtio_quiesce(virtio_t *vio)
{
	if (vio->vio_initlevel & VIRTIO_INITLEVEL_SHUTDOWN) {
		/*
		 * Device has already been reset.
		 */
		return (DDI_SUCCESS);
	}

	/*
	 * When we reset the device, it should immediately stop using any DMA
	 * memory we've previously passed to it.  All queue configuration is
	 * discarded.  This is good enough for quiesce(9E).
	 */
	virtio_device_reset_locked(vio);

	return (DDI_SUCCESS);
}

/*
 * DEVICE-SPECIFIC REGISTER ACCESS
 *
 * Note that these functions take the mutex to avoid racing with interrupt
 * enable/disable, when the device-specific offset can potentially change.
 */

uint8_t
virtio_dev_get8(virtio_t *vio, uintptr_t offset)
{
	mutex_enter(&vio->vio_mutex);
	uint8_t r = virtio_get8(vio, vio->vio_config_offset + offset);
	mutex_exit(&vio->vio_mutex);

	return (r);
}

uint16_t
virtio_dev_get16(virtio_t *vio, uintptr_t offset)
{
	mutex_enter(&vio->vio_mutex);
	uint16_t r = virtio_get16(vio, vio->vio_config_offset + offset);
	mutex_exit(&vio->vio_mutex);

	return (r);
}

uint32_t
virtio_dev_get32(virtio_t *vio, uintptr_t offset)
{
	mutex_enter(&vio->vio_mutex);
	uint32_t r = virtio_get32(vio, vio->vio_config_offset + offset);
	mutex_exit(&vio->vio_mutex);

	return (r);
}

uint64_t
virtio_dev_get64(virtio_t *vio, uintptr_t offset)
{
	mutex_enter(&vio->vio_mutex);
	/*
	 * On at least some systems, a 64-bit read or write to this BAR is not
	 * possible.  For legacy devices, there is no generation number to use
	 * to determine if configuration may have changed half-way through a
	 * read.  We need to continue to read both halves of the value until we
	 * read the same value at least twice.
	 */
	uintptr_t o_lo = vio->vio_config_offset + offset;
	uintptr_t o_hi = o_lo + 4;

	uint64_t val = virtio_get32(vio, o_lo) |
	    ((uint64_t)virtio_get32(vio, o_hi) << 32);

	for (;;) {
		uint64_t tval = virtio_get32(vio, o_lo) |
		    ((uint64_t)virtio_get32(vio, o_hi) << 32);

		if (tval == val) {
			break;
		}

		val = tval;
	}

	mutex_exit(&vio->vio_mutex);
	return (val);
}

void
virtio_dev_put8(virtio_t *vio, uintptr_t offset, uint8_t value)
{
	mutex_enter(&vio->vio_mutex);
	virtio_put8(vio, vio->vio_config_offset + offset, value);
	mutex_exit(&vio->vio_mutex);
}

void
virtio_dev_put16(virtio_t *vio, uintptr_t offset, uint16_t value)
{
	mutex_enter(&vio->vio_mutex);
	virtio_put16(vio, vio->vio_config_offset + offset, value);
	mutex_exit(&vio->vio_mutex);
}

void
virtio_dev_put32(virtio_t *vio, uintptr_t offset, uint32_t value)
{
	mutex_enter(&vio->vio_mutex);
	virtio_put32(vio, vio->vio_config_offset + offset, value);
	mutex_exit(&vio->vio_mutex);
}

/*
 * VIRTQUEUE MANAGEMENT
 */

int
virtio_inflight_compar(const void *lp, const void *rp)
{
	const virtio_chain_t *l = lp;
	const virtio_chain_t *r = rp;

	if (l->vic_head < r->vic_head) {
		return (-1);
	} else if (l->vic_head > r->vic_head) {
		return (1);
	} else {
		return (0);
	}
}

void
virtio_queue_no_interrupt(virtio_queue_t *viq, boolean_t stop_interrupts)
{
	mutex_enter(&viq->viq_mutex);

	if (stop_interrupts) {
		viq->viq_dma_driver->vqdr_flags |= VIRTQ_AVAIL_F_NO_INTERRUPT;
	} else {
		viq->viq_dma_driver->vqdr_flags &= ~VIRTQ_AVAIL_F_NO_INTERRUPT;
	}
	VIRTQ_DMA_SYNC_FORDEV(viq);

	mutex_exit(&viq->viq_mutex);
}

static virtio_chain_t *
virtio_queue_complete(virtio_queue_t *viq, uint_t index)
{
	VERIFY(MUTEX_HELD(&viq->viq_mutex));

	virtio_chain_t *vic;

	virtio_chain_t search;
	bzero(&search, sizeof (search));
	search.vic_head = index;

	if ((vic = avl_find(&viq->viq_inflight, &search, NULL)) == NULL) {
		return (NULL);
	}
	avl_remove(&viq->viq_inflight, vic);

	return (vic);
}

uint_t
virtio_queue_size(virtio_queue_t *viq)
{
	return (viq->viq_size);
}

uint_t
virtio_queue_nactive(virtio_queue_t *viq)
{
	mutex_enter(&viq->viq_mutex);
	uint_t r = avl_numnodes(&viq->viq_inflight);
	mutex_exit(&viq->viq_mutex);

	return (r);
}

virtio_chain_t *
virtio_queue_poll(virtio_queue_t *viq)
{
	mutex_enter(&viq->viq_mutex);
	if (viq->viq_shutdown) {
		/*
		 * The device has been reset by virtio_shutdown(), and queue
		 * processing has been halted.  Any previously submitted chains
		 * will be evacuated using virtio_queue_evacuate().
		 */
		mutex_exit(&viq->viq_mutex);
		return (NULL);
	}

	VIRTQ_DMA_SYNC_FORKERNEL(viq);
	if (viq->viq_device_index == viq->viq_dma_device->vqde_index) {
		/*
		 * If the device index has not changed since the last poll,
		 * there are no new chains to process.
		 */
		mutex_exit(&viq->viq_mutex);
		return (NULL);
	}

	/*
	 * We need to ensure that all reads from the descriptor (vqde_ring[])
	 * and any referenced memory by the descriptor occur after we have read
	 * the descriptor index value above (vqde_index).
	 */
	membar_consumer();

	uint16_t index = (viq->viq_device_index++) % viq->viq_size;
	uint16_t start = viq->viq_dma_device->vqde_ring[index].vqe_start;
	uint32_t len = viq->viq_dma_device->vqde_ring[index].vqe_len;

	virtio_chain_t *vic;
	if ((vic = virtio_queue_complete(viq, start)) == NULL) {
		/*
		 * We could not locate a chain for this descriptor index, which
		 * suggests that something has gone horribly wrong.
		 */
		dev_err(viq->viq_virtio->vio_dip, CE_PANIC,
		    "queue \"%s\" ring entry %u (descriptor %u) has no chain",
		    viq->viq_name, (uint16_t)index, (uint16_t)start);
	}

	vic->vic_received_length = len;

	mutex_exit(&viq->viq_mutex);

	return (vic);
}

/*
 * After a call to "virtio_shutdown()", the driver must retrieve any previously
 * submitted chains and free any associated resources.
 */
virtio_chain_t *
virtio_queue_evacuate(virtio_queue_t *viq)
{
	virtio_t *vio = viq->viq_virtio;

	mutex_enter(&vio->vio_mutex);
	if (!(vio->vio_initlevel & VIRTIO_INITLEVEL_SHUTDOWN)) {
		dev_err(vio->vio_dip, CE_PANIC,
		    "virtio_queue_evacuate() without virtio_shutdown()");
	}
	mutex_exit(&vio->vio_mutex);

	mutex_enter(&viq->viq_mutex);
	VERIFY(viq->viq_shutdown);

	virtio_chain_t *vic = avl_first(&viq->viq_inflight);
	if (vic != NULL) {
		avl_remove(&viq->viq_inflight, vic);
	}

	mutex_exit(&viq->viq_mutex);

	return (vic);
}

/*
 * VIRTQUEUE DESCRIPTOR CHAIN MANAGEMENT
 */

/*
 * When the device returns a descriptor chain to the driver, it may provide the
 * length in bytes of data written into the chain.  Client drivers should use
 * this value with care; the specification suggests some device implementations
 * have not always provided a useful or correct value.
 */
size_t
virtio_chain_received_length(virtio_chain_t *vic)
{
	return (vic->vic_received_length);
}

/*
 * Allocate a descriptor chain for use with this queue.  The "kmflags" value
 * may be KM_SLEEP or KM_NOSLEEP as per kmem_alloc(9F).
 */
virtio_chain_t *
virtio_chain_alloc(virtio_queue_t *viq, int kmflags)
{
	virtio_t *vio = viq->viq_virtio;
	virtio_chain_t *vic;
	uint_t cap;

	/*
	 * Direct descriptors are known by their index in the descriptor table
	 * for the queue.  We use the variable-length array member at the end
	 * of the chain tracking object to hold the list of direct descriptors
	 * assigned to this chain.
	 */
	if (viq->viq_indirect) {
		/*
		 * When using indirect descriptors we still need one direct
		 * descriptor entry to hold the physical address and length of
		 * the indirect descriptor table.
		 */
		cap = 1;
	} else {
		/*
		 * For direct descriptors we need to be able to track a
		 * descriptor for each possible segment in a single chain.
		 */
		cap = viq->viq_max_segs;
	}

	size_t vicsz = sizeof (*vic) + sizeof (uint16_t) * cap;
	if ((vic = kmem_zalloc(vicsz, kmflags)) == NULL) {
		return (NULL);
	}
	vic->vic_vq = viq;
	vic->vic_direct_capacity = cap;

	if (viq->viq_indirect) {
		/*
		 * Allocate an indirect descriptor list with the appropriate
		 * number of entries.
		 */
		if (virtio_dma_init(vio, &vic->vic_indirect_dma,
		    sizeof (virtio_vq_desc_t) * viq->viq_max_segs,
		    &virtio_dma_attr_indirect,
		    DDI_DMA_CONSISTENT | DDI_DMA_WRITE,
		    kmflags) != DDI_SUCCESS) {
			goto fail;
		}

		/*
		 * Allocate a single descriptor to hold the indirect list.
		 * Leave the length as zero for now; it will be set to include
		 * any occupied entries at push time.
		 */
		mutex_enter(&viq->viq_mutex);
		if (virtio_chain_append_impl(vic,
		    virtio_dma_cookie_pa(&vic->vic_indirect_dma, 0), 0,
		    VIRTQ_DESC_F_INDIRECT) != DDI_SUCCESS) {
			mutex_exit(&viq->viq_mutex);
			goto fail;
		}
		mutex_exit(&viq->viq_mutex);
		VERIFY3U(vic->vic_direct_used, ==, 1);

		/*
		 * Don't set the indirect capacity until after we've installed
		 * the direct descriptor which points at the indirect list, or
		 * virtio_chain_append_impl() will be confused.
		 */
		vic->vic_indirect_capacity = viq->viq_max_segs;
	}

	return (vic);

fail:
	virtio_dma_fini(&vic->vic_indirect_dma);
	kmem_free(vic, vicsz);
	return (NULL);
}

void *
virtio_chain_data(virtio_chain_t *vic)
{
	return (vic->vic_data);
}

void
virtio_chain_data_set(virtio_chain_t *vic, void *data)
{
	vic->vic_data = data;
}

void
virtio_chain_clear(virtio_chain_t *vic)
{
	if (vic->vic_indirect_capacity != 0) {
		/*
		 * There should only be one direct descriptor, which points at
		 * our indirect descriptor list.  We don't want to clear it
		 * here.
		 */
		VERIFY3U(vic->vic_direct_capacity, ==, 1);

		if (vic->vic_indirect_used > 0) {
			/*
			 * Clear out the indirect descriptor table.
			 */
			vic->vic_indirect_used = 0;
			bzero(virtio_dma_va(&vic->vic_indirect_dma, 0),
			    virtio_dma_size(&vic->vic_indirect_dma));
		}

	} else if (vic->vic_direct_capacity > 0) {
		/*
		 * Release any descriptors that were assigned to us previously.
		 */
		for (uint_t i = 0; i < vic->vic_direct_used; i++) {
			id_free(vic->vic_vq->viq_descmap, vic->vic_direct[i]);
			vic->vic_direct[i] = 0;
		}
		vic->vic_direct_used = 0;
	}
}

void
virtio_chain_free(virtio_chain_t *vic)
{
	/*
	 * First ensure that we have released any descriptors used by this
	 * chain.
	 */
	virtio_chain_clear(vic);

	if (vic->vic_indirect_capacity > 0) {
		/*
		 * Release the direct descriptor that points to our indirect
		 * descriptor list.
		 */
		VERIFY3U(vic->vic_direct_capacity, ==, 1);
		id_free(vic->vic_vq->viq_descmap, vic->vic_direct[0]);

		virtio_dma_fini(&vic->vic_indirect_dma);
	}

	size_t vicsz = sizeof (*vic) +
	    vic->vic_direct_capacity * sizeof (uint16_t);

	kmem_free(vic, vicsz);
}

static inline int
virtio_queue_descmap_alloc(virtio_queue_t *viq, uint_t *indexp)
{
	id_t index;

	if ((index = id_alloc_nosleep(viq->viq_descmap)) == -1) {
		return (ENOMEM);
	}

	VERIFY3S(index, >=, 0);
	VERIFY3S(index, <=, viq->viq_size);

	*indexp = (uint_t)index;
	return (0);
}

static int
virtio_chain_append_impl(virtio_chain_t *vic, uint64_t pa, size_t len,
    uint16_t flags)
{
	virtio_queue_t *viq = vic->vic_vq;
	virtio_vq_desc_t *vqd;
	uint_t index;

	/*
	 * We're modifying the queue-wide descriptor list so make sure we have
	 * the appropriate lock.
	 */
	VERIFY(MUTEX_HELD(&viq->viq_mutex));

	if (vic->vic_indirect_capacity != 0) {
		/*
		 * Use indirect descriptors.
		 */
		if (vic->vic_indirect_used >= vic->vic_indirect_capacity) {
			return (DDI_FAILURE);
		}

		vqd = virtio_dma_va(&vic->vic_indirect_dma, 0);

		if ((index = vic->vic_indirect_used++) > 0) {
			/*
			 * Chain the current last indirect descriptor to the
			 * new one.
			 */
			vqd[index - 1].vqd_flags |= VIRTQ_DESC_F_NEXT;
			vqd[index - 1].vqd_next = index;
		}

	} else {
		/*
		 * Use direct descriptors.
		 */
		if (vic->vic_direct_used >= vic->vic_direct_capacity) {
			return (DDI_FAILURE);
		}

		if (virtio_queue_descmap_alloc(viq, &index) != 0) {
			return (DDI_FAILURE);
		}

		vqd = virtio_dma_va(&viq->viq_dma, 0);

		if (vic->vic_direct_used > 0) {
			/*
			 * This is not the first entry.  Chain the current
			 * descriptor to the next one.
			 */
			uint16_t p = vic->vic_direct[vic->vic_direct_used - 1];

			vqd[p].vqd_flags |= VIRTQ_DESC_F_NEXT;
			vqd[p].vqd_next = index;
		}
		vic->vic_direct[vic->vic_direct_used++] = index;
	}

	vqd[index].vqd_addr = pa;
	vqd[index].vqd_len = len;
	vqd[index].vqd_flags = flags;
	vqd[index].vqd_next = 0;

	return (DDI_SUCCESS);
}

int
virtio_chain_append(virtio_chain_t *vic, uint64_t pa, size_t len,
    virtio_direction_t dir)
{
	virtio_queue_t *viq = vic->vic_vq;
	uint16_t flags = 0;

	switch (dir) {
	case VIRTIO_DIR_DEVICE_WRITES:
		flags |= VIRTQ_DESC_F_WRITE;
		break;

	case VIRTIO_DIR_DEVICE_READS:
		break;

	default:
		panic("unknown direction value %u", dir);
	}

	mutex_enter(&viq->viq_mutex);
	int r = virtio_chain_append_impl(vic, pa, len, flags);
	mutex_exit(&viq->viq_mutex);

	return (r);
}

void
virtio_queue_flush_locked(virtio_queue_t *viq)
{
	virtio_t	*vio;

	if (viq == NULL)
		return;

	ASSERT(viq->viq_virtio);
	vio = viq->viq_virtio;
	ASSERT(vio->vio_implfuncs);

	vio->vio_implfuncs->vi_queue_flush_locked(viq);
}

void
virtio_queue_flush(virtio_queue_t *viq)
{
	mutex_enter(&viq->viq_mutex);
	virtio_queue_flush_locked(viq);
	mutex_exit(&viq->viq_mutex);
}

void
virtio_chain_submit(virtio_chain_t *vic, boolean_t flush)
{
	virtio_queue_t *viq = vic->vic_vq;

	mutex_enter(&viq->viq_mutex);

	if (vic->vic_indirect_capacity != 0) {
		virtio_vq_desc_t *vqd = virtio_dma_va(&viq->viq_dma, 0);

		VERIFY3U(vic->vic_direct_used, ==, 1);

		/*
		 * This is an indirect descriptor queue.  The length in bytes
		 * of the descriptor must extend to cover the populated
		 * indirect descriptor entries.
		 */
		vqd[vic->vic_direct[0]].vqd_len =
		    sizeof (virtio_vq_desc_t) * vic->vic_indirect_used;

		virtio_dma_sync(&vic->vic_indirect_dma, DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * Populate the next available slot in the driver-owned ring for this
	 * chain.  The updated value of viq_driver_index is not yet visible to
	 * the device until a subsequent queue flush.
	 */
	uint16_t index = (viq->viq_driver_index++) % viq->viq_size;
	viq->viq_dma_driver->vqdr_ring[index] = vic->vic_direct[0];

	vic->vic_head = vic->vic_direct[0];
	avl_add(&viq->viq_inflight, vic);

	if (flush) {
		virtio_queue_flush_locked(vic->vic_vq);
	}

	mutex_exit(&viq->viq_mutex);
}

/*
 * INTERRUPTS MANAGEMENT
 */

static const char *
virtio_interrupt_type_name(int type)
{
	switch (type) {
	case DDI_INTR_TYPE_MSIX:
		return ("MSI-X");
	case DDI_INTR_TYPE_MSI:
		return ("MSI");
	case DDI_INTR_TYPE_FIXED:
		return ("fixed");
	default:
		return ("?");
	}
}

static int
virtio_interrupts_alloc(virtio_t *vio, int type, int nrequired)
{
	dev_info_t *dip = vio->vio_dip;
	int nintrs = 0;
	int navail = 0;

	VERIFY(MUTEX_HELD(&vio->vio_mutex));
	VERIFY(!(vio->vio_initlevel & VIRTIO_INITLEVEL_INT_ALLOC));

	if (ddi_intr_get_nintrs(dip, type, &nintrs) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not count %s interrupts",
		    virtio_interrupt_type_name(type));
		return (DDI_FAILURE);
	}
	if (nintrs < 1) {
		dev_err(dip, CE_WARN, "no %s interrupts supported",
		    virtio_interrupt_type_name(type));
		return (DDI_FAILURE);
	}

	if (ddi_intr_get_navail(dip, type, &navail) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not count available %s interrupts",
		    virtio_interrupt_type_name(type));
		return (DDI_FAILURE);
	}
	if (navail < nrequired) {
		dev_err(dip, CE_WARN, "need %d %s interrupts, but only %d "
		    "available", nrequired, virtio_interrupt_type_name(type),
		    navail);
		return (DDI_FAILURE);
	}

	VERIFY3P(vio->vio_interrupts, ==, NULL);
	vio->vio_interrupts = kmem_zalloc(
	    sizeof (ddi_intr_handle_t) * nrequired, KM_SLEEP);

	int r;
	if ((r = ddi_intr_alloc(dip, vio->vio_interrupts, type, 0, nrequired,
	    &vio->vio_ninterrupts, DDI_INTR_ALLOC_STRICT)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "%s interrupt allocation failure (%d)",
		    virtio_interrupt_type_name(type), r);
		kmem_free(vio->vio_interrupts,
		    sizeof (ddi_intr_handle_t) * nrequired);
		vio->vio_interrupts = NULL;
		return (DDI_FAILURE);
	}

	vio->vio_initlevel |= VIRTIO_INITLEVEL_INT_ALLOC;
	vio->vio_interrupt_type = type;
	return (DDI_SUCCESS);
}

static int
virtio_interrupts_setup(virtio_t *vio, int allow_types)
{
	dev_info_t *dip = vio->vio_dip;
	int types;
	int count = 0;

	mutex_enter(&vio->vio_mutex);

	/*
	 * Determine the number of interrupts we'd like based on the number of
	 * virtqueues.
	 */
	for (virtio_queue_t *viq = list_head(&vio->vio_queues); viq != NULL;
	    viq = list_next(&vio->vio_queues, viq)) {
		if (viq->viq_func != NULL) {
			count++;
		}
	}

	/*
	 * If there is a configuration change handler, one extra interrupt
	 * is needed for that.
	 */
	if (vio->vio_cfgchange_handler != NULL)
		count++;

	if (ddi_intr_get_supported_types(dip, &types) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not get supported interrupts");
		mutex_exit(&vio->vio_mutex);
		return (DDI_FAILURE);
	}

	if (allow_types != VIRTIO_ANY_INTR_TYPE) {
		/*
		 * Restrict the possible interrupt types at the request of the
		 * driver.
		 */
		types &= allow_types;
	}

	/*
	 * Try each potential interrupt type in descending order of preference.
	 * Note that the specification does not appear to allow for the use of
	 * classical MSI, so we are limited to either MSI-X or fixed
	 * interrupts.
	 */
	if (types & DDI_INTR_TYPE_MSIX) {
		if (virtio_interrupts_alloc(vio, DDI_INTR_TYPE_MSIX,
		    count) == DDI_SUCCESS) {
			goto add_handlers;
		}
	}
	if (types & DDI_INTR_TYPE_FIXED) {
		/*
		 * If fixed interrupts are all that are available, we'll just
		 * ask for one.
		 */
		if (virtio_interrupts_alloc(vio, DDI_INTR_TYPE_FIXED, 1) ==
		    DDI_SUCCESS) {
			goto add_handlers;
		}
	}

	dev_err(dip, CE_WARN, "interrupt allocation failed");
	mutex_exit(&vio->vio_mutex);
	return (DDI_FAILURE);

add_handlers:
	/*
	 * Ensure that we have not been given any high-level interrupts as our
	 * interrupt handlers do not support them.
	 */
	for (int i = 0; i < vio->vio_ninterrupts; i++) {
		uint_t ipri;

		if (ddi_intr_get_pri(vio->vio_interrupts[i], &ipri) !=
		    DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "could not determine interrupt "
			    "priority");
			goto fail;
		}

		if (ipri >= ddi_intr_get_hilevel_pri()) {
			dev_err(dip, CE_WARN, "high level interrupts not "
			    "supported");
			goto fail;
		}

		/*
		 * Record the highest priority we've been allocated to use for
		 * mutex initialisation.
		 */
		if (i == 0 || ipri > vio->vio_interrupt_priority) {
			vio->vio_interrupt_priority = ipri;
		}
	}

	/*
	 * Get the interrupt capabilities from the first handle to determine
	 * whether we need to use ddi_intr_block_enable(9F).
	 */
	if (ddi_intr_get_cap(vio->vio_interrupts[0],
	    &vio->vio_interrupt_cap) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to get interrupt capabilities");
		goto fail;
	}

	if (vio->vio_interrupt_type == DDI_INTR_TYPE_FIXED) {
		VERIFY3S(vio->vio_ninterrupts, ==, 1);
		/*
		 * For fixed interrupts, we need to use our shared handler to
		 * multiplex the per-queue handlers provided by the driver.
		 */
		if (ddi_intr_add_handler(vio->vio_interrupts[0],
		    virtio_shared_isr, (caddr_t)vio, NULL) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "adding shared %s interrupt "
			    "handler failed", virtio_interrupt_type_name(
			    vio->vio_interrupt_type));
			goto fail;
		}

		goto done;
	}

	VERIFY3S(vio->vio_ninterrupts, ==, count);

	uint_t n = 0;

	/* Bind the configuration vector interrupt */
	if (vio->vio_cfgchange_handler != NULL) {
		if (ddi_intr_add_handler(vio->vio_interrupts[n],
		    vio->vio_cfgchange_handler,
		    (caddr_t)vio->vio_cfgchange_handlerarg,
		    (caddr_t)vio) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN,
			    "adding configuration change interrupt failed");
			goto fail;
		}
		vio->vio_cfgchange_handler_added = B_TRUE;
		vio->vio_cfgchange_handler_index = n;
		n++;
	}

	for (virtio_queue_t *viq = list_head(&vio->vio_queues); viq != NULL;
	    viq = list_next(&vio->vio_queues, viq)) {
		if (viq->viq_func == NULL) {
			continue;
		}

		if (ddi_intr_add_handler(vio->vio_interrupts[n],
		    viq->viq_func, (caddr_t)viq->viq_funcarg,
		    (caddr_t)vio) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "adding interrupt %u (%s) failed",
			    n, viq->viq_name);
			goto fail;
		}

		viq->viq_handler_index = n;
		viq->viq_handler_added = B_TRUE;
		n++;
	}

done:
	vio->vio_initlevel |= VIRTIO_INITLEVEL_INT_ADDED;
	mutex_exit(&vio->vio_mutex);
	return (DDI_SUCCESS);

fail:
	virtio_interrupts_teardown(vio);
	mutex_exit(&vio->vio_mutex);
	return (DDI_FAILURE);
}

uint_t
virtio_shared_isr(caddr_t arg0, caddr_t arg1)
{
	virtio_t *vio = (virtio_t *)arg0;
	ASSERT(arg0);
	ASSERT(vio->vio_implfuncs);
	return (vio->vio_implfuncs->vi_shared_isr(arg0, arg1));
}

void
virtio_interrupts_unwind(virtio_t *vio)
{
	ASSERT(vio->vio_implfuncs);
	vio->vio_implfuncs->vi_interrupts_unwind(vio);
}

static void
virtio_interrupts_teardown(virtio_t *vio)
{
	VERIFY(MUTEX_HELD(&vio->vio_mutex));

	virtio_interrupts_disable_locked(vio);

	if (vio->vio_interrupt_type == DDI_INTR_TYPE_FIXED) {
		/*
		 * Remove the multiplexing interrupt handler.
		 */
		if (vio->vio_initlevel & VIRTIO_INITLEVEL_INT_ADDED) {
			int r;

			VERIFY3S(vio->vio_ninterrupts, ==, 1);

			if ((r = ddi_intr_remove_handler(
			    vio->vio_interrupts[0])) != DDI_SUCCESS) {
				dev_err(vio->vio_dip, CE_WARN, "removing "
				    "shared interrupt handler failed (%d)", r);
			}
		}
	} else {
		/*
		 * Remove the configuration vector interrupt handler.
		 */
		if (vio->vio_cfgchange_handler_added) {
			int r;

			if ((r = ddi_intr_remove_handler(
			    vio->vio_interrupts[0])) != DDI_SUCCESS) {
				dev_err(vio->vio_dip, CE_WARN,
				    "removing configuration change interrupt "
				    "handler failed (%d)", r);
			}
			vio->vio_cfgchange_handler_added = B_FALSE;
		}

		for (virtio_queue_t *viq = list_head(&vio->vio_queues);
		    viq != NULL; viq = list_next(&vio->vio_queues, viq)) {
			int r;

			if (!viq->viq_handler_added) {
				continue;
			}

			if ((r = ddi_intr_remove_handler(
			    vio->vio_interrupts[viq->viq_handler_index])) !=
			    DDI_SUCCESS) {
				dev_err(vio->vio_dip, CE_WARN, "removing "
				    "interrupt handler (%s) failed (%d)",
				    viq->viq_name, r);
			}

			viq->viq_handler_added = B_FALSE;
		}
	}
	vio->vio_initlevel &= ~VIRTIO_INITLEVEL_INT_ADDED;

	if (vio->vio_initlevel & VIRTIO_INITLEVEL_INT_ALLOC) {
		for (int i = 0; i < vio->vio_ninterrupts; i++) {
			int r;

			if ((r = ddi_intr_free(vio->vio_interrupts[i])) !=
			    DDI_SUCCESS) {
				dev_err(vio->vio_dip, CE_WARN, "freeing "
				    "interrupt %u failed (%d)", i, r);
			}
		}
		kmem_free(vio->vio_interrupts,
		    sizeof (ddi_intr_handle_t) * vio->vio_ninterrupts);
		vio->vio_interrupts = NULL;
		vio->vio_ninterrupts = 0;
		vio->vio_interrupt_type = 0;
		vio->vio_interrupt_cap = 0;
		vio->vio_interrupt_priority = 0;

		vio->vio_initlevel &= ~VIRTIO_INITLEVEL_INT_ALLOC;
	}
}

int
virtio_interrupts_enable(virtio_t *vio)
{
	mutex_enter(&vio->vio_mutex);
	if (vio->vio_initlevel & VIRTIO_INITLEVEL_INT_ENABLED) {
		mutex_exit(&vio->vio_mutex);
		return (DDI_SUCCESS);
	}

	int r = DDI_SUCCESS;
	if (vio->vio_interrupt_cap & DDI_INTR_FLAG_BLOCK) {
		r = ddi_intr_block_enable(vio->vio_interrupts,
		    vio->vio_ninterrupts);
	} else {
		for (int i = 0; i < vio->vio_ninterrupts; i++) {
			if ((r = ddi_intr_enable(vio->vio_interrupts[i])) !=
			    DDI_SUCCESS) {
				/*
				 * Disable the interrupts we have enabled so
				 * far.
				 */
				for (i--; i >= 0; i--) {
					(void) ddi_intr_disable(
					    vio->vio_interrupts[i]);
				}
				break;
			}
		}
	}

	if (r != DDI_SUCCESS) {
		mutex_exit(&vio->vio_mutex);
		return (r);
	}

	if (vio->vio_interrupt_type == DDI_INTR_TYPE_MSIX) {
		/*
		 * When asked to enable the interrupts, the system enables
		 * MSI-X in the PCI configuration for the device.  While
		 * enabled, the extra MSI-X configuration table fields appear
		 * between the general and the device-specific regions of the
		 * BAR.
		 */
		vio->vio_config_offset = VIRTIO_LEGACY_CFG_OFFSET_MSIX;

		for (virtio_queue_t *viq = list_head(&vio->vio_queues);
		    viq != NULL; viq = list_next(&vio->vio_queues, viq)) {
			if (!viq->viq_handler_added) {
				continue;
			}

			uint16_t qi = viq->viq_index;
			uint16_t msi = viq->viq_handler_index;

			/*
			 * Route interrupts for this queue to the assigned
			 * MSI-X vector number.
			 */
			virtio_put16(vio, VIRTIO_LEGACY_QUEUE_SELECT, qi);
			virtio_put16(vio, VIRTIO_LEGACY_MSIX_QUEUE, msi);

			/*
			 * The device may not actually accept the vector number
			 * we're attempting to program.  We need to confirm
			 * that configuration was successful by re-reading the
			 * configuration we just wrote.
			 */
			if (virtio_get16(vio, VIRTIO_LEGACY_MSIX_QUEUE) !=
			    msi) {
				dev_err(vio->vio_dip, CE_WARN,
				    "failed to configure MSI-X vector %u for "
				    "queue \"%s\" (#%u)", (uint_t)msi,
				    viq->viq_name, (uint_t)qi);

				virtio_interrupts_unwind(vio);
				mutex_exit(&vio->vio_mutex);
				return (DDI_FAILURE);
			}
		}

		if (vio->vio_cfgchange_handler_added) {
			virtio_put16(vio, VIRTIO_LEGACY_MSIX_CONFIG,
			    vio->vio_cfgchange_handler_index);

			/* Verify the value was accepted. */
			if (virtio_get16(vio, VIRTIO_LEGACY_MSIX_CONFIG) !=
			    vio->vio_cfgchange_handler_index) {
				dev_err(vio->vio_dip, CE_WARN,
				    "failed to configure MSI-X vector for "
				    "configuration");

				virtio_interrupts_unwind(vio);
				mutex_exit(&vio->vio_mutex);
				return (DDI_FAILURE);
			}
		}
	}

	vio->vio_initlevel |= VIRTIO_INITLEVEL_INT_ENABLED;

	mutex_exit(&vio->vio_mutex);
	return (DDI_SUCCESS);
}

static void
virtio_interrupts_disable_locked(virtio_t *vio)
{
	VERIFY(MUTEX_HELD(&vio->vio_mutex));

	if (!(vio->vio_initlevel & VIRTIO_INITLEVEL_INT_ENABLED)) {
		return;
	}

	virtio_interrupts_unwind(vio);

	vio->vio_initlevel &= ~VIRTIO_INITLEVEL_INT_ENABLED;
}

void
virtio_interrupts_disable(virtio_t *vio)
{
	mutex_enter(&vio->vio_mutex);
	virtio_interrupts_disable_locked(vio);
	mutex_exit(&vio->vio_mutex);
}
