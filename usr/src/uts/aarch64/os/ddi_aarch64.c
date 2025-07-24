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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddifm.h>
#include <sys/fm/io/ddi.h>
#include <sys/fm/protocol.h>
#include <sys/ontrap.h>
#include <sys/pci_impl.h>

/*
 * SECTION: DDI Data Access
 */

static uintptr_t impl_acc_hdl_id = 0;

/*
 * access handle allocator
 */
ddi_acc_hdl_t *
impl_acc_hdl_get(ddi_acc_handle_t hdl)
{
	/*
	 * Extract the access handle address from the DDI implemented
	 * access handle
	 */
	return (&((ddi_acc_impl_t *)hdl)->ahi_common);
}

ddi_acc_handle_t
impl_acc_hdl_alloc(int (*waitfp)(caddr_t), caddr_t arg)
{
	ddi_acc_impl_t *hp;
	on_trap_data_t *otp;
	int sleepflag;

	sleepflag = ((waitfp == (int (*)())KM_SLEEP) ? KM_SLEEP : KM_NOSLEEP);

	/*
	 * Allocate and initialize the data access handle and error status.
	 */
	if ((hp = kmem_zalloc(sizeof (ddi_acc_impl_t), sleepflag)) == NULL)
		goto fail;
	if ((hp->ahi_err = (ndi_err_t *)kmem_zalloc(
	    sizeof (ndi_err_t), sleepflag)) == NULL) {
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		goto fail;
	}

	if ((hp->ahi_common.ah_bus_private = kmem_zalloc(
	    sizeof (pci_acc_cfblk_t), sleepflag)) == NULL) {
		kmem_free(hp->ahi_err, sizeof (ndi_err_t));
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		goto fail;
	}

	if ((otp = (on_trap_data_t *)kmem_zalloc(
	    sizeof (on_trap_data_t), sleepflag)) == NULL) {
		kmem_free(hp->ahi_common.ah_bus_private,
		    sizeof (pci_acc_cfblk_t));
		kmem_free(hp->ahi_err, sizeof (ndi_err_t));
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		goto fail;
	}
	hp->ahi_err->err_ontrap = otp;
	hp->ahi_common.ah_platform_private = (void *)hp;

	return ((ddi_acc_handle_t)hp);
fail:
	if ((waitfp != (int (*)())KM_SLEEP) &&
	    (waitfp != (int (*)())KM_NOSLEEP))
		ddi_set_callback(waitfp, arg, &impl_acc_hdl_id);
	return (NULL);
}

void
impl_acc_hdl_free(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hp;

	/*
	 * The supplied (ddi_acc_handle_t) is actually a (ddi_acc_impl_t *),
	 * because that's what we allocated in impl_acc_hdl_alloc() above.
	 */
	hp = (ddi_acc_impl_t *)handle;
	if (hp) {
		kmem_free(hp->ahi_common.ah_bus_private,
		    sizeof (pci_acc_cfblk_t));
		kmem_free(hp->ahi_err->err_ontrap, sizeof (on_trap_data_t));
		kmem_free(hp->ahi_err, sizeof (ndi_err_t));
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		if (impl_acc_hdl_id)
			ddi_run_callback(&impl_acc_hdl_id);
	}
}

static int
impl_acc_check(dev_info_t *dip, const void *handle, const void *addr,
    const void *not_used)
{
	pfn_t pfn, fault_pfn;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get((ddi_acc_handle_t)handle);

	ASSERT(hp);

	if (addr != NULL) {
		pfn = hp->ah_pfn;
		fault_pfn = mmu_btop(*(uint64_t *)addr);
		if (fault_pfn >= pfn && fault_pfn < (pfn + hp->ah_pnum))
			return (DDI_FM_NONFATAL);
	}
	return (DDI_FM_UNKNOWN);
}

void
impl_acc_err_init(ddi_acc_hdl_t *handlep)
{
	int fmcap;
	ndi_err_t *errp;
	on_trap_data_t *otp;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handlep;

	fmcap = ddi_fm_capable(handlep->ah_dip);

	if ((handlep->ah_acc.devacc_attr_version < DDI_DEVICE_ATTR_V1) ||
	    !DDI_FM_ACC_ERR_CAP(fmcap)) {
		handlep->ah_acc.devacc_attr_access = DDI_DEFAULT_ACC;
	} else if (DDI_FM_ACC_ERR_CAP(fmcap)) {
		if (handlep->ah_acc.devacc_attr_access == DDI_DEFAULT_ACC) {
			i_ddi_drv_ereport_post(handlep->ah_dip, DVR_EFMCAP,
			    NULL, DDI_NOSLEEP);
		} else {
			errp = hp->ahi_err;
			otp = (on_trap_data_t *)errp->err_ontrap;
			otp->ot_handle = (void *)(hp);
			otp->ot_prot = OT_DATA_ACCESS;
			errp->err_status = DDI_FM_OK;
			errp->err_expected = DDI_FM_ERR_UNEXPECTED;
			errp->err_cf = impl_acc_check;
		}
	}
}

int
impl_dma_check(dev_info_t *dip, const void *handle, const void *pci_hdl,
    const void *not_used)
{
	return (DDI_FM_UNKNOWN);
}

void
impl_acc_hdl_init(ddi_acc_hdl_t *handlep)
{
	ddi_acc_impl_t *hp;
	int fmcap;
	int devacc_attr_access;

	if (!handlep)
		return;
	fmcap = ddi_fm_capable(handlep->ah_dip);
	if (handlep->ah_acc.devacc_attr_version < DDI_DEVICE_ATTR_V1 ||
	    !DDI_FM_ACC_ERR_CAP(fmcap))
		devacc_attr_access = DDI_DEFAULT_ACC;
	else
		devacc_attr_access = handlep->ah_acc.devacc_attr_access;

	hp = (ddi_acc_impl_t *)handlep->ah_platform_private;
	switch (devacc_attr_access) {
	case DDI_FLAGERR_ACC:
	case DDI_CAUTIOUS_ACC:
		hp->ahi_get8 = i_ddi_caut_get8;
		hp->ahi_put8 = i_ddi_caut_put8;
		hp->ahi_rep_get8 = i_ddi_caut_rep_get8;
		hp->ahi_rep_put8 = i_ddi_caut_rep_put8;
		hp->ahi_get16 = i_ddi_caut_get16;
		hp->ahi_get32 = i_ddi_caut_get32;
		hp->ahi_put16 = i_ddi_caut_put16;
		hp->ahi_put32 = i_ddi_caut_put32;
		hp->ahi_rep_get16 = i_ddi_caut_rep_get16;
		hp->ahi_rep_get32 = i_ddi_caut_rep_get32;
		hp->ahi_rep_put16 = i_ddi_caut_rep_put16;
		hp->ahi_rep_put32 = i_ddi_caut_rep_put32;
		hp->ahi_get64 = i_ddi_caut_get64;
		hp->ahi_put64 = i_ddi_caut_put64;
		hp->ahi_rep_get64 = i_ddi_caut_rep_get64;
		hp->ahi_rep_put64 = i_ddi_caut_rep_put64;
		break;
	case DDI_DEFAULT_ACC:
		if (hp->ahi_acc_attr & DDI_ACCATTR_IO_SPACE) {
			hp->ahi_get8 = i_ddi_io_get8;
			hp->ahi_put8 = i_ddi_io_put8;
			hp->ahi_rep_get8 = i_ddi_io_rep_get8;
			hp->ahi_rep_put8 = i_ddi_io_rep_put8;

			if (handlep->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {
				hp->ahi_get16 = i_ddi_io_swap_get16;
				hp->ahi_get32 = i_ddi_io_swap_get32;
				hp->ahi_get64 = i_ddi_io_swap_get64;
				hp->ahi_put16 = i_ddi_io_swap_put16;
				hp->ahi_put32 = i_ddi_io_swap_put32;
				hp->ahi_put64 = i_ddi_io_swap_put64;
				hp->ahi_rep_get16 = i_ddi_io_swap_rep_get16;
				hp->ahi_rep_get32 = i_ddi_io_swap_rep_get32;
				hp->ahi_rep_get64 = i_ddi_io_swap_rep_get64;
				hp->ahi_rep_put16 = i_ddi_io_swap_rep_put16;
				hp->ahi_rep_put32 = i_ddi_io_swap_rep_put32;
				hp->ahi_rep_put64 = i_ddi_io_swap_rep_put64;
			} else {
				hp->ahi_acc_attr |= DDI_ACCATTR_DIRECT;
				hp->ahi_get16 = i_ddi_io_get16;
				hp->ahi_get32 = i_ddi_io_get32;
				hp->ahi_get64 = i_ddi_io_get64;
				hp->ahi_put16 = i_ddi_io_put16;
				hp->ahi_put32 = i_ddi_io_put32;
				hp->ahi_put64 = i_ddi_io_put64;
				hp->ahi_rep_get16 = i_ddi_io_rep_get16;
				hp->ahi_rep_get32 = i_ddi_io_rep_get32;
				hp->ahi_rep_get64 = i_ddi_io_rep_get64;
				hp->ahi_rep_put16 = i_ddi_io_rep_put16;
				hp->ahi_rep_put32 = i_ddi_io_rep_put32;
				hp->ahi_rep_put64 = i_ddi_io_rep_put64;
			}
		} else if (hp->ahi_acc_attr & DDI_ACCATTR_CPU_VADDR) {
			hp->ahi_get8 = i_ddi_get8;
			hp->ahi_put8 = i_ddi_put8;
			hp->ahi_rep_get8 = i_ddi_rep_get8;
			hp->ahi_rep_put8 = i_ddi_rep_put8;

			if (handlep->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {
				hp->ahi_get16 = i_ddi_swap_get16;
				hp->ahi_get32 = i_ddi_swap_get32;
				hp->ahi_get64 = i_ddi_swap_get64;
				hp->ahi_put16 = i_ddi_swap_put16;
				hp->ahi_put32 = i_ddi_swap_put32;
				hp->ahi_put64 = i_ddi_swap_put64;
				hp->ahi_rep_get16 = i_ddi_swap_rep_get16;
				hp->ahi_rep_get32 = i_ddi_swap_rep_get32;
				hp->ahi_rep_get64 = i_ddi_swap_rep_get64;
				hp->ahi_rep_put16 = i_ddi_swap_rep_put16;
				hp->ahi_rep_put32 = i_ddi_swap_rep_put32;
				hp->ahi_rep_put64 = i_ddi_swap_rep_put64;
			} else {
				hp->ahi_acc_attr |= DDI_ACCATTR_DIRECT;
				hp->ahi_get16 = i_ddi_get16;
				hp->ahi_get32 = i_ddi_get32;
				hp->ahi_get64 = i_ddi_get64;
				hp->ahi_put16 = i_ddi_put16;
				hp->ahi_put32 = i_ddi_put32;
				hp->ahi_put64 = i_ddi_put64;
				hp->ahi_rep_get16 = i_ddi_rep_get16;
				hp->ahi_rep_get32 = i_ddi_rep_get32;
				hp->ahi_rep_get64 = i_ddi_rep_get64;
				hp->ahi_rep_put16 = i_ddi_rep_put16;
				hp->ahi_rep_put32 = i_ddi_rep_put32;
				hp->ahi_rep_put64 = i_ddi_rep_put64;
			}
		}
		break;
	}
	hp->ahi_fault_check = i_ddi_acc_fault_check;
	hp->ahi_fault_notify = i_ddi_acc_fault_notify;
	hp->ahi_fault = 0;
	impl_acc_err_init(handlep);
}


uint8_t
ddi_get8(ddi_acc_handle_t handle, uint8_t *addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get8(hp, addr));
}

uint8_t
ddi_mem_get8(ddi_acc_handle_t handle, uint8_t *addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get8(hp, addr));
}

uint8_t
ddi_io_get8(ddi_acc_handle_t handle, uint8_t *dev_addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get8(hp, dev_addr));
}

uint16_t
ddi_get16(ddi_acc_handle_t handle, uint16_t *addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get16(hp, addr));
}

uint16_t
ddi_mem_get16(ddi_acc_handle_t handle, uint16_t *addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get16(hp, addr));
}

uint16_t
ddi_io_get16(ddi_acc_handle_t handle, uint16_t *dev_addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get16(hp, dev_addr));
}

uint32_t
ddi_get32(ddi_acc_handle_t handle, uint32_t *addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get32(hp, addr));
}

uint32_t
ddi_mem_get32(ddi_acc_handle_t handle, uint32_t *addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get32(hp, addr));
}

uint32_t
ddi_io_get32(ddi_acc_handle_t handle, uint32_t *dev_addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get32(hp, dev_addr));
}

uint64_t
ddi_get64(ddi_acc_handle_t handle, uint64_t *addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get64(hp, addr));
}

uint64_t
ddi_mem_get64(ddi_acc_handle_t handle, uint64_t *addr)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	return (hp->ahi_get64(hp, addr));
}

void
ddi_put8(ddi_acc_handle_t handle, uint8_t *addr, uint8_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put8(hp, addr, value);
}

void
ddi_mem_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put8(hp, dev_addr, value);
}

void
ddi_io_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put8(hp, dev_addr, value);
}

void
ddi_put16(ddi_acc_handle_t handle, uint16_t *addr, uint16_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put16(hp, addr, value);
}

void
ddi_mem_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put16(hp, dev_addr, value);
}

void
ddi_io_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put16(hp, dev_addr, value);
}

void
ddi_put32(ddi_acc_handle_t handle, uint32_t *addr, uint32_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put32(hp, addr, value);
}

void
ddi_mem_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put32(hp, dev_addr, value);
}

void
ddi_io_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put32(hp, dev_addr, value);
}

void
ddi_put64(ddi_acc_handle_t handle, uint64_t *addr, uint64_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put64(hp, addr, value);
}

void
ddi_mem_put64(ddi_acc_handle_t handle, uint64_t *dev_addr, uint64_t value)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_put64(hp, dev_addr, value);
}

void
ddi_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get8(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_rep_get16(ddi_acc_handle_t handle, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get16(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_rep_get32(ddi_acc_handle_t handle, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get32(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_rep_get64(ddi_acc_handle_t handle, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get64(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_rep_put8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put8(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_rep_put16(ddi_acc_handle_t handle, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put16(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put32(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_rep_put64(ddi_acc_handle_t handle, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put64(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_mem_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get8(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_mem_rep_get16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get16(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_mem_rep_get32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get32(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_mem_rep_get64(ddi_acc_handle_t handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get64(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_mem_rep_put8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put8(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_mem_rep_put16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put16(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_mem_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put32(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_mem_rep_put64(ddi_acc_handle_t handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put64(hp, host_addr, dev_addr, repcount, flags);
}

void
ddi_io_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get8(hp, host_addr, dev_addr, repcount,
	    DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_get16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get16(hp, host_addr, dev_addr, repcount,
	    DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_get32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_get32(hp, host_addr, dev_addr, repcount,
	    DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_put8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put8(hp, host_addr, dev_addr, repcount,
	    DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_put16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put16(hp, host_addr, dev_addr, repcount,
	    DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	hp->ahi_rep_put32(hp, host_addr, dev_addr, repcount,
	    DDI_DEV_NO_AUTOINCR);
}

int
i_ddi_acc_fault_check(ddi_acc_impl_t *hdlp)
{
	return (hdlp->ahi_fault);
}

void
i_ddi_acc_fault_notify(ddi_acc_impl_t *hdlp)
{
}

void
i_ddi_acc_set_fault(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hdlp = (ddi_acc_impl_t *)handle;

	if (!hdlp->ahi_fault) {
		hdlp->ahi_fault = 1;
		(*hdlp->ahi_fault_notify)(hdlp);
	}
}

void
i_ddi_acc_clr_fault(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hdlp = (ddi_acc_impl_t *)handle;

	if (hdlp->ahi_fault) {
		hdlp->ahi_fault = 0;
		(*hdlp->ahi_fault_notify)(hdlp);
	}
}
