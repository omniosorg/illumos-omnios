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

#include <sys/types.h>
#include <sys/null.h>
#include <sys/machparam.h>
#include <sys/efi.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/bootinfo.h>
#include <sys/framebuffer.h>
#include <sys/efifb.h>

#include "dboot.h"
#include "dboot_printf.h"

extern struct efi_map_header *efi_map_header;

int pagesize = MMU_PAGESIZE;

extern uintptr_t pa_to_ttbr1(uintptr_t pa);

/*
 * UEFI Memory Types
 * =================
 *
 * EfiReservedMemoryType
 *   Not usable.
 *
 * EfiLoaderCode
 *   The code portions of a loaded UEFI application.
 *
 * EfiLoaderData
 *   The data portions of a loaded UEFI application and the default data
 *   allocation type used by a UEFI application to allocate pool memory.
 *
 * EfiRuntimeServicesCode
 *   The memory in this range is to be preserved by the UEFI OS loader and
 *   OS in the working and ACPI S1–S3 states.
 *
 * EfiRuntimeServicesData
 *   The memory in this range is to be preserved by the UEFI OS loader and
 *   OS in the working and ACPI S1–S3 states.
 *
 * EfiConventionalMemory
 *   Memory available for general use.
 *
 * EfiUnusableMemory
 *   Memory that contains errors and is not to be used.
 *
 * EfiACPIReclaimMemory
 *   This memory is to be preserved by the UEFI OS loader and OS until ACPI
 *   is enabled. Once ACPI is enabled, the memory in this range is available
 *   for general use.
 *
 * EfiACPIMemoryNVS
 *   This memory is to be preserved by the UEFI OS loader and OS in the
 *   working and ACPI S1–S3 states.
 *
 * EfiMemoryMappedIO
 *   This memory is not used by the OS. All system memory-mapped IO
 *   information should come from ACPI tables.
 *
 * EfiMemoryMappedIOPortSpace
 *   This memory is not used by the OS. All system memory-mapped IO port
 *   space information should come from ACPI tables.
 *
 * EfiPalCode
 *   This memory is to be preserved by the UEFI OS loader and OS in the
 *   working and ACPI S1–S4 states. This memory may also have other
 *   attributes that are defined by the processor implementation.
 *
 * EfiPersistentMemory
 *   A memory region that operates as EfiConventionalMemory. However, it
 *   happens to also support byte-addressable non-volatility.
 *
 * EfiUnacceptedMemoryType
 *   A memory region that represents unaccepted memory, that must be
 *   accepted by the boot target before it can be used. Unless otherwise
 *   noted, all other EFI memory types are accepted. For platforms that
 *   support unaccepted memory, all unaccepted valid memory will be
 *   reported as unaccepted in the memory map. Unreported physical
 *   address ranges must be treated as not-present memory.
 */
void
init_physmem(void)
{
	struct efi_map_header	*mhdr;
	size_t			efisz;
	EFI_MEMORY_DESCRIPTOR	*map;
	int			ndesc;
	EFI_MEMORY_DESCRIPTOR	*p;
	int			i;
	uint64_t		addr;
	uint64_t		size;
	uint64_t		ptot;
	uint64_t		stot;
	uint64_t		rtot;
	uint64_t		rttot;

	extern struct xboot_info *bi;

	if (efi_map_header == NULL)
		panic("init_physmem: no UEFI memory map header\n");

	ptot = stot = rtot = rttot = 0;
	mhdr = efi_map_header;
	efisz = (sizeof (struct efi_map_header) + 0xf) & ~0xf;
	map = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)mhdr + efisz);
	if (mhdr->descriptor_size == 0)
		panic("init_physmem: invalid memory descriptor size\n");

	ndesc = mhdr->memory_size / mhdr->descriptor_size;

	for (i = 0, p = map; i < ndesc;
	    i++, p = efi_mmap_next(p, mhdr->descriptor_size)) {
		switch (p->Type) {
		case EfiMemoryMappedIO:
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart +
			    (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) -
			    addr;
			dprintf("mmio memory add span 0x%lx - 0x%lx\n",
			    addr, addr + size - 1);
			memlist_add_span(addr, size, &piolistp);
			memlist_add_span(addr, size, &pldriolistp);
			break;
#if defined(NOT_YET)
		case EfiUnacceptedMemoryType:	/* fallthrough */
#endif
		case EfiPalCode:		/* fallthrough */
		case EfiACPIMemoryNVS:		/* fallthrough */
		case EfiACPIReclaimMemory:	/* fallthrough */
		case EfiUnusableMemory:		/* fallthrough */
		case EfiReservedMemoryType:	/* fallthrough */
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart +
			    (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) -
			    addr;
			dprintf("rsvd memory add span 0x%lx - 0x%lx\n",
			    addr, addr + size - 1);
			memlist_add_span(addr, size, &pinstalledp);
			memlist_add_span(addr, size, &prsvdlistp);
			rtot += size;
			ptot += size;
			break;
		case EfiLoaderCode:		/* fallthrough */
		case EfiLoaderData:		/* fallthrough */
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart +
			    (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) -
			    addr;
			dprintf("phys memory add span 0x%lx - 0x%lx\n",
			    addr, addr + size - 1);
			memlist_add_span(addr, size, &pinstalledp);
			memlist_add_span(addr, size, &pmappablep);
			memlist_add_span(addr, size, &pscratchlistp);
			stot += size;
			ptot += size;
			break;
		case EfiRuntimeServicesCode:	/* fallthrough */
		case EfiRuntimeServicesData:	/* fallthrough */
			/*
			 * Not sure what to do with this yet
			 */
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart +
			    (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) -
			    addr;
			dprintf("rtim memory add span 0x%lx - 0x%lx\n",
			    addr, addr + size - 1);
			memlist_add_span(addr, size, &pinstalledp);
			if (p->Type == EfiRuntimeServicesCode) {
				memlist_add_span(addr, size, &pfwcodelistp);
			} else {
				memlist_add_span(addr, size, &pfwdatalistp);
			}
			rttot += size;
			ptot += size;
			break;
		case EfiBootServicesCode:	/* fallthrough */
		case EfiBootServicesData:	/* fallthrough */
		case EfiPersistentMemory:	/* fallthrough */
		case EfiConventionalMemory:
			addr = RNDUP(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDDN(p->PhysicalStart +
			    (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) -
			    addr;
			dprintf("phys memory add span 0x%lx - 0x%lx\n",
			    addr, addr + size - 1);
			memlist_add_span(addr, size, &pinstalledp);
			memlist_add_span(addr, size, &pmappablep);
			memlist_add_span(addr, size, &pfreelistp);
			ptot += size;
			break;
		default:
			dboot_printf("Treating unhandled memory type %u as "
			    "reserved\n", p->Type);

			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart +
			    (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) -
			    addr;
			dprintf("rsvd memory add span 0x%lx - 0x%lx\n",
			    addr, addr + size - 1);
			memlist_add_span(addr, size, &pinstalledp);
			memlist_add_span(addr, size, &prsvdlistp);
			rtot += size;
			ptot += size;
			break;
		}
	}

	/*
	 * UEFI configuration tables loaded at boot time could be contained
	 * in memory of type EfiBootServicesdata, which we hand back at this
	 * point. Ensure that all configuration table memory is reserved.
	 */
	/* XXXARM: reserve_firmware_tables(); */

	/*
	 * There's no guarantee we'll see EfiMemoryMappedIO entries, or which
	 * devices those will correspond to. The docs even suggest that we
	 * should never touch entries of this type.
	 *
	 * The only device we really need is the UART, so ensure that there's
	 * an entry for that. Addresses in this list will only be mapped to
	 * the lower address space.
	 */
	if (bi != NULL && bi->bi_bsvc_uart_mmio_base != 0) {
		addr = RNDDN(bi->bi_bsvc_uart_mmio_base, MMU_PAGESIZE);
		size = RNDUP(
		    bi->bi_bsvc_uart_mmio_base + 0x1000, MMU_PAGESIZE) - addr;
		if (!memlist_find(pldriolistp, addr))
			memlist_add_span(addr, size, &pldriolistp);
	}

	if (bi != NULL && bi->bi_framebuffer != 0) {
		boot_framebuffer_t *bfb =
		    (boot_framebuffer_t *)bi->bi_framebuffer;
		if (bfb->framebuffer != 0) {
			struct efi_fb *fb = (struct efi_fb *)bfb->framebuffer;
			addr = RNDDN(fb->fb_addr, MMU_PAGESIZE);
			size = RNDUP(
			    fb->fb_addr + fb->fb_size, MMU_PAGESIZE) - addr;
			if (!memlist_find(pldriolistp, addr))
				memlist_add_span(addr, size, &pldriolistp);
		}
	}

	if (verbosemode) {
		dprintf("physical memory: 0x%lx bytes\n", ptot);
		dprintf("       reserved: 0x%lx bytes\n", rtot);
		dprintf("        runtime: 0x%lx bytes\n", rttot);
		dprintf("        scratch: 0x%lx bytes\n", stot);
	}
}
