/*
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
 * Copyright (c) 2017, 2019 by Delphix. All rights reserved.
 */

/*
 * Implements low-level interactions with Hyper-V/Azure
 */

#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/cmn_err.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include <sys/ilstr.h>

#include <sys/x86_archext.h>

#include <sys/hyperv_illumos.h>
#include <sys/hyperv_busdma.h>
#include <vmbus/hyperv_machdep.h>

#include "hyperv_reg.h"
#include "hyperv_var.h"
#include <sys/hyperv.h>

#define	HYPERV_ILLUMOS_BUILD		0ULL
#define	HYPERV_ILLUMOS_VERSION		511ULL
#define	HYPERV_ILLUMOS_OSID		0ULL

#define	MSR_HV_GUESTID_BUILD_ILLUMOS	\
	(HYPERV_ILLUMOS_BUILD & MSR_HV_GUESTID_BUILD_MASK)
#define	MSR_HV_GUESTID_VERSION_ILLUMOS	\
	((HYPERV_ILLUMOS_VERSION << MSR_HV_GUESTID_VERSION_SHIFT) & \
	MSR_HV_GUESTID_VERSION_MASK)
#define	MSR_HV_GUESTID_OSID_ILLUMOS	\
	((HYPERV_ILLUMOS_OSID << MSR_HV_GUESTID_OSID_SHIFT) & \
	MSR_HV_GUESTID_OSID_MASK)

#define	MSR_HV_GUESTID_ILLUMOS		\
	(MSR_HV_GUESTID_BUILD_ILLUMOS |	\
	MSR_HV_GUESTID_VERSION_ILLUMOS | \
	MSR_HV_GUESTID_OSID_ILLUMOS |	\
	MSR_HV_GUESTID_OSTYPE_ILLUMOS)

#ifdef	DEBUG
#define	hyperv_log(level, fmt...)	\
	cmn_err(level, fmt);

#define	HYPERCALL_LOG_STATUS(status)				\
{								\
	switch (status) {					\
	case HYPERCALL_STATUS_SUCCESS:				\
		break;						\
	case HYPERCALL_STATUS_INVALID_HYPERCALL_INPUT:		\
		hyperv_log(CE_WARN,				\
		    "%s: Invalid hypercall input", __func__);	\
		break;						\
	case HYPERCALL_STATUS_INVALID_ALIGNMENT:		\
		hyperv_log(CE_WARN,				\
		    "%s: Invalid alignment", __func__);		\
		break;						\
	case HYPERCALL_STATUS_INSUFFICIENT_BUFFERS:		\
		/*
		 * This can happen due to bursty activity.	\
		 * vmbus will retry, so only log when		\
		 * verbose is set.				\
		 */						\
		hyperv_log(CE_WARN,				\
		    "?%s: Insufficient buffers", __func__);	\
		break;						\
	case HYPERCALL_STATUS_INSUFFICIENT_MEMORY:		\
		hyperv_log(CE_WARN,				\
		    "%s: Insufficient memory", __func__);	\
		break;						\
	case HYPERCALL_STATUS_INVALID_CONNECTION_ID:		\
		hyperv_log(CE_WARN,				\
		    "%s: Invalid connection id", __func__);	\
		break;						\
	case HYPERCALL_STATUS_INVALID_HYPERCALL_CODE:		\
		hyperv_log(CE_WARN,				\
		    "%s: Invalid hypercall code", __func__);	\
		break;						\
	default:						\
		hyperv_log(CE_WARN, "%s: Unknown status: %d",	\
		    __func__, status);				\
		break;						\
	}							\
}
#else
#define	hyperv_log(level, fmt...)
#define	HYPERCALL_LOG_STATUS(status)
#endif

typedef struct hvbit {
	uint8_t		hvb_bit;
	const char	*hvb_desc;
} hvbit_t;

static hvbit_t hyperv_access_tbl[] = {
	{ 0, "AccessVpRunTimeReg" },
	{ 1, "AccessPartitionReferenceCounter" },
	{ 2, "AccessSynicRegs" },
	{ 3, "AccessSyntheticTimerRegs" },
	{ 4, "AccessIntrCtrlRegs" },
	{ 5, "AccessHypercallMsrs" },
	{ 6, "AccessVpIndex" },
	{ 7, "AccessResetReg" },
	{ 8, "AccessStatsReg" },
	{ 9, "AccessPartitionReferenceTsc" },
	{ 10, "AccessGuestIdleReg" },
	{ 11, "AccessFrequencyRegs" },
	{ 12, "AccessDebugRegs" },
	{ 13, "AccessReenlightenmentControls" },
	/* 14-31 Reserved */
	{ 32, "CreatePartitions" },
	{ 33, "AccessPartitionId" },
	{ 34, "AccessMemoryPool" },
	/* 35 Reserved */
	{ 36, "PostMessages" },
	{ 37, "SignalEvents" },
	{ 38, "CreatePort" },
	{ 39, "ConnectPort" },
	{ 40, "AccessStats" },
	/* 41-42 Reserved */
	{ 43, "Debugging" },
	{ 44, "CpuManagement" },
	/* 45-47 Reserved */
	{ 48, "AccessVSM" },
	{ 49, "AccessVPRegisters" },
	/* 50-51 Reserved */
	{ 52, "EnabledExtendedHypercalls" },
	{ 53, "StartVirtualProcessor" },
};

static hvbit_t hyperv_features_tbl[] = {
	/* 0 Deprecated */
	{ 1, "Guest debugging support" },
	{ 2, "Performance Monitor support" },
	{ 3, "Physical CPU dynamic partitioning events" },
	{ 4, "Hypercall inputs using XMM registers" },
	{ 5, "Virtual guest idle state" },
	{ 6, "Hypervisor sleep state" },
	{ 7, "NUMA distances" },
	{ 8, "Timer frequencies" },
	{ 9, "Synthetic machine checks" },
	{ 10, "Guest crash MSR" },
	{ 11, "Debug MSR" },
	{ 12, "NPIEP" },
	{ 13, "DisableHypervisorAvailable" },
	{ 14, "ExtendedGvaRangesForFlushVirtualAddressListAvailable" },
	{ 15, "Hypercall return using XMM registers" },
	/* 16 Reserved */
	{ 17, "SintPollingModeAvailable" },
	{ 18, "HypercallMsrLockAvailable" },
	{ 19, "Use direct synthetic timers" },
	{ 20, "PAT register available for VSM" },
	{ 21, "Sbndcfgs register available for VSM" },
	/* 22 Reserved */
	{ 23, "Synthetic time unhalted timer" },
	/* 24-25 Reserved */
	{ 26, "Last Branch Record (LBR)" },
};

static hvbit_t hyperv_recommendations_tbl[] = {
	{ 0, "Use hypercall for address space switches" },
	{ 1, "Use hypercall for local TLB flushes" },
	{ 2, "Use hypercall for remote TLB flushes" },
	{ 3, "Use MSRs for accessing APIC EOI, ICR, and TPR" },
	{ 4, "Use MSR for system reset" },
	{ 5, "Use relaxed timing (no watchdog timeouts)" },
	{ 6, "Use DMA remapping" },
	{ 7, "Use interrupt remapping" },
	/* 8 Reserved */
	{ 9, "Deprecate AutoEOI" },
	{ 10, "Use SyntheticClusterIpi hypercall" },
	{ 11, "Use ExProcessorMasks interface" },
	{ 12, "Is nested hypervisor" },
	{ 13, "Use INT for MBEC system calls" },
	{ 14, "Use enlightened VMCS interface" },
	{ 15, "UseSyncedTimeline" },
	/* 16 Reserved */
	{ 17, "UseDirectLocalFlushEntire" },
	{ 18, "NoNonArchitecturalCoreSharing" },
};

uint16_t		hyperv_ver_major;
uint16_t		hyperv_ver_minor;
uint32_t		hyperv_build;
uint32_t		hyperv_svc_pack;
uint32_t		hyperv_svc_number;
uint8_t			hyperv_svc_branch;

uint64_t		hyperv_privs_mask;
uint32_t		hyperv_features;
uint32_t		hyperv_recommendations;
uint32_t		hyperv_max_vcpu;
uint32_t		hyperv_max_lcpu;
uint32_t		hyperv_max_intr;
uint32_t		hyperv_hw_features;

static boolean_t	hyperv_is_init;

static int		hypercall_create(void);
static void		hypercall_destroy(void);
static boolean_t	hyperv_identify(void);
static void		hyperv_show_features(uint64_t, const char *,
    const hvbit_t *, size_t);

hv_status_t
hypercall_post_message(paddr_t msg_paddr)
{
	hv_status_t status;
	status = hypercall_md(HYPERCALL_POST_MESSAGE, msg_paddr, 0);
	status &= HYPERCALL_STATUS_MASK;
	HYPERCALL_LOG_STATUS(status);
	return (status);
}

hv_status_t
hypercall_signal_event(paddr_t monprm_paddr)
{
	hv_status_t status;
	status = hypercall_md(HYPERCALL_SIGNAL_EVENT, monprm_paddr, 0);
	status &= HYPERCALL_STATUS_MASK;
	HYPERCALL_LOG_STATUS(status);
	return (status);
}

/* Get my partition id */
hv_status_t
hv_vmbus_get_partitionid(uint64_t part_paddr)
{
	hv_status_t status;
	status = hypercall_md(HV_CALL_GET_PARTITIONID, 0, part_paddr);
	status &= HYPERCALL_STATUS_MASK;
	HYPERCALL_LOG_STATUS(status);
	return (status);
}

void
hyperv_guid2str(const struct hyperv_guid *guid, char *buf, size_t sz)
{
	const uint8_t *d = guid->hv_guid;

	(void) snprintf(buf, sz, "%02x%02x%02x%02x-"
	    "%02x%02x-%02x%02x-%02x%02x-"
	    "%02x%02x%02x%02x%02x%02x",
	    d[3], d[2], d[1], d[0],
	    d[5], d[4], d[7], d[6], d[8], d[9],
	    d[10], d[11], d[12], d[13], d[14], d[15]);
}

static int
hyperv_parse_nibble(char c)
{
	if (c >= 'A' && c <= 'F') {
		return (c - 'A' + 10);
	}
	if (c >= 'a' && c <= 'f') {
		return (c - 'a' + 10);
	}
	if (c >= '0' && c <= '9') {
		return (c - '0');
	}

	return (-1);
}

static boolean_t
hyperv_parse_byte(const char *s, uint8_t *vp)
{
	int hi, lo;

	if (s[0] == '\0')
		return (B_FALSE);
	hi = hyperv_parse_nibble(s[0]);
	if (hi == -1)
		return (B_FALSE);

	if (s[1] == '\0')
		return (B_FALSE);
	lo = hyperv_parse_nibble(s[1]);
	if (lo == -1)
		return (B_FALSE);

	*vp = (uint8_t)hi << 4 | ((uint8_t)lo & 0x0f);
	return (B_TRUE);
}

boolean_t
hyperv_str2guid(const char *s, struct hyperv_guid *guid)
{
	/* This matches the byte order used in hyperv_guid2str. */
	static const uint_t guidpos[] = {
		3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15
	};

	/* How the bytes are grouped */
	static const uint_t groups[] = { 8, 13, 18, 23 };

	uint_t guidx = 0, sidx = 0, grpidx = 0;
	uint8_t byte;

	while (s[sidx] != '\0' && guidx < ARRAY_SIZE(guidpos)) {
		if (s[sidx] == '-') {
			if (sidx != groups[grpidx])
			       return (B_FALSE);
			sidx++;
			grpidx++;
			continue;
		}

		/*
		 * We expect the hex values are zero padded, so we always
		 * parse a 2-character hex value into a single byte.
		 */
		if (!hyperv_parse_byte(s + sidx, &byte))
			return (B_FALSE);
		sidx += 2;

		guid->hv_guid[guidpos[guidx++]] = byte;
	}

#ifdef DEBUG
	char check[HYPERV_GUID_STRLEN] = { 0 };

	hyperv_guid2str(guid, check, sizeof (check));
	if (strcmp(s, check) != 0) {
		cmn_err(CE_PANIC, "%s parsed '%s' as '%s'", __func__,
		    s, check);
	}
#endif

	return (B_TRUE);
}

/*
 * Based on conversations with Microsoft engineers about Hyper-V, the
 * way other platforms distinguish between Gen1 and Gen2 VMs is by their
 * boot method. Gen1 VMs always use BIOS while Gen2 always uses EFI.
 * Currently, the easiest way for us to tell if we've booted via EFI is
 * by looking for the presense of the efi-version property on the root
 * nexus.
 *
 * NOTE: This check is also duplicated within the acipica filter code
 * to cons up the EFI framebuffer and ISA bus (as nothing else will in Gen2
 * VMs).
 */
boolean_t
hyperv_isgen2(void)
{
	if (ddi_prop_exists(DDI_DEV_T_ANY, ddi_root_node(), DDI_PROP_DONTPASS,
	    "efi-version") != 0) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

void
do_cpuid(uint32_t eax, struct cpuid_regs *cp)
{
	bzero(cp, sizeof (struct cpuid_regs));
	cp->cp_eax = eax;

	(void) __cpuid_insn(cp);

	hyperv_log(CE_CONT, "?%s: leaf=0x%08x eax=0x%08x ebx=0x%08x"
	    "ecx=0x%08x, edx=0x%08x\n", __func__, eax,
	    cp->cp_eax, cp->cp_ebx, cp->cp_ecx, cp->cp_edx);
}

/*
 * Check if Hyper-V supported in currently booted environment
 * And if so what features are available.
 */
static boolean_t
hyperv_identify(void)
{
	struct cpuid_regs regs;
	unsigned int maxleaf;

	if ((get_hwenv() & HW_MICROSOFT) == 0) {
		cmn_err(CE_CONT,
		    "?%s: NOT Hyper-V environment: 0x%x", __func__,
		    get_hwenv());
		return (B_FALSE);
	}

	hyperv_log(CE_CONT, "?%s: Checking Hyper-V features...\n", __func__);

	do_cpuid(CPUID_LEAF_HV_MAXLEAF, &regs);
	maxleaf = regs.cp_eax;
	if (maxleaf < CPUID_LEAF_HV_LIMITS) {
		cmn_err(CE_WARN,
		    "%s: cpuid max leaves mismatch, maxleaf=0x%08x", __func__,
		    maxleaf);
		return (B_FALSE);
	}

	do_cpuid(CPUID_LEAF_HV_INTERFACE, &regs);
	if (regs.cp_eax != CPUID_HV_IFACE_HYPERV) {
		cmn_err(CE_WARN,
		    "%s: Hyper-V signature mismatch=0x%08x", __func__,
		    regs.cp_eax);
		return (B_FALSE);
	}

	do_cpuid(CPUID_LEAF_HV_FEATURES, &regs);
	if ((regs.cp_eax & CPUID_HV_MSR_HYPERCALL) == 0) {
		/*
		 * Hyper-V w/o Hypercall is impossible; someone
		 * is faking Hyper-V.
		 */
		cmn_err(CE_WARN,
		    "%s: Hypercall Interface not supported, "
		    "please contact your system administrator!", __func__);
		return (B_FALSE);
	}

	hyperv_privs_mask = ((uint64_t)regs.cp_ebx << 32) | regs.cp_eax;
	hyperv_features = regs.cp_edx;

	do_cpuid(CPUID_LEAF_HV_IDENTITY, &regs);

	hyperv_ver_major = regs.cp_ebx >> 16;
	hyperv_ver_minor = regs.cp_ebx & 0xffff;
	hyperv_build = regs.cp_eax;
	hyperv_svc_pack = regs.cp_ecx;
	hyperv_svc_number = regs.cp_edx & 0x00ffffff;
	hyperv_svc_branch = regs.cp_edx >> 24;

	cmn_err(CE_CONT, "?Hyper-V Version: %u.%u.%u [SP%u]\n",
	    hyperv_ver_major, hyperv_ver_minor, hyperv_build, hyperv_svc_pack);

	/*
	 * Hyper-V version numbering is based on Linux source code, in
	 * function ms_hyperv_init_platform().
	 */
	cmn_err(CE_CONT, "?Hyper-V Host Build: %u-%u.%u-%u-%u.%u\n",
	    hyperv_build,
	    hyperv_ver_major, hyperv_ver_minor,
	    hyperv_svc_pack,
	    hyperv_svc_branch, hyperv_svc_number);

	hyperv_show_features(hyperv_privs_mask, "Hyper-V guest access",
	    hyperv_access_tbl, ARRAY_SIZE(hyperv_access_tbl));
	hyperv_show_features(hyperv_features, "Hyper-V features",
	    hyperv_features_tbl, ARRAY_SIZE(hyperv_features_tbl));

	do_cpuid(CPUID_LEAF_HV_RECOMMENDS, &regs);
	hyperv_recommendations = regs.cp_eax;

	hyperv_show_features(hyperv_recommendations,
	    "Hyper-V guest recommendations", hyperv_recommendations_tbl,
	    ARRAY_SIZE(hyperv_recommendations_tbl));
	cmn_err(CE_CONT, "?Hyper-V recommended spinlock retries: %d\n",
	    (int)regs.cp_ebx);
	cmn_err(CE_CONT, "?Hyper-V physical address bits implemented: %u\n",
	    CPU_RECOMMEND_PHYSADDR_BITS(regs.cp_ecx));

	do_cpuid(CPUID_LEAF_HV_LIMITS, &regs);
	hyperv_max_vcpu = regs.cp_eax;
	hyperv_max_lcpu = regs.cp_ebx;
	hyperv_max_intr = regs.cp_ecx;

	cmn_err(CE_CONT, "?Hyper-V limits: Vcpu: %u Lcpu: %u Intrs: %u\n",
	    hyperv_max_vcpu, hyperv_max_lcpu, hyperv_max_intr);

	return (B_TRUE);
}

static int
hyperv_init(void)
{
	hyperv_log(CE_CONT, "?hyperv_init: Checking Hyper-V support...\n");
	if (!hyperv_identify()) {
		hyperv_log(CE_CONT,
		    "?hyperv_init: Hyper-V not supported on this environment");
		return (-1);
	}

	/* Set guest id */
	wrmsr(MSR_HV_GUEST_OS_ID, MSR_HV_GUESTID_ILLUMOS);

	if (hypercall_create() != 0)
		return (-1);

	return (0);
}

/*
 * Enable Hypercall interface
 *
 * All hypercalls are invoked using special opcode.
 * Since this opcode can vary among hyper-v implementations,
 * this is done through a special "Hypercall Page", used by
 * the hypervisor to abstract the differences.
 *
 * We enable Hypercall interface by:
 * - Creating a "Hypercall Page" in guest memory
 * - Programming the Hypercall MSR (MSR_HV_HYPERCALL)
 *   with the GPA (guest physical address) of the above page.
 */
int
hypercall_create(void)
{
	/*
	 * The kernel has a page of text called 'hypercall_page'. Xen
	 * overlays/populates the page with the specific instructions to
	 * issue Xen hypercalls/syscalls. Hyper-V does essentially the
	 * exact same thing (the difference being the register calling
	 * convention). Since there can be only one Hypervisor, we
	 * use the hypercall_page for the same purpose.
	 */
	extern void *hypercall_page(void);

	uint64_t hc, hc_orig;
	pfn_t pfn;

	if ((get_hwenv() & HW_MICROSOFT) == 0)
		return (DDI_FAILURE);

	cmn_err(CE_CONT, "?%s: Enabling Hypercall interface...\n", __func__);

	pfn = hat_getpfnum(kas.a_hat, (caddr_t)hypercall_page);
	ASSERT3U(pfn, !=, PFN_INVALID);

	/* Get the 'reserved' bits, which requires preservation. */
	hc_orig = rdmsr(MSR_HV_HYPERCALL);
	cmn_err(CE_CONT, "?%s: Current Hypercall MSR: 0x%016" PRIx64 "\n",
	    __func__, hc_orig);

	cmn_err(CE_CONT, "?%s: hypercall_page va: 0x%p pa: 0x%p\n",
	    __func__, hypercall_page, (caddr_t)(pfn << PAGE_SHIFT));

	/*
	 * Setup the Hypercall page.
	 *
	 * NOTE: 'reserved' bits (11:1) MUST be preserved.
	 * And bit 0 must be set to 1 to indicate enable Hypercall Page.
	 */
	hc = (pfn << MSR_HV_HYPERCALL_PGSHIFT) |
	    (hc_orig & MSR_HV_HYPERCALL_RSVD_MASK) |
	    MSR_HV_HYPERCALL_ENABLE;

	cmn_err(CE_CONT, "?%s: Programming Hypercall MSR: 0x%016" PRIx64 "\n",
	    __func__, hc);
	wrmsr(MSR_HV_HYPERCALL, hc);

	/*
	 * Confirm that Hypercall page did get setup.
	 */
	hc = rdmsr(MSR_HV_HYPERCALL);

	if ((hc & MSR_HV_HYPERCALL_ENABLE) == 0) {
		cmn_err(CE_CONT, "?%s: Verify Hypercall MSR: 0x%016" PRIx64
		    "failed\n", __func__, hc);
		goto fail;
	}

	cmn_err(CE_CONT, "?%s: Verified Hypercall MSR: 0x%016" PRId64 "\n",
	    __func__, hc);
	cmn_err(CE_CONT, "?%s: Enabling Hypercall interface - SUCCESS !\n",
	    __func__);

	hyperv_is_init = B_TRUE;
	return (DDI_SUCCESS);

fail:
	cmn_err(CE_WARN, "%s: Enabling Hypercall interface - FAILED.",
	    __func__);
	return (DDI_FAILURE);
}

/*
 * Disable Hypercall interface
 */
void
hypercall_destroy(void)
{
	uint64_t hc;

	if (!hyperv_is_init)
		return;

	cmn_err(CE_CONT, "?%s: Disabling Hypercall interface...\n", __func__);

	/* Disable Hypercall */
	hc = rdmsr(MSR_HV_HYPERCALL);
	wrmsr(MSR_HV_HYPERCALL, (hc & MSR_HV_HYPERCALL_RSVD_MASK));

	cmn_err(CE_CONT, "?%s: Disabling Hypercall interface - done.\n",
	    __func__);
}

static void
hyperv_show_features(uint64_t val, const char *desc, const hvbit_t *fields,
    size_t nfields)
{
	if ((boothowto & RB_VERBOSE) == 0)
		return;

	char buf[512] = { 0 };
	ilstr_t ils;
	uint_t i;

	ilstr_init_prealloc(&ils, buf, sizeof (buf));

	ilstr_append_str(&ils, desc);
	ilstr_aprintf(&ils, "%s: 0x%08x\n", desc, val);

	for (i = 0; i < nfields; i++) {
		uint64_t mask = (uint64_t)1 << fields[i].hvb_bit;

		if ((val & mask) == 0)
			continue;

		ilstr_aprintf(&ils, "\t%s\n", fields[i].hvb_desc);
	}

	cmn_err(CE_CONT, "?%s", buf);
}

static struct modldrv hyperv_modldrv = {
	&mod_miscops,
	"Hyper-V Driver"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&hyperv_modldrv,
	NULL
};

int
_init(void)
{
	if (hyperv_init() != 0)
		return (ENOTSUP);

	int error = mod_install(&modlinkage);
	return (error);
}

int
_fini(void)
{
	int error;

	hypercall_destroy();

	error = mod_remove(&modlinkage);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
