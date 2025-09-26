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

/* Copyright 2023 Richard Lowe */

/*
 * CPU Identification
 *
 * Determining the naming, etc, of processors, their features, and potentially
 * any workarounds they require.
 *
 * This is much simpler than on x86, but much less regular than on SPARC.
 */

#include <sys/arm_features.h>
#include <sys/cpu.h>
#include <sys/cpuid.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

struct cpu_partno {
	uint16_t part_id;
	const char *part_name;
};

struct cpu_impl {
	uint8_t impl_id;
	const char *impl_name;
	const struct cpu_partno *impl_part;
};

static const struct cpu_partno cpu_parts_arm[] = {
	{ MIDR_PART_ARM_FOUNDATION,	"Foundation" },
	{ MIDR_PART_ARM_CORTEX_A34,	"Cortex-A34" },
	{ MIDR_PART_ARM_CORTEX_A53,	"Cortex-A53" },
	{ MIDR_PART_ARM_CORTEX_A35,	"Cortex-A35" },
	{ MIDR_PART_ARM_CORTEX_A55,	"Cortex-A55" },
	{ MIDR_PART_ARM_CORTEX_A65,	"Cortex-A65" },
	{ MIDR_PART_ARM_CORTEX_A57,	"Cortex-A57" },
	{ MIDR_PART_ARM_CORTEX_A72,	"Cortex-A72" },
	{ MIDR_PART_ARM_CORTEX_A73,	"Cortex-A73" },
	{ MIDR_PART_ARM_CORTEX_A75,	"Cortex-A75" },
	{ MIDR_PART_ARM_CORTEX_A76,	"Cortex-A76" },
	{ MIDR_PART_ARM_NEOVERSE_N1,	"Neoverse-N1" },
	{ MIDR_PART_ARM_CORTEX_A77,	"Cortex-A77" },
	{ MIDR_PART_ARM_CORTEX_A76AE,	"Cortex-A76AE" },
	{ MIDR_PART_ARM_AEM_V8,		"AEMv8" },
	{ MIDR_PART_ARM_NEOVERSE_V1,	"Neoverse-V1" },
	{ MIDR_PART_ARM_CORTEX_A78,	"Cortex-A78" },
	{ MIDR_PART_ARM_CORTEX_A65AE,	"Cortex-A65AE" },
	{ MIDR_PART_ARM_CORTEX_X1,	"Cortex-X1" },
	{ MIDR_PART_ARM_CORTEX_A510,	"Cortex-A510" },
	{ MIDR_PART_ARM_CORTEX_A710,	"Cortex-A710" },
	{ MIDR_PART_ARM_CORTEX_X2,	"Cortex-X2" },
	{ MIDR_PART_ARM_NEOVERSE_N2,	"Neoverse-N2" },
	{ MIDR_PART_ARM_NEOVERSE_E1,	"Neoverse-E1" },
	{ MIDR_PART_ARM_CORTEX_A78C,	"Cortex-A78C" },
	{ MIDR_PART_ARM_CORTEX_X1C,	"Cortex-X1C" },
	{ MIDR_PART_ARM_CORTEX_A715,	"Cortex-A715" },
	{ MIDR_PART_ARM_CORTEX_X3,	"Cortex-X3" },
	{ MIDR_PART_ARM_NEOVERSE_V2,	"Neoverse-V2" },
	{ MIDR_PART_ARM_CORTEX_A520,	"Cortex-A520" },
	{ MIDR_PART_ARM_CORTEX_A720,	"Cortex-A720" },
	{ MIDR_PART_ARM_CORTEX_X4,	"Cortex-X4" },
	{ MIDR_PART_ARM_NEOVERSE_V3,	"Neoverse-V3" },
	{ MIDR_PART_ARM_CORTEX_X925,	"Cortex-X925" },
	{ MIDR_PART_ARM_CORTEX_A725,	"Cortex-A725" },
	{ MIDR_PART_ARM_NEOVERSE_N3,	"Neoverse-N3" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_cavium[] = {
	{ MIDR_PART_CAVIUM_THUNDERX,		"ThunderX" },
	{ MIDR_PART_CAVIUM_THUNDERX_81XX,	"ThunderX 81xx" },
	{ MIDR_PART_CAVIUM_THUNDERX_83XX,	"ThunderX 83xx" },
	{ MIDR_PART_CAVIUM_THUNDERX2,		"ThunderX2" },
	{ MIDR_PART_CAVIUM_OCTX2_98XX,		"OcteonX2 98xx" },
	{ MIDR_PART_CAVIUM_OCTX2_96XX,		"OcteonX2 96xx" },
	{ MIDR_PART_CAVIUM_OCTX2_95XX,		"OcteonX2 95xx" },
	{ MIDR_PART_CAVIUM_OCTX2_95XXN,		"OcteonX2 95xxN" },
	{ MIDR_PART_CAVIUM_OCTX2_95XXMM,	"OcteonX2 95xxMM" },
	{ MIDR_PART_CAVIUM_OCTX2_95XXO,		"OcteonX2 95xxO" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_amc[] = {
	{ MIDR_PART_AMC_POTENZA,	"Potenza" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_qualcomm[] = {
	{ MIDR_PART_QUALCOMM_KRYO,		"Kryo" },
	{ MIDR_PART_QUALCOMM_KRYO2xx_GOLD,	"Kryo 2xx Gold" },
	{ MIDR_PART_QUALCOMM_KRYO2xx_SILVER,	"Kryo 2xx Silver" },
	{ MIDR_PART_QUALCOMM_FALKOR,		"Falkor" },
	{ MIDR_PART_QUALCOMM_KRYO3xx_SILVER,	"Kryo 3xx Silver" },
	{ MIDR_PART_QUALCOMM_KRYO4xx_SILVER,	"Kryo 4xx Silver" },
	{ MIDR_PART_QUALCOMM_KRYO4xx_GOLD,	"Kryo 4xx Gold" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_broadcom[] = {
	{ MIDR_PART_BROADCOM_BRAHMA_B53,	"Brahma B53" },
	{ MIDR_PART_BROADCOM_VULCAN,		"Vulcan" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_nvidia[] = {
	{ MIDR_PART_NVIDIA_DENVER,	"Denver" },
	{ MIDR_PART_NVIDIA_CARMEL,	"Carmel" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_fujitsu[] = {
	{ MIDR_PART_FUJITSU_A64FX,	"A64FX" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_apple[] = {
	{ MIDR_PART_APPLE_M1_ICESTORM,		"M1 (Icestorm)" },
	{ MIDR_PART_APPLE_M1_FIRESTORM,		"M1 (Firestorm)" },
	{ MIDR_PART_APPLE_M1_ICESTORM_PRO,	"M1 Pro (Icestorm)" },
	{ MIDR_PART_APPLE_M1_FIRESTORM_PRO,	"M1 Pro (Firestorm)" },
	{ MIDR_PART_APPLE_M1_ICESTORM_MAX,	"M1 Max (Icestorm)" },
	{ MIDR_PART_APPLE_M1_FIRESTORM_MAX,	"M1 Max (Firestorm)" },
	{ MIDR_PART_APPLE_M2_BLIZZARD,		"M2 (Blizzard)" },
	{ MIDR_PART_APPLE_M2_AVALANCHE,		"M2 (Avalanche)" },
	{ MIDR_PART_APPLE_M2_BLIZZARD_PRO,	"M2 Pro (Blizzard)" },
	{ MIDR_PART_APPLE_M2_AVALANCHE_PRO,	"M2 Pro (Avalanche)" },
	{ MIDR_PART_APPLE_M2_BLIZZARD_MAX,	"M2 Max (Blizzard)" },
	{ MIDR_PART_APPLE_M2_AVALANCHE_MAX,	"M2 Max (Avalanche)" },
	{ MIDR_PART_APPLE_M3_SAWTOOTH,		"M3 (Sawtooth)" },
	{ MIDR_PART_APPLE_M3_EVEREST,		"M3 (Everest)" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_ampere[] = {
	{ MIDR_PART_AMPERE_AMPERE1,	"Ampere1" },
	{ 0x0, NULL }
};

static const struct cpu_partno cpu_parts_software[] = {
	{ MIDR_PART_SOFTWARE_QEMUMAX,	"QEMU Max" },
	{ 0x0, NULL }
};


static const struct cpu_partno cpu_parts_microsoft[] = {
	{ MIDR_PART_MICROSOFT_AZURE_COBALT_100, "Azure Cobalt 100" },
	{ 0x0, NULL }
};

/* NB: MIDR_IMPL_SOFTWARE is 0x0, use the impl_name as a sentinel */
static const struct cpu_impl cpu_impls[] = {
	{ MIDR_IMPL_SOFTWARE,	"Software",	cpu_parts_software },
	{ MIDR_IMPL_AMPERE,	"Ampere",	cpu_parts_ampere },
	{ MIDR_IMPL_ARM,	"ARM",		cpu_parts_arm },
	{ MIDR_IMPL_BROADCOM,	"Broadcom",	cpu_parts_broadcom },
	{ MIDR_IMPL_CAVIUM,	"Cavium",	cpu_parts_cavium },
	{ MIDR_IMPL_DEC,	"DEC",		NULL },
	{ MIDR_IMPL_FUJITSU,	"Fujitsu",	cpu_parts_fujitsu },
	{ MIDR_IMPL_HISILICON,	"HiSilicon",	NULL },
	{ MIDR_IMPL_INFINEON,	"Infineon",	NULL },
	{ MIDR_IMPL_MOTOROLA,	"Motorola",	NULL },
	{ MIDR_IMPL_NVIDIA,	"Nvidia",	cpu_parts_nvidia },
	{ MIDR_IMPL_AMC,	"AMC",		cpu_parts_amc },
	{ MIDR_IMPL_SAMSUNG,	"Samsung",	NULL },
	{ MIDR_IMPL_QUALCOMM,	"Qualcomm",	cpu_parts_qualcomm },
	{ MIDR_IMPL_MARVELL,	"Marvell",	NULL },
	{ MIDR_IMPL_APPLE,	"Apple",	cpu_parts_apple },
	{ MIDR_IMPL_FARADAY,	"Faraday",	NULL },
	{ MIDR_IMPL_INTEL,	"Intel",	NULL },
	{ MIDR_IMPL_MICROSOFT,	"Microsoft",	cpu_parts_microsoft },
	{ MIDR_IMPL_PHYTIUM,	"Phytium",	NULL },
	{ 0x0,	NULL, NULL },
};

void
cpuid_implementer(const cpu_t *cpu, char *s, size_t n)
{
	uint8_t impl = MIDR_IMPL(cpu->cpu_m.mcpu_midr);
	char *vendor = NULL;

	for (const struct cpu_impl *ci = cpu_impls;
	    ci->impl_name != NULL; ci++) {
		if (ci->impl_id == impl) {
			strlcat(s, ci->impl_name, n);
			return;
		}
	}

	snprintf(s, n, "Unknown [0x%x]", impl);
}

void
cpuid_partname(const cpu_t *cpu, char *s, size_t n)
{
	uint8_t impl = MIDR_IMPL(cpu->cpu_m.mcpu_midr);
	uint16_t partid = MIDR_PART(cpu->cpu_m.mcpu_midr);
	const struct cpu_impl *ci;
	const struct cpu_partno *cp;
	char *part = NULL;

	for (ci = cpu_impls; ci->impl_name != NULL; ci++) {
		if ((ci->impl_id != impl) || (ci->impl_part == NULL))
			continue;

		for (cp = ci->impl_part; cp->part_name != NULL; cp++) {
			if (cp->part_id == partid) {
				strlcat(s, cp->part_name, n);
				return;
			}
		}
	}

	snprintf(s, n, "Unknown [0x%x]", partid);
}

void
cpuid_brandstr(const cpu_t *cpu, char *s, size_t n)
{
	uint8_t impl = MIDR_IMPL(cpu->cpu_m.mcpu_midr);
	uint16_t partid = MIDR_PART(cpu->cpu_m.mcpu_midr);
	const struct cpu_impl *ci;
	const struct cpu_partno *cp;
	char *part = NULL;

	for (ci = cpu_impls; ci->impl_name != NULL; ci++) {
		if (ci->impl_id != impl)
			continue;

		if (ci->impl_part == NULL) {
			snprintf(s, n, "%s Unknown [0x%x] @ %ld MHz",
			    ci->impl_name, partid,
			    cpu->cpu_curr_clock / 1000 / 1000);
			return;
		}

		for (cp = ci->impl_part; cp->part_name != NULL; cp++) {
			if (cp->part_id == partid) {
				snprintf(s, n, "%s %s @ %ld MHz", ci->impl_name,
				    cp->part_name,
				    cpu->cpu_curr_clock / 1000 / 1000);
				return;
			}
		}

		snprintf(s, n, "%s Unknown [0x%x] @ %ld MHz", ci->impl_name,
		    partid, cpu->cpu_curr_clock / 1000 / 1000);
		return;
	}

	snprintf(s, n, "Unknown [0x%x, 0x%x] @ %ld MHz", impl,
	    partid, cpu->cpu_curr_clock / 1000 / 1000);
}

static const char *arm_feature_names[NUM_ARM_FEATURES] = {
	[ARM_FEAT_AdvSIMD]		= "AdvSIMD",
	[ARM_FEAT_AES]			= "AES",
	[ARM_FEAT_PMULL]		= "PMULL",
	[ARM_FEAT_CP15SDISABLE2]	= "CP15SDISABLE2",
	[ARM_FEAT_CSV2]			= "CSV2",
	[ARM_FEAT_CSV2_1p1]		= "CSV2_1p1",
	[ARM_FEAT_CSV2_1p2]		= "CSV2_1p2",
	[ARM_FEAT_CSV2_2]		= "CSV2_2",
	[ARM_FEAT_CSV3]			= "CSV3",
	[ARM_FEAT_DGH]			= "DGH",
	[ARM_FEAT_DoubleLock]		= "DoubleLock",
	[ARM_FEAT_ETS]			= "ETS",
	[ARM_FEAT_FP]			= "FP",
	[ARM_FEAT_IVIPT]		= "IVIPT",
	[ARM_FEAT_PCSRv8]		= "PCSRv8",
	[ARM_FEAT_SPECRES]		= "SPECRES",
	[ARM_FEAT_RAS]			= "RAS",
	[ARM_FEAT_SB]			= "SB",
	[ARM_FEAT_SHA1]			= "SHA1",
	[ARM_FEAT_SHA256]		= "SHA256",
	[ARM_FEAT_SSBS]			= "SSBS",
	[ARM_FEAT_SSBS2]		= "SSBS2",
	[ARM_FEAT_CRC32]		= "CRC32",
	[ARM_FEAT_nTLBPA]		= "nTLBPA",
	[ARM_FEAT_Debugv8p1]		= "Debugv8p1",
	[ARM_FEAT_HPDS]			= "HPDS",
	[ARM_FEAT_LOR]			= "LOR",
	[ARM_FEAT_LSE]			= "LSE",
	[ARM_FEAT_PAN]			= "PAN",
	[ARM_FEAT_PMUv3p1]		= "PMUv3p1",
	[ARM_FEAT_RDM]			= "RDM",
	[ARM_FEAT_HAFDBS]		= "HAFDBS",
	[ARM_FEAT_VHE]			= "VHE",
	[ARM_FEAT_VMID16]		= "VMID16",
	[ARM_FEAT_AA32BF16]		= "AA32BF16",
	[ARM_FEAT_AA32HPD]		= "AA32HPD",
	[ARM_FEAT_AA32I8MM]		= "AA32I8MM",
	[ARM_FEAT_PAN2]			= "PAN2",
	[ARM_FEAT_BF16]			= "BF16",
	[ARM_FEAT_DPB2]			= "DPB2",
	[ARM_FEAT_DPB]			= "DPB",
	[ARM_FEAT_Debugv8p2]		= "Debugv8p2",
	[ARM_FEAT_DotProd]		= "DotProd",
	[ARM_FEAT_EVT]			= "EVT",
	[ARM_FEAT_F32MM]		= "F32MM",
	[ARM_FEAT_F64MM]		= "F64MM",
	[ARM_FEAT_FHM]			= "FHM",
	[ARM_FEAT_FP16]			= "FP16",
	[ARM_FEAT_I8MM]			= "I8MM",
	[ARM_FEAT_IESB]			= "IESB",
	[ARM_FEAT_LPA]			= "LPA",
	[ARM_FEAT_LSMAOC]		= "LSMAOC",
	[ARM_FEAT_LVA]			= "LVA",
	[ARM_FEAT_MPAM]			= "MPAM",
	[ARM_FEAT_PCSRv8p2]		= "PCSRv8p2",
	[ARM_FEAT_SHA3]			= "SHA3",
	[ARM_FEAT_SHA512]		= "SHA512",
	[ARM_FEAT_SM3]			= "SM3",
	[ARM_FEAT_SM4]			= "SM4",
	[ARM_FEAT_SPE]			= "SPE",
	[ARM_FEAT_SVE]			= "SVE",
	[ARM_FEAT_TTCNP]		= "TTCNP",
	[ARM_FEAT_HPDS2]		= "HPDS2",
	[ARM_FEAT_XNX]			= "XNX",
	[ARM_FEAT_UAO]			= "UAO",
	[ARM_FEAT_VPIPT]		= "VPIPT",
	[ARM_FEAT_CCIDX]		= "CCIDX",
	[ARM_FEAT_FCMA]			= "FCMA",
	[ARM_FEAT_DoPD]			= "DoPD",
	[ARM_FEAT_EPAC]			= "EPAC",
	[ARM_FEAT_FPAC]			= "FPAC",
	[ARM_FEAT_FPACCOMBINE]		= "FPACCOMBINE",
	[ARM_FEAT_JSCVT]		= "JSCVT",
	[ARM_FEAT_LRCPC]		= "LRCPC",
	[ARM_FEAT_NV]			= "NV",
	[ARM_FEAT_PACQARMA5]		= "PACQARMA5",
	[ARM_FEAT_PACIMP]		= "PACIMP",
	[ARM_FEAT_PAuth]		= "PAuth",
	[ARM_FEAT_PAuth2]		= "PAuth2",
	[ARM_FEAT_SPEv1p1]		= "SPEv1p1",
	[ARM_FEAT_AMUv1]		= "AMUv1",
	[ARM_FEAT_CNTSC]		= "CNTSC",
	[ARM_FEAT_Debugv8p4]		= "Debugv8p4",
	[ARM_FEAT_DoubleFault]		= "DoubleFault",
	[ARM_FEAT_DIT]			= "DIT",
	[ARM_FEAT_FlagM]		= "FlagM",
	[ARM_FEAT_IDST]			= "IDST",
	[ARM_FEAT_LRCPC2]		= "LRCPC2",
	[ARM_FEAT_LSE2]			= "LSE2",
	[ARM_FEAT_NV2]			= "NV2",
	[ARM_FEAT_PMUv3p4]		= "PMUv3p4",
	[ARM_FEAT_RASv1p1]		= "RASv1p1",
	[ARM_FEAT_S2FWB]		= "S2FWB",
	[ARM_FEAT_SEL2]			= "SEL2",
	[ARM_FEAT_TLBIOS]		= "TLBIOS",
	[ARM_FEAT_TLBIRANGE]		= "TLBIRANGE",
	[ARM_FEAT_TRF]			= "TRF",
	[ARM_FEAT_TTL]			= "TTL",
	[ARM_FEAT_BBM]			= "BBM",
	[ARM_FEAT_TTST]			= "TTST",
	[ARM_FEAT_BTI]			= "BTI",
	[ARM_FEAT_FlagM2]		= "FlagM2",
	[ARM_FEAT_ExS]			= "ExS",
	[ARM_FEAT_E0PD]			= "E0PD",
	[ARM_FEAT_FRINTTS]		= "FRINTTS",
	[ARM_FEAT_GTG]			= "GTG",
	[ARM_FEAT_MTE]			= "MTE",
	[ARM_FEAT_MTE2]			= "MTE2",
	[ARM_FEAT_PMUv3p5]		= "PMUv3p5",
	[ARM_FEAT_RNG]			= "RNG",
	[ARM_FEAT_AMUv1p1]		= "AMUv1p1",
	[ARM_FEAT_ECV]			= "ECV",
	[ARM_FEAT_FGT]			= "FGT",
	[ARM_FEAT_MPAMv0p1]		= "MPAMv0p1",
	[ARM_FEAT_MPAMv1p1]		= "MPAMv1p1",
	[ARM_FEAT_MTPMU]		= "MTPMU",
	[ARM_FEAT_TWED]			= "TWED",
	[ARM_FEAT_ETMv4]		= "ETMv4",
	[ARM_FEAT_ETMv4p1]		= "ETMv4p1",
	[ARM_FEAT_ETMv4p2]		= "ETMv4p2",
	[ARM_FEAT_ETMv4p3]		= "ETMv4p3",
	[ARM_FEAT_ETMv4p4]		= "ETMv4p4",
	[ARM_FEAT_ETMv4p5]		= "ETMv4p5",
	[ARM_FEAT_ETMv4p6]		= "ETMv4p6",
	[ARM_FEAT_GICv3]		= "GICv3",
	[ARM_FEAT_GICv3p1]		= "GICv3p1",
	[ARM_FEAT_GICv3_TDIR]		= "GICv3_TDIR",
	[ARM_FEAT_GICv4]		= "GICv4",
	[ARM_FEAT_GICv4p1]		= "GICv4p1",
	[ARM_FEAT_PMUv3]		= "PMUv3",
	[ARM_FEAT_ETE]			= "ETE",
	[ARM_FEAT_ETEv1p1]		= "ETEv1p1",
	[ARM_FEAT_SVE2]			= "SVE2",
	[ARM_FEAT_SVE_AES]		= "SVE_AES",
	[ARM_FEAT_SVE_PMULL128]		= "SVE_PMULL128",
	[ARM_FEAT_SVE_BitPerm]		= "SVE_BitPerm",
	[ARM_FEAT_SVE_SHA3]		= "SVE_SHA3",
	[ARM_FEAT_SVE_SM4]		= "SVE_SM4",
	[ARM_FEAT_TME]			= "TME",
	[ARM_FEAT_TRBE]			= "TRBE",
	[ARM_FEAT_SME]			= "SME",

	[ARM_FEAT_AFP]			= "AFP",
	[ARM_FEAT_HCX]			= "HCX",
	[ARM_FEAT_LPA2]			= "LPA2",
	[ARM_FEAT_LS64]			= "LS64",
	[ARM_FEAT_LS64_V]		= "LS64_V",
	[ARM_FEAT_LS64_ACCDATA]		= "LS64_ACCDATA",
	[ARM_FEAT_MTE3]			= "MTE3",
	[ARM_FEAT_PAN3]			= "PAN3",
	[ARM_FEAT_PMUv3p7]		= "PMUv3p7",
	[ARM_FEAT_RPRES]		= "RPRES",
	[ARM_FEAT_RME]			= "RME",
	[ARM_FEAT_SME_FA64]		= "SME_FA64",
	[ARM_FEAT_SME_F64F64]		= "SME_F64F64",
	[ARM_FEAT_SME_I16I64]		= "SME_I16I64",
	[ARM_FEAT_EBF16]		= "EBF16",
	[ARM_FEAT_SPEv1p2]		= "SPEv1p2",
	[ARM_FEAT_WFxT]			= "WFxT",
	[ARM_FEAT_XS]			= "XS",
	[ARM_FEAT_BRBE]			= "BRBE",

	[ARM_FEAT_CMOW]			= "CMOW",
	[ARM_FEAT_CONSTPACFIELD]	= "CONSTPACFIELD",
	[ARM_FEAT_Debugv8p8]		= "Debugv8p8",
	[ARM_FEAT_HBC]			= "HBC",
	[ARM_FEAT_HPMN0]		= "HPMN0",
	[ARM_FEAT_NMI]			= "NMI",
	[ARM_FEAT_GICv3_NMI]		= "GICv3_NMI",
	[ARM_FEAT_MOPS]			= "MOPS",
	[ARM_FEAT_PACQARMA3]		= "PACQARMA3",
	[ARM_FEAT_PMUv3_TH]		= "PMUv3_TH",
	[ARM_FEAT_PMUv3p8]		= "PMUv3p8",
	[ARM_FEAT_PMUv3_EXT64]		= "PMUv3_EXT64",
	[ARM_FEAT_PMUv3_EXT32]		= "PMUv3_EXT32",
	[ARM_FEAT_RNG_TRAP]		= "RNG_TRAP",
	[ARM_FEAT_SPEv1p3]		= "SPEv1p3",
	[ARM_FEAT_TIDCP1]		= "TIDCP1",
	[ARM_FEAT_BRBEv1p1]		= "BRBEv1p1",

	[ARM_FEAT_ABLE]			= "ABLE",
	[ARM_FEAT_ADERR]		= "ADERR",
	[ARM_FEAT_ANERR]		= "ANERR",
	[ARM_FEAT_AIE]			= "AIE",
	[ARM_FEAT_B16B16]		= "B16B16",
	[ARM_FEAT_CLRBHB]		= "CLRBHB",
	[ARM_FEAT_CHK]			= "CHK",
	[ARM_FEAT_CSSC]			= "CSSC",
	[ARM_FEAT_CSV2_3]		= "CSV2_3",
	[ARM_FEAT_D128]			= "D128",
	[ARM_FEAT_Debugv8p9]		= "Debugv8p9",
	[ARM_FEAT_DoubleFault2]		= "DoubleFault2",
	[ARM_FEAT_EBEP]			= "EBEP",
	[ARM_FEAT_ECBHB]		= "ECBHB",
	[ARM_FEAT_ETEv1p3]		= "ETEv1p3",
	[ARM_FEAT_FGT2]			= "FGT2",
	[ARM_FEAT_GCS]			= "GCS",
	[ARM_FEAT_HAFT]			= "HAFT",
	[ARM_FEAT_ITE]			= "ITE",
	[ARM_FEAT_LRCPC3]		= "LRCPC3",
	[ARM_FEAT_LSE128]		= "LSE128",
	[ARM_FEAT_LVA3]			= "LVA3",
	[ARM_FEAT_MEC]			= "MEC",
	[ARM_FEAT_MTE4]			= "MTE4",
	[ARM_FEAT_MTE_CANONICAL_TAGS]	= "MTE_CANONICAL_TAGS",
	[ARM_FEAT_MTE_TAGGED_FAR]	= "MTE_TAGGED_FAR",
	[ARM_FEAT_MTE_STORE_ONLY]	= "MTE_STORE_ONLY",
	[ARM_FEAT_MTE_NO_ADDRESS_TAGS]	= "MTE_NO_ADDRESS_TAGS",
	[ARM_FEAT_MTE_ASYM_FAULT]	= "MTE_ASYM_FAULT",
	[ARM_FEAT_MTE_ASYNC]		= "MTE_ASYNC",
	[ARM_FEAT_MTE_PERM]		= "MTE_PERM",
	[ARM_FEAT_PCSRv8p9]		= "PCSRv8p9",
	[ARM_FEAT_PIE]			= "PIE",
	[ARM_FEAT_POE]			= "POE",
	[ARM_FEAT_S1PIE]		= "S1PIE",
	[ARM_FEAT_S2PIE]		= "S2PIE",
	[ARM_FEAT_S1POE]		= "S1POE",
	[ARM_FEAT_S2POE]		= "S2POE",
	[ARM_FEAT_PMUv3p9]		= "PMUv3p9",
	[ARM_FEAT_PMUv3_EDGE]		= "PMUv3_EDGE",
	[ARM_FEAT_PMUv3_ICNTR]		= "PMUv3_ICNTR",
	[ARM_FEAT_PMUv3_SS]		= "PMUv3_SS",
	[ARM_FEAT_PRFMSLC]		= "PRFMSLC",
	[ARM_FEAT_RASv2]		= "RASv2",
	[ARM_FEAT_RPRFM]		= "RPRFM",
	[ARM_FEAT_SCTLR2]		= "SCTLR2",
	[ARM_FEAT_SEBEP]		= "SEBEP",
	[ARM_FEAT_SME_F16F16]		= "SME_F16F16",
	[ARM_FEAT_SME2]			= "SME2",
	[ARM_FEAT_SME2p1]		= "SME2p1",
	[ARM_FEAT_SPECRES2]		= "SPECRES2",
	[ARM_FEAT_SPMU]			= "SPMU",
	[ARM_FEAT_SPEv1p4]		= "SPEv1p4",
	[ARM_FEAT_SPE_FDS]		= "SPE_FDS",
	[ARM_FEAT_SVE2p1]		= "SVE2p1",
	[ARM_FEAT_SYSINSTR128]		= "SYSINSTR128",
	[ARM_FEAT_SYSREG128]		= "SYSREG128",
	[ARM_FEAT_TCR2]			= "TCR2",
	[ARM_FEAT_THE]			= "THE",
	[ARM_FEAT_TRBE_EXT]		= "TRBE_EXT",
	[ARM_FEAT_TRBE_MPAM]		= "TRBE_MPAM",
};

/*
 * XXXARM: These are the x86_feature macros, they seemed too simple to be
 * worth making generic right now.
 */
uchar_t arm_features[BT_SIZEOFMAP(NUM_ARM_FEATURES)];

boolean_t
has_arm_feature(void *featureset, arm_feature_t feature)
{
	ASSERT(feature < NUM_ARM_FEATURES);
	return (BT_TEST((ulong_t *)featureset, feature));
}

void
add_arm_feature(void *featureset, arm_feature_t feature)
{
	ASSERT(feature < NUM_ARM_FEATURES);
	BT_SET((ulong_t *)featureset, feature);
}

void
remove_arm_feature(void *featureset, arm_feature_t feature)
{
	ASSERT(feature < NUM_ARM_FEATURES);
	BT_CLEAR((ulong_t *)featureset, feature);
}

boolean_t
compare_arm_features(void *setA, void *setB)
{
	/*
	 * We assume that the unused bits of the bitmap are always zero.
	 */
	if (memcmp(setA, setB, BT_SIZEOFMAP(NUM_ARM_FEATURES)) == 0) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

void
print_arm_features(void *featureset)
{
	uint_t i;

	for (i = 0; i < NUM_ARM_FEATURES; i++) {
		if (has_arm_feature(featureset, i)) {
			cmn_err(CE_CONT, "?ARM Feature: %s\n",
			    arm_feature_names[i]);
		}
	}
}

enum arm_register {
	ARM_REG_DFR0,
	ARM_REG_DFR1,
	ARM_REG_ISAR0,
	ARM_REG_ISAR1,
	ARM_REG_ISAR2,
	ARM_REG_MMFR0,
	ARM_REG_MMFR1,
	ARM_REG_MMFR2,
	ARM_REG_MMFR3,
	ARM_REG_PFR0,
	ARM_REG_PFR1,
	ARM_REG_SMFR0,
	ARM_REG_ZFR0,
};

struct feature_spec {
	arm_feature_t fs_feature;
	enum arm_register fs_reg;
	uint_t fs_low;
	uint_t fs_high;
	uint64_t fs_value;
	boolean_t fs_signed;
};

#define	FEATURE_UNSIGNED(feat, reg, field, val) \
	{ .fs_feature = feat,			\
	.fs_reg = ARM_REG_##reg,		\
	.fs_low = reg##_##field##_LOW,		\
	.fs_high = reg##_##field##_HIGH,	\
	.fs_value = val,			\
	.fs_signed = B_FALSE			\
	}

#define	FEATURE_SIGNED(feat, reg, field, val)	\
	{ .fs_feature = feat,			\
	.fs_reg = ARM_REG_##reg,		\
	.fs_low = reg##_##field##_LOW,		\
	.fs_high = reg##_##field##_HIGH,	\
	.fs_value = val,			\
	.fs_signed = B_TRUE			\
	}

static const struct feature_spec feature_specs[] = {
	FEATURE_SIGNED(ARM_FEAT_AdvSIMD, PFR0, ADVSIMD, 0),
	FEATURE_SIGNED(ARM_FEAT_FP, PFR0, FP, 0),
	FEATURE_UNSIGNED(ARM_FEAT_CRC32, ISAR0, CRC32, 1),
	FEATURE_UNSIGNED(ARM_FEAT_Debugv8p1, DFR0, DEBUGVER,
	    DFR0_FEAT_DEBUGVER_DEBUGv8),

	/*
	 * NB: These attempt to be in manual order, please try to keep
	 * them that way.
	 */

	/*
	 * A2.2.1 Additional functionality added to Armv8.0 in later
	 * releases pp. A2-76 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_SB, ISAR1, SB, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SSBS, PFR1, SSBS, PFR1_FEAT_SSBS_SSBS),
	FEATURE_UNSIGNED(ARM_FEAT_SSBS2, PFR1, SSBS, PFR1_FEAT_SSBS_SSBS2),

	/* XXXARM: I'm still unclear about CSV2_x.y and fractionals  */
	FEATURE_UNSIGNED(ARM_FEAT_CSV2, PFR0, CSV2, PFR0_FEAT_CSV2),
	FEATURE_UNSIGNED(ARM_FEAT_CSV2_2, PFR0, CSV2, PFR0_FEAT_CSV2_2),
	FEATURE_UNSIGNED(ARM_FEAT_CSV2_3, PFR0, CSV2, PFR0_FEAT_CSV2_3),
	FEATURE_UNSIGNED(ARM_FEAT_CSV2_1p1, PFR1, CSV2_FRAC,
	    PFR1_FEAT_CSV2_1p1),
	FEATURE_UNSIGNED(ARM_FEAT_CSV2_1p2, PFR1, CSV2_FRAC,
	    PFR1_FEAT_CSV2_1p2),
	FEATURE_UNSIGNED(ARM_FEAT_CSV3, PFR0, CSV3, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SPECRES, ISAR1, SPECRES,
	    ISAR1_FEAT_SPECRES_SPECRES),
	FEATURE_SIGNED(ARM_FEAT_DoubleLock, DFR0, DOUBLELOCK, 0),
	FEATURE_UNSIGNED(ARM_FEAT_DGH, ISAR1, DGH, 1),
	FEATURE_UNSIGNED(ARM_FEAT_ETS, MMFR1, ETS, 1),
	FEATURE_UNSIGNED(ARM_FEAT_nTLBPA, MMFR1, NTLBPA, 1),

	/*
	 * A2.3 The Armv8 Cryptographic Extension
	 * pp. A2-80 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_AES, ISAR0, AES, ISAR0_FEAT_AES_AES),
	FEATURE_UNSIGNED(ARM_FEAT_PMULL, ISAR0, AES, ISAR0_FEAT_AES_PMULL),
	FEATURE_UNSIGNED(ARM_FEAT_SHA1, ISAR0, SHA1, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SHA256, ISAR0, SHA2, ISAR0_FEAT_SHA2_SHA256),

	/*
	 * A2.3.1 Armv8.2 extensions to the Cryptographic Extension
	 * pp. A2-81 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_SHA512, ISAR0, SHA2, ISAR0_FEAT_SHA2_SHA512),
	FEATURE_UNSIGNED(ARM_FEAT_SHA3, ISAR0, SHA3, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SM3, ISAR0, SM3, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SM4, ISAR0, SM4, 1),

	/*
	 * A2.4.1 Architectural features added by Armv8.1
	 * pp. A2-82 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_LSE, ISAR0, ATOMIC, ISAR0_FEAT_ATOMIC_LSE),
	FEATURE_UNSIGNED(ARM_FEAT_RDM, ISAR0, RDM, 1),
	FEATURE_UNSIGNED(ARM_FEAT_LOR, MMFR1, LO, 1),
	FEATURE_UNSIGNED(ARM_FEAT_HPDS, MMFR1, HPDS, MMFR1_FEAT_HPDS_HPDS),
	FEATURE_UNSIGNED(ARM_FEAT_HAFDBS, MMFR1, HAFDBS,
	    MMFR1_FEAT_HAFDBS_HAFDBS),
	FEATURE_UNSIGNED(ARM_FEAT_PAN, MMFR1, PAN, MMFR1_FEAT_PAN_PAN),
	FEATURE_UNSIGNED(ARM_FEAT_VMID16, MMFR1, VMIDBITS,
	    MMFR1_FEAT_VMIDBITS_16),
	FEATURE_UNSIGNED(ARM_FEAT_VHE, DFR0, DEBUGVER, DFR0_FEAT_DEBUGVER_VHE),
	FEATURE_SIGNED(ARM_FEAT_PMUv3p1, DFR0, PMUVER,
	    DFR0_FEAT_PMUVER_PMUv3p1),

	/*
	 * A2.4.3 Features added to the Armv8.1 extension in later releases
	 */
	FEATURE_UNSIGNED(ARM_FEAT_PAN3, MMFR1, PAN, MMFR1_FEAT_PAN_PAN3),

	/*
	 * A2.5.1 Architectural features added by Armv8.2
	 * pp. A2-86
	 */
	FEATURE_UNSIGNED(ARM_FEAT_PAN2, MMFR1, PAN, MMFR1_FEAT_PAN_PAN2),
	FEATURE_SIGNED(ARM_FEAT_FP16, PFR0, ADVSIMD, PFR0_FEAT_ADVSIMD_FP16),
	FEATURE_SIGNED(ARM_FEAT_FP16, PFR0, FP, PFR0_FEAT_FP_FP16),
	FEATURE_UNSIGNED(ARM_FEAT_DotProd, ISAR0, DP, 1),
	FEATURE_UNSIGNED(ARM_FEAT_FHM, ISAR0, FHM, 1),
	FEATURE_UNSIGNED(ARM_FEAT_LSMAOC, MMFR2, LSM, 1),
	FEATURE_UNSIGNED(ARM_FEAT_UAO, MMFR2, UAO, 1),
	FEATURE_UNSIGNED(ARM_FEAT_DPB, ISAR1, DPB, 1),
	FEATURE_UNSIGNED(ARM_FEAT_HPDS2, MMFR1, HPDS, MMFR1_FEAT_HPDS_HPDS2),
	FEATURE_UNSIGNED(ARM_FEAT_LPA, MMFR0, PARANGE, MMFR0_PARANGE_4P),
	FEATURE_UNSIGNED(ARM_FEAT_LVA, MMFR2, VARANGE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_TTCNP, MMFR2, CNP, 1),
	FEATURE_UNSIGNED(ARM_FEAT_XNX, MMFR1, XNX, 1),
	FEATURE_UNSIGNED(ARM_FEAT_Debugv8p2, DFR0, DEBUGVER,
	    DFR0_FEAT_DEBUGVER_DEBUGv8p2),
	FEATURE_UNSIGNED(ARM_FEAT_IESB, MMFR2, IESB, 1),

	/*
	 * A2.5.3 Features added to the Armv8.2 extension in later releases
	 * pp. A2-93
	 */
	FEATURE_UNSIGNED(ARM_FEAT_EVT, MMFR2, EVT, 1),
	FEATURE_UNSIGNED(ARM_FEAT_DPB2, ISAR1, DPB, ISAR1_FEAT_DPB_DPB2),
	FEATURE_UNSIGNED(ARM_FEAT_BF16, ISAR1, BF16, ISAR1_FEAT_BF16_BF16),
	FEATURE_UNSIGNED(ARM_FEAT_I8MM, ISAR1, I8MM, 1),

	/*
	 * A2.5.4 Features made OPTIONAL in Armv8.2 implementations
	 */
	FEATURE_UNSIGNED(ARM_FEAT_FlagM, ISAR0, TS, ISAR0_FEAT_TS_FLAGM),
	FEATURE_UNSIGNED(ARM_FEAT_LSE2, MMFR2, AT, 1),
	FEATURE_UNSIGNED(ARM_FEAT_LRCPC2, ISAR1, LRCPC,
	    ISAR1_FEAT_LRCPC_LRCPC2),

	/*
	 * A2.6.1 Architectural features added by Armv8.3
	 * pp. A2-96 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_FCMA, ISAR1, FCMA, 1),
	FEATURE_UNSIGNED(ARM_FEAT_JSCVT, ISAR1, JSCVT, 1),
	FEATURE_UNSIGNED(ARM_FEAT_LRCPC, ISAR1, LRCPC, ISAR1_FEAT_LRCPC_LRCPC),
	FEATURE_UNSIGNED(ARM_FEAT_NV, MMFR2, NV, MMFR2_FEAT_NV_NV),
	FEATURE_UNSIGNED(ARM_FEAT_CCIDX, MMFR2, CCIDX, 1),

	/* XXXARM: These PAC ones still confuse me */
	FEATURE_UNSIGNED(ARM_FEAT_PACQARMA3, ISAR2, APA3,
	    ISAR2_FEAT_APA3_PAUTH),
	FEATURE_UNSIGNED(ARM_FEAT_PAuth, ISAR2, APA3, ISAR2_FEAT_APA3_PAUTH),
	FEATURE_UNSIGNED(ARM_FEAT_EPAC, ISAR2, APA3, ISAR2_FEAT_APA3_EPAC),
	FEATURE_UNSIGNED(ARM_FEAT_PAuth, ISAR1, API, ISAR1_FEAT_API_PAuth),
	FEATURE_UNSIGNED(ARM_FEAT_PAuth, ISAR1, APA, ISAR1_FEAT_APA_PAuth),
	FEATURE_UNSIGNED(ARM_FEAT_EPAC, ISAR1, API, ISAR1_FEAT_API_EPAC),
	FEATURE_UNSIGNED(ARM_FEAT_EPAC, ISAR1, APA, ISAR1_FEAT_APA_EPAC),
	FEATURE_UNSIGNED(ARM_FEAT_PACIMP, ISAR1, GPI, 1),
	FEATURE_UNSIGNED(ARM_FEAT_PACQARMA3, ISAR2, GPA3, 1),
	FEATURE_UNSIGNED(ARM_FEAT_PACQARMA5, ISAR1, GPA, 1),
	FEATURE_UNSIGNED(ARM_FEAT_PACQARMA5, ISAR1, APA, 1),
	FEATURE_SIGNED(ARM_FEAT_PMUv3p4, DFR0, PMUVER,
	    DFR0_FEAT_PMUVER_PMUv3p4),

	/*
	 * A2.6.3 Features added to the Armv8.3 extension in later releases
	 * pp. A2-98 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_SPEv1p1, DFR0, PMSVER,
	    DFR0_FEAT_PMSVER_SPEv1p1),
	/* XXXARM: These PAC ones, too, confuse me still */
	FEATURE_UNSIGNED(ARM_FEAT_PAuth2, ISAR1, API, ISAR1_FEAT_API_PAuth2),
	FEATURE_UNSIGNED(ARM_FEAT_PAuth2, ISAR1, APA, ISAR1_FEAT_APA_PAuth2),
	FEATURE_UNSIGNED(ARM_FEAT_PAuth2, ISAR2, APA3, ISAR2_FEAT_APA3_PAuth2),
	FEATURE_UNSIGNED(ARM_FEAT_FPAC, ISAR1, API, ISAR1_FEAT_API_FPAC),
	FEATURE_UNSIGNED(ARM_FEAT_FPAC, ISAR1, APA, ISAR1_FEAT_APA_FPAC),
	FEATURE_UNSIGNED(ARM_FEAT_FPAC, ISAR2, APA3, ISAR2_FEAT_APA3_FPAC),
	FEATURE_UNSIGNED(ARM_FEAT_FPACCOMBINE, ISAR1, API,
	    ISAR1_FEAT_API_FPACCOMBINE),
	FEATURE_UNSIGNED(ARM_FEAT_FPACCOMBINE, ISAR1, APA,
	    ISAR1_FEAT_APA_FPACCOMBINE),
	FEATURE_UNSIGNED(ARM_FEAT_FPACCOMBINE, ISAR2, APA3,
	    ISAR2_FEAT_APA3_FPACCOMBINE),
	FEATURE_UNSIGNED(ARM_FEAT_CONSTPACFIELD, ISAR2, PAC_FRAC, 1),

	/*
	 * A2.7.1 Architectural features added by Armv8.4
	 * pp. A2-101 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_DIT, PFR0, DIT, 1),
	FEATURE_UNSIGNED(ARM_FEAT_TLBIOS, ISAR0, TLB, ISAR0_FEAT_TLB_TLBIOS),
	FEATURE_UNSIGNED(ARM_FEAT_TLBIRANGE, ISAR0, TLB,
	    ISAR0_FEAT_TLB_TLBIOS_AND_RANGE),
	FEATURE_UNSIGNED(ARM_FEAT_TTL, MMFR2, TTL, 1),
	FEATURE_UNSIGNED(ARM_FEAT_S2FWB, MMFR2, FWB, 1),
	FEATURE_UNSIGNED(ARM_FEAT_TTST, MMFR2, ST, 1),
	FEATURE_UNSIGNED(ARM_FEAT_BBM, MMFR2, BBM, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SEL2, PFR0, SEL2, 1),
	FEATURE_UNSIGNED(ARM_FEAT_NV2, MMFR2, NV, MMFR2_FEAT_NV_NV2),
	FEATURE_UNSIGNED(ARM_FEAT_IDST, MMFR2, IDS, 1),
	FEATURE_UNSIGNED(ARM_FEAT_Debugv8p4, DFR0, DEBUGVER,
	    DFR0_FEAT_DEBUGVER_DEBUGv8p4),
	FEATURE_UNSIGNED(ARM_FEAT_TRF, DFR0, TRACEFILT, 1),

	/*
	 * A2.8.1 Architectural features added by Armv8.5
	 * pp. A2-107 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_FlagM2, ISAR0, TS, ISAR0_FEAT_TS_FLAGM2),
	FEATURE_UNSIGNED(ARM_FEAT_FRINTTS, ISAR1, FRINTTS, 1),
	FEATURE_UNSIGNED(ARM_FEAT_ExS, MMFR0, EXS, 1),
	FEATURE_UNSIGNED(ARM_FEAT_GTG, MMFR0, TGRAN4_2, 1),
	FEATURE_UNSIGNED(ARM_FEAT_GTG, MMFR0, TGRAN64_2, 1),
	FEATURE_UNSIGNED(ARM_FEAT_GTG, MMFR0, TGRAN16_2, 1),
	FEATURE_UNSIGNED(ARM_FEAT_BTI, PFR1, BT, 1),
	FEATURE_UNSIGNED(ARM_FEAT_E0PD, MMFR2, E0PD, 1),
	FEATURE_UNSIGNED(ARM_FEAT_RNG, ISAR0, RNDR, 1),
	FEATURE_UNSIGNED(ARM_FEAT_MTE, PFR1, MTE, PFR1_FEAT_MTE_MTE),
	FEATURE_UNSIGNED(ARM_FEAT_MTE2, PFR1, MTE, PFR1_FEAT_MTE_MTE2),
	FEATURE_SIGNED(ARM_FEAT_PMUv3p5, DFR0, PMUVER,
	    DFR0_FEAT_PMUVER_PMUv3p5),

	/*
	 * A2.8.5 Features added to the Armv8.5 extension in later releases
	 */
	FEATURE_UNSIGNED(ARM_FEAT_MTE3, PFR1, MTE, PFR1_FEAT_MTE_MTE3),
	FEATURE_UNSIGNED(ARM_FEAT_RNG_TRAP, PFR1, RNDR_TRAP, 1),

	/*
	 * A2.9.1 Architectural features added by Armv8.6
	 * pp. A2-111 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_ECV, MMFR0, ECV, MMFR0_FEAT_ECV_ECV),
	FEATURE_UNSIGNED(ARM_FEAT_FGT, MMFR0, FGT, MMFR0_FEAT_FGT_FGT),
	FEATURE_UNSIGNED(ARM_FEAT_TWED, MMFR1, TWED, 1),
	FEATURE_UNSIGNED(ARM_FEAT_AMUv1p1, PFR0, AMU, PFR0_FEAT_AMUv1p1),
	FEATURE_SIGNED(ARM_FEAT_MTPMU, DFR0, MTPMU, 1),

	/*
	 * A2.10.1 Architectural features added by Armv8.7
	 * pp. A2-113
	 */
	FEATURE_UNSIGNED(ARM_FEAT_AFP, MMFR1, AFP, 1),
	FEATURE_UNSIGNED(ARM_FEAT_RPRES, ISAR2, RPRES, 1),
	FEATURE_UNSIGNED(ARM_FEAT_LS64, ISAR1, LS64, ISAR1_FEAT_LS64),
	FEATURE_UNSIGNED(ARM_FEAT_LS64_V, ISAR1, LS64, ISAR1_FEAT_LS64_V),
	FEATURE_UNSIGNED(ARM_FEAT_LS64_ACCDATA, ISAR1, LS64,
	    ISAR1_FEAT_LS64_ACCDATA),
	FEATURE_UNSIGNED(ARM_FEAT_WFxT, ISAR2, WFXT, 1),
	FEATURE_UNSIGNED(ARM_FEAT_HCX, MMFR1, HCX, 1),
	/* XXXARM: Worried about these */
	FEATURE_UNSIGNED(ARM_FEAT_LPA2, MMFR0, TGRAN4_2,
	    MMFR0_FEAT_TGRAN4_2_LPA2),
	FEATURE_UNSIGNED(ARM_FEAT_LPA2, MMFR0, TGRAN16_2,
	    MMFR0_FEAT_TGRAN16_2_LPA2),
	FEATURE_UNSIGNED(ARM_FEAT_LPA2, MMFR0, TGRAN4, MMFR0_FEAT_TGRAN4_LPA2),
	FEATURE_UNSIGNED(ARM_FEAT_LPA2, MMFR0, TGRAN16,
	    MMFR0_FEAT_TGRAN16_LPA2),
	FEATURE_UNSIGNED(ARM_FEAT_XS, ISAR1, XS, 1),
	FEATURE_SIGNED(ARM_FEAT_PMUv3p7, DFR0, PMUVER,
	    DFR0_FEAT_PMUVER_PMUv3p7),
	FEATURE_UNSIGNED(ARM_FEAT_SPEv1p2, DFR0, PMSVER,
	    DFR0_FEAT_PMSVER_SPEv1p2),

	/*
	 * A2.11 The Armv8.8 architecture extension
	 * pp. A2-116 et seq.
	 */
	FEATURE_UNSIGNED(ARM_FEAT_MOPS, ISAR2, MOPS, 1),
	FEATURE_UNSIGNED(ARM_FEAT_HBC, ISAR2, BC, 1),
	FEATURE_UNSIGNED(ARM_FEAT_NMI, PFR1, NMI, 1),
	FEATURE_UNSIGNED(ARM_FEAT_TIDCP1, MMFR1, TIDCP1, 1),
	FEATURE_UNSIGNED(ARM_FEAT_CMOW, MMFR1, CMOW, 1),
	FEATURE_SIGNED(ARM_FEAT_PMUv3p8, DFR0, PMUVER,
	    DFR0_FEAT_PMUVER_PMUv3p8),
	FEATURE_UNSIGNED(ARM_FEAT_HPMN0, DFR0, HPMN0, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SPEv1p3, DFR0, PMSVER,
	    DFR0_FEAT_PMSVER_SPEv1p3),
	FEATURE_UNSIGNED(ARM_FEAT_Debugv8p8, DFR0, DEBUGVER,
	    DFR0_FEAT_DEBUGVER_DEBUGv8p8),

	/*
	 * The following are extensions, sub-versions of which may be above
	 * here as they apply to new ARMv8/9 revs, but added here for the sake
	 * of maintaining order.
	 */

	/* A2.12 The Performance Monitors Extension */
	FEATURE_SIGNED(ARM_FEAT_PMUv3, DFR0, PMUVER, DFR0_FEAT_PMUVER_PMUv3),

	/* A2.13 The Reliability, Availability, and Serviceability Extension */
	/* XXXARM: RAS versions and fracs confuse me, some bits are below */
	FEATURE_UNSIGNED(ARM_FEAT_RAS, PFR0, RAS, PFR0_FEAT_RAS_RASv1),
	FEATURE_UNSIGNED(ARM_FEAT_RASv1p1, PFR0, RAS, PFR0_FEAT_RAS_RASv1p1),
	FEATURE_UNSIGNED(ARM_FEAT_RASv2, PFR0, RAS, PFR0_FEAT_RAS_RASv2),

	/* A2.14 The Statistical Profiling Extension (SPE) */
	FEATURE_UNSIGNED(ARM_FEAT_SPE, DFR0, PMSVER, DFR0_FEAT_PMSVER_SPE),

	/* A2.15 The Scalable Vector Extension (SVE) */
	FEATURE_UNSIGNED(ARM_FEAT_SVE, PFR0, SVE, 1),

	/* A2.16 The Activity Monitors Extension (AMU) */
	FEATURE_UNSIGNED(ARM_FEAT_AMUv1, PFR0, AMU, PFR0_FEAT_AMUv1),

	FEATURE_UNSIGNED(ARM_FEAT_ETE, DFR0, TRACEVER, 1),
	FEATURE_UNSIGNED(ARM_FEAT_TME, ISAR0, TME, 1),
	FEATURE_UNSIGNED(ARM_FEAT_TRBE, DFR0, TRACEBUFFER, 1),
	FEATURE_UNSIGNED(ARM_FEAT_BRBE, DFR0, BRBE, DFR0_FEAT_BRBE_BRBE),
	FEATURE_UNSIGNED(ARM_FEAT_BRBEv1p1, DFR0, BRBE,
	    DFR0_FEAT_BRBE_BRBEv1p1),
	FEATURE_UNSIGNED(ARM_FEAT_RME, PFR0, RME, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SME, PFR1, SME, PFR1_FEAT_SME_SME),
	FEATURE_UNSIGNED(ARM_FEAT_EBF16, ISAR1, BF16, ISAR1_FEAT_BF16_EBF16),
	FEATURE_UNSIGNED(ARM_FEAT_SPECRES2, ISAR1, SPECRES,
	    ISAR1_FEAT_SPECRES_SPECRES2),
	FEATURE_UNSIGNED(ARM_FEAT_LRCPC3, ISAR1, LRCPC,
	    ISAR1_FEAT_LRCPC_LRCPC3),
	FEATURE_UNSIGNED(ARM_FEAT_LSE128, ISAR0, ATOMIC,
	    ISAR0_FEAT_ATOMIC_LSE128),
	FEATURE_UNSIGNED(ARM_FEAT_TRBE_EXT, DFR0, EXTTRCBUFF, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SPEv1p4, DFR0, PMSVER,
	    DFR0_FEAT_PMSVER_SPEv1p4),
	FEATURE_UNSIGNED(ARM_FEAT_SEBEP, DFR0, SEBEP, 1),
	FEATURE_UNSIGNED(ARM_FEAT_PMUv3_SS, DFR0, PMSS, 1),
	FEATURE_SIGNED(ARM_FEAT_PMUv3p9, DFR0, PMUVER,
	    DFR0_FEAT_PMUVER_PMUv3p9),
	FEATURE_UNSIGNED(ARM_FEAT_Debugv8p9, DFR0, DEBUGVER,
	    DFR0_FEAT_DEBUGVER_DEBUGv8p9),
	FEATURE_UNSIGNED(ARM_FEAT_FGT2, MMFR0, FGT, MMFR0_FEAT_FGT_FGT2),
	FEATURE_UNSIGNED(ARM_FEAT_ECBHB, MMFR1, ECBHB, 1),
	FEATURE_UNSIGNED(ARM_FEAT_VHE, MMFR1, VH, 1),
	FEATURE_UNSIGNED(ARM_FEAT_HAFT, MMFR1, HAFDBS, MMFR1_FEAT_HAFDBS_HAFT),
	FEATURE_UNSIGNED(ARM_FEAT_PFAR, PFR1, PFAR, 1),
	FEATURE_UNSIGNED(ARM_FEAT_DoubleFault2, PFR1, DF2, 1),
	FEATURE_UNSIGNED(ARM_FEAT_MTE4, PFR1, MTE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_THE, PFR1, THE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_GCS, PFR1, GCS, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SME2, PFR1, SME, PFR1_FEAT_SME_SME2),
	FEATURE_UNSIGNED(ARM_FEAT_CSSC, ISAR2, CSSC, 1),
	FEATURE_UNSIGNED(ARM_FEAT_RPRFM, ISAR2, RPRFM, 1),
	FEATURE_UNSIGNED(ARM_FEAT_PRFMSLC, ISAR2, PRFMSLC, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SYSINSTR128, ISAR2, SYSINSTR_128, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SYSREG128, ISAR2, SYSREG_128, 1),
	FEATURE_UNSIGNED(ARM_FEAT_CLRBHB, ISAR2, CLRBHB, 1),
	FEATURE_UNSIGNED(ARM_FEAT_EBEP, DFR1, EBEP, 1),
	FEATURE_UNSIGNED(ARM_FEAT_ITE, DFR1, ITE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_ABLE, DFR1, ABLE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_PMUv3_ICNTR, DFR1, PMICNTR, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SPMU, DFR1, SPMU, 1),
	FEATURE_UNSIGNED(ARM_FEAT_ADERR, MMFR3, ADERR, 1),
	FEATURE_UNSIGNED(ARM_FEAT_ANERR, MMFR3, ANERR, 1),
	FEATURE_UNSIGNED(ARM_FEAT_MEC, MMFR3, MEC, 1),
	FEATURE_UNSIGNED(ARM_FEAT_AIE, MMFR3, AIE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_S2POE, MMFR3, S2POE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_S1POE, MMFR3, S1POE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_S2PIE, MMFR3, S2PIE, 1),
	FEATURE_UNSIGNED(ARM_FEAT_S1PIE, MMFR3, S1PIE, 1),
};

/* XXXARM: I don't understand the manual with SME v. Streaming SVE. */
static const struct feature_spec sve_feature_specs[] = {
	FEATURE_UNSIGNED(ARM_FEAT_F32MM, ZFR0, F32MM, 1),
	FEATURE_UNSIGNED(ARM_FEAT_F64MM, ZFR0, F64MM, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SVE2, ZFR0, SVEVER, ZFR0_FEAT_SVEVER_SVE2),
	FEATURE_UNSIGNED(ARM_FEAT_SVE_AES, ZFR0, AES, ZFR0_FEAT_AES_AES),
	FEATURE_UNSIGNED(ARM_FEAT_SVE_BitPerm, ZFR0, BITPERM, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SVE_PMULL128, ZFR0, AES,
	    ZFR0_FEAT_AES_PMULL128),
	FEATURE_UNSIGNED(ARM_FEAT_SVE_SHA3, ZFR0, SHA3, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SVE_SM4, ZFR0, SM4, 1),
	FEATURE_UNSIGNED(ARM_FEAT_B16B16, ZFR0, B16B16, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SVE2p1, ZFR0, SVEVER,
	    ZFR0_FEAT_SVEVER_SVE2p1),
};

/* XXXARM: I don't understand the manual with SME v. Streaming SVE. */
static const struct feature_spec sme_feature_specs[] = {
	FEATURE_UNSIGNED(ARM_FEAT_SME_FA64, SMFR0, FA64, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SME_F64F64, SMFR0, F64F64, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SME_I16I64, SMFR0, I16I64, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SME_F16F16, SMFR0, F16F16, 1),
	FEATURE_UNSIGNED(ARM_FEAT_SME2, SMFR0, SMEVER, SMFR0_FEAT_SMEVER_SME2),
	FEATURE_UNSIGNED(ARM_FEAT_SME2p1, SMFR0, SMEVER,
	    SMFR0_FEAT_SMEVER_SME2p1),
};

struct cpuid_regs {
	uint64_t dfr0;
	uint64_t dfr1;
	uint64_t isar0;
	uint64_t isar1;
	uint64_t isar2;
	uint64_t mmfr0;
	uint64_t mmfr1;
	uint64_t mmfr2;
	uint64_t mmfr3;
	uint64_t pfr0;
	uint64_t pfr1;
	uint64_t smfr0;
	uint64_t zfr0;
};

static void
cpuid_features_from_idregs(void *features, const struct feature_spec *specs,
    size_t nspecs, struct cpuid_regs *cpuid_regs)
{
	for (size_t i = 0; i < nspecs; i++) {
		uint64_t *reg;

		switch (specs[i].fs_reg) {
		case ARM_REG_DFR0:
			reg = &cpuid_regs->dfr0;
			break;
		case ARM_REG_DFR1:
			reg = &cpuid_regs->dfr1;
			break;
		case ARM_REG_ISAR0:
			reg = &cpuid_regs->isar0;
			break;
		case ARM_REG_ISAR1:
			reg = &cpuid_regs->isar1;
			break;
		case ARM_REG_ISAR2:
			reg = &cpuid_regs->isar2;
			break;
		case ARM_REG_MMFR0:
			reg = &cpuid_regs->mmfr0;
			break;
		case ARM_REG_MMFR1:
			reg = &cpuid_regs->mmfr1;
			break;
		case ARM_REG_MMFR2:
			reg = &cpuid_regs->mmfr2;
			break;
		case ARM_REG_MMFR3:
			reg = &cpuid_regs->mmfr3;
			break;
		case ARM_REG_PFR0:
			reg = &cpuid_regs->pfr0;
			break;
		case ARM_REG_PFR1:
			reg = &cpuid_regs->pfr1;
			break;
		case ARM_REG_SMFR0:
			reg = &cpuid_regs->smfr0;
			break;
		case ARM_REG_ZFR0:
			reg = &cpuid_regs->zfr0;
			break;
		}

		uint64_t val = bitx64(*reg, specs[i].fs_high, specs[i].fs_low);

		/*
		 * XXXARM: I don't think they're really _signed_ just that
		 * 0xf is -1 is unimplemented.
		 * 0xe is not -2, for eg.
		 */
		if (specs[i].fs_signed && (val == 0xf))
			continue;

		if (val >= specs[i].fs_value) {
			add_arm_feature(features, specs[i].fs_feature);
		}
	}
}

/*
 * Arm Architecture Reference Manual for A-profile architecture
 *    A2.2 Architectural features within Armv8.0 architecture
 *    (ARM DDI 0487I.a)
 *    pp. A2-76 et seq
 *
 * NB: This is only PE features, or at least those in the system ID registers,
 * features of external devices (Debug, PMU, AMU, GIC, CNT, ETM, etc.) are
 * detected with support for those devices (if it exists).
 */
void
cpuid_gather_arm_features(void *features)
{
	struct cpuid_regs cpuid_regs;

	cpuid_regs.pfr0 = read_id_aa64pfr0();
	cpuid_regs.pfr1 = read_id_aa64pfr1();
	cpuid_regs.isar0 = read_id_aa64isar0();
	cpuid_regs.isar1 = read_id_aa64isar1();
	cpuid_regs.isar2 = read_id_aa64isar2();
	cpuid_regs.dfr0 = read_id_aa64dfr0();
	cpuid_regs.dfr1 = read_id_aa64dfr1();
	cpuid_regs.mmfr0 = read_id_aa64mmfr0();
	cpuid_regs.mmfr1 = read_id_aa64mmfr1();
	cpuid_regs.mmfr2 = read_id_aa64mmfr2();
	cpuid_regs.mmfr3 = read_id_aa64mmfr3();

	/* These are initialized later based on FEAT_SVE, and FEAT_SME */
	cpuid_regs.zfr0 = 0;
	cpuid_regs.smfr0 = 0;

	/*
	 * Pass 1: Features which don't imply the existence of feature registers
	 */
	cpuid_features_from_idregs(features, feature_specs,
	    ARRAY_SIZE(feature_specs), &cpuid_regs);

	if (CTR_L1IP(read_ctr_el0()) == 0x0) {
		add_arm_feature(features, ARM_FEAT_VPIPT);
	}

	/*
	 * A2.11 The Armv8.8 architecture extension
	 * pp. A2-116 et seq.
	 *
	 * XXXARM: As with SME/SVE, we can't read the pmmir just yet.
	 */
#if 0
	if (has_arm_feature(features, ARM_FEAT_PMUv3p4)) {
		if (PMMIR_THWIDTH(read_pmmir()) != 0) {
			add_arm_feature(features, ARM_FEAT_PMUv3_TH);
		}
	}
#endif

	/* A2.13 The Reliability, Availability, and Serviceability Extension */
	/* if PFR0.RAS == 1, PFR1.RAS_frac is meaningful */
	if (PFR0_RAS(cpuid_regs.pfr0) == PFR0_FEAT_RAS_RASv1) {
		if (PFR1_RAS_FRAC(cpuid_regs.pfr1) >= PFR1_FEAT_RAS_MINOR_1) {
			add_arm_feature(features, ARM_FEAT_RASv1p1);
		}
	}

	/*
	 * See D17.2.67 pp. D16-6004
	 *
	 * Specifically re: PFR0.RAS, RASv1p1 without PFR1.RAS_frac, and
	 * FEAT_DoubleFault.
	 */
	if (has_arm_feature(features, ARM_FEAT_RASv1p1)) {
		if (PFR0_EL3(cpuid_regs.pfr0) != 0) {
			add_arm_feature(features, ARM_FEAT_DoubleFault);
		}
	}

	/*
	 * A2.17 The Memory Partitioning and Monitoring (MPAM) Extension
	 * See D17.2.67 pp. D16-6005
	 */
	if ((PFR0_MPAM(cpuid_regs.pfr0) >= PFR0_FEAT_MPAM_0dotX) &&
	    (PFR1_MPAM_FRAC(cpuid_regs.pfr1) != PFR1_FEAT_MPAM_MINOR_0)) {
		add_arm_feature(features, ARM_FEAT_MPAM);
	}

	if ((PFR0_MPAM(cpuid_regs.pfr0) == PFR0_FEAT_MPAM_0dotX) &&
	    (PFR1_MPAM_FRAC(cpuid_regs.pfr1) == PFR1_FEAT_MPAM_MINOR_1)) {
		add_arm_feature(features, ARM_FEAT_MPAMv0p1);
	}

	if ((PFR0_MPAM(cpuid_regs.pfr0) == PFR0_FEAT_MPAM_1dotX) &&
	    (PFR1_MPAM_FRAC(cpuid_regs.pfr1) == PFR1_FEAT_MPAM_MINOR_1)) {
		add_arm_feature(features, ARM_FEAT_MPAMv1p1);
	}

	/*
	 * A3.1 Armv9-A architecture extensions
	 * pp. A3-128 et seq.
	 *
	 * XXXARM: We can't handle these just yet because we can't read the
	 * registers (by name, in the assembler), and we can't let the C
	 * compiler try to use these, we just want the assembler to let us
	 * refer to the registers.
	 */
#if 0
	if (has_arm_feature(features, ARM_FEAT_SVE)) {
		/* We know we have SVE, so we can read this */
		cpuid_regs.zfr0 = read_id_aa64zfr0();

		cpuid_features_from_idregs(features, sve_feature_specs,
		    ARRAY_SIZE(sve_feature_specs), &cpuid_regs);
	}

	if (has_arm_feature(features, ARM_FEAT_SME)) {
		/* We know we have SME, so we can read this */
		cpuid_regs.smfr0 = read_id_aa64smfr0();

		cpuid_features_from_idregs(features, sme_feature_specs,
		    ARRAY_SIZE(sme_feature_specs), &cpuid_regs);
	}
#endif
}

/*
 * Given the ARM features in features, set the relevant hwcaps.  Note once
 * again that HWCAPs reflect features that the CPU _and the OS_ both support.
 * This is not straight translation from ARM features.  If the OS doesn't
 * support a feature, the HWCAP _must not be set_.
 */
void
cpuid_features_to_hwcap(void *features, uint_t *hwcaps1, uint_t *hwcaps2,
    uint_t *hwcaps3)
{
	uint_t *hwcaps[] = { hwcaps1, hwcaps2, hwcaps3 };
	struct hwcap_map {
		arm_feature_t hw_feature;
		uint_t hw_index;
		uint_t hw_cap;
	} hwcap_map[] = {
		{ ARM_FEAT_FP, 1, AV_AARCH64_FP },
		{ ARM_FEAT_AdvSIMD,	1, AV_AARCH64_ADVSIMD },
#if 0				/* XXXARM: No SVE yet */
		{ ARM_FEAT_SVE,		1, AV_AARCH64_SVE },
#endif
		{ ARM_FEAT_CRC32,	1, AV_AARCH64_CRC32 },
		{ ARM_FEAT_SB,		1, AV_AARCH64_SB },
		/*
		 * XXXARM: _SSBS controls whether they exist, _SSBS2 whether
		 * msr/mrs can see them, I think.  See A2-76 and D1-4671.
		 *
		 * This means that the useful feature for the HWCAP is SSBS2.
		 */
		{ ARM_FEAT_SSBS2,	1, AV_AARCH64_SSBS },
		{ ARM_FEAT_DGH,		1, AV_AARCH64_DGH },
		{ ARM_FEAT_AES,		1, AV_AARCH64_AES },
		{ ARM_FEAT_PMULL,	1, AV_AARCH64_PMULL },
		{ ARM_FEAT_SHA1,	1, AV_AARCH64_SHA1 },
		{ ARM_FEAT_SHA256,	1, AV_AARCH64_SHA256 },
		{ ARM_FEAT_LSE,		1, AV_AARCH64_LSE },
		{ ARM_FEAT_RDM,		1, AV_AARCH64_RDM },
		{ ARM_FEAT_FP16,	1, AV_AARCH64_FP16 },
		{ ARM_FEAT_DotProd,	1, AV_AARCH64_DOTPROD },
		{ ARM_FEAT_FHM,		1, AV_AARCH64_FHM },
		{ ARM_FEAT_DPB,		1, AV_AARCH64_DCPOP },
#if 0				/* XXXARM: No SVE yet */
		{ ARM_FEAT_F32MM,	1, AV_AARCH64_F32MM },
		{ ARM_FEAT_F64MM,	1, AV_AARCH64_F64MM },
#endif
		{ ARM_FEAT_DPB2,	1, AV_AARCH64_DCPODP },
		{ ARM_FEAT_BF16,	1, AV_AARCH64_BF16 },
		{ ARM_FEAT_I8MM,	1, AV_AARCH64_I8MM },
		{ ARM_FEAT_FCMA,	1, AV_AARCH64_FCMA },
		{ ARM_FEAT_JSCVT,	1, AV_AARCH64_JSCVT },
		{ ARM_FEAT_LRCPC,	1, AV_AARCH64_LRCPC },
#if 0				/* XXXARM: No PAC yet */
		{ ARM_FEAT_Pauth,	1, AV_AARCH64_PACA },
		{ ARM_FEAT_PACIMP,	1, AV_AARCH64_PACG },
#endif
		{ ARM_FEAT_DIT,		1, AV_AARCH64_DIT },
		{ ARM_FEAT_FlagM,	2, AV_AARCH64_2_FLAGM },
		{ ARM_FEAT_LRCPC2,	2, AV_AARCH64_2_ILRCPC },
		{ ARM_FEAT_LSE2,	2, AV_AARCH64_2_LSE2 },
		{ ARM_FEAT_FlagM2,	2, AV_AARCH64_2_FLAGM2 },
		{ ARM_FEAT_FRINTTS,	2, AV_AARCH64_2_FRINTTS },
#if 0				/* XXXARM: No BTI */
		{ ARM_FEAT_BTI,		2, AV_AARCH64_2_BTI },
#endif
		{ ARM_FEAT_RNG,		2, AV_AARCH64_2_RNG },
#if 0				/* XXXARM: No MTE */
		{ ARM_FEAT_MTE,		2, AV_AARCH64_2_MTE },
		{ ARM_FEAT_MTE3,	2, AV_AARCH64_2_MTE2 },
#endif
		{ ARM_FEAT_ECV,			2, AV_AARCH64_2_ECV },
		{ ARM_FEAT_RPRES,		2, AV_AARCH64_2_RPRES },
		{ ARM_FEAT_LS64,		2, AV_AARCH64_2_LD64B },
		{ ARM_FEAT_LS64_V,		2, AV_AARCH64_2_ST64BV },
		{ ARM_FEAT_LS64_ACCDATA,	2, AV_AARCH64_2_ST64BV0 },
		{ ARM_FEAT_WFxT,		2, AV_AARCH64_2_WFXT },
		{ ARM_FEAT_MOPS,		2, AV_AARCH64_2_MOPS },
		{ ARM_FEAT_HBC,			2, AV_AARCH64_2_HBC },
		{ ARM_FEAT_CMOW,		2, AV_AARCH64_2_CMOW },
#if 0				/* XXXARM: No SVE2 support */
		{ ARM_FEAT_SVE2		2, 2, AV_AARCH64_2_SVE2 },
		{ ARM_FEAT_SVE_AES,	2, AV_AARCH64_2_SVE2_AES },
		{ ARM_FEAT_SVE_BitPerm, 2, AV_AARCH64_2_SVE2_BITPERM },
		{ ARM_FEAT_SVE_PMULL128, 2, AV_AARCH64_2_PMULL128 },
		{ ARM_FEAT_SVE_SHA3,	2, AV_AARCH64_2_SHA3 },
		{ ARM_FEAT_SVE_SM4,	2, AV_AARCH64_2_SM4 },
#endif
		/* XXXARM: Needs OS support? */
		{ ARM_FEAT_TME,		2, AV_AARCH64_2_TME },
#if 0				/* XXXARM: No SME support */
		{ ARM_FEAT_SME,		2, AV_AARCH64_2_SME },
		{ ARM_FEAT_SME_FA64,	2, AV_AARCH64_2_FA64 },
		/* XXXARM: I think this needs SME too */
		{ ARM_FEAT_EBF16,	2, AV_AARCH64_2_EBF16 },
		{ ARM_FEAT_SME_F64F64,	2, AV_AARCH64_2_F64F64 },
		{ ARM_FEAT_SME_I16I64,	2, AV_AARCH64_2_I16I64 },
#endif
		{ 0, 0, 0 },

	};

	for (int i = 0; hwcap_map[i].hw_feature != 0; i++) {
		if (has_arm_feature(features, hwcap_map[i].hw_feature)) {
			*hwcaps[hwcap_map[i].hw_index - 1] |=
			    hwcap_map[i].hw_cap;
		}
	}
}
