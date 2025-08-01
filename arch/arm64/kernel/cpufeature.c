// SPDX-License-Identifier: GPL-2.0-only
/*
 * Contains CPU feature definitions
 *
 * Copyright (C) 2015 ARM Ltd.
 *
 * A note for the weary kernel hacker: the code here is confusing and hard to
 * follow! That's partly because it's solving a nasty problem, but also because
 * there's a little bit of over-abstraction that tends to obscure what's going
 * on behind a maze of helper functions and macros.
 *
 * The basic problem is that hardware folks have started gluing together CPUs
 * with distinct architectural features; in some cases even creating SoCs where
 * user-visible instructions are available only on a subset of the available
 * cores. We try to address this by snapshotting the feature registers of the
 * boot CPU and comparing these with the feature registers of each secondary
 * CPU when bringing them up. If there is a mismatch, then we update the
 * snapshot state to indicate the lowest-common denominator of the feature,
 * known as the "safe" value. This snapshot state can be queried to view the
 * "sanitised" value of a feature register.
 *
 * The sanitised register values are used to decide which capabilities we
 * have in the system. These may be in the form of traditional "hwcaps"
 * advertised to userspace or internal "cpucaps" which are used to configure
 * things like alternative patching and static keys. While a feature mismatch
 * may result in a TAINT_CPU_OUT_OF_SPEC kernel taint, a capability mismatch
 * may prevent a CPU from being onlined at all.
 *
 * Some implementation details worth remembering:
 *
 * - Mismatched features are *always* sanitised to a "safe" value, which
 *   usually indicates that the feature is not supported.
 *
 * - A mismatched feature marked with FTR_STRICT will cause a "SANITY CHECK"
 *   warning when onlining an offending CPU and the kernel will be tainted
 *   with TAINT_CPU_OUT_OF_SPEC.
 *
 * - Features marked as FTR_VISIBLE have their sanitised value visible to
 *   userspace. FTR_VISIBLE features in registers that are only visible
 *   to EL0 by trapping *must* have a corresponding HWCAP so that late
 *   onlining of CPUs cannot lead to features disappearing at runtime.
 *
 * - A "feature" is typically a 4-bit register field. A "capability" is the
 *   high-level description derived from the sanitised field value.
 *
 * - Read the Arm ARM (DDI 0487F.a) section D13.1.3 ("Principles of the ID
 *   scheme for fields in ID registers") to understand when feature fields
 *   may be signed or unsigned (FTR_SIGNED and FTR_UNSIGNED accordingly).
 *
 * - KVM exposes its own view of the feature registers to guest operating
 *   systems regardless of FTR_VISIBLE. This is typically driven from the
 *   sanitised register values to allow virtual CPUs to be migrated between
 *   arbitrary physical CPUs, but some features not present on the host are
 *   also advertised and emulated. Look at sys_reg_descs[] for the gory
 *   details.
 *
 * - If the arm64_ftr_bits[] for a register has a missing field, then this
 *   field is treated as STRICT RES0, including for read_sanitised_ftr_reg().
 *   This is stronger than FTR_HIDDEN and can be used to hide features from
 *   KVM guests.
 */

#define pr_fmt(fmt) "CPU features: " fmt

#include <linux/bsearch.h>
#include <linux/cpumask.h>
#include <linux/crash_dump.h>
#include <linux/kstrtox.h>
#include <linux/sort.h>
#include <linux/stop_machine.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/kasan.h>
#include <linux/percpu.h>

#include <asm/cpu.h>
#include <asm/cpufeature.h>
#include <asm/cpu_ops.h>
#include <asm/fpsimd.h>
#include <asm/hwcap.h>
#include <asm/insn.h>
#include <asm/kvm_host.h>
#include <asm/mmu_context.h>
#include <asm/mte.h>
#include <asm/processor.h>
#include <asm/smp.h>
#include <asm/sysreg.h>
#include <asm/traps.h>
#include <asm/vectors.h>
#include <asm/virt.h>

/* Kernel representation of AT_HWCAP and AT_HWCAP2 */
static DECLARE_BITMAP(elf_hwcap, MAX_CPU_FEATURES) __read_mostly;

#ifdef CONFIG_COMPAT
#define COMPAT_ELF_HWCAP_DEFAULT	\
				(COMPAT_HWCAP_HALF|COMPAT_HWCAP_THUMB|\
				 COMPAT_HWCAP_FAST_MULT|COMPAT_HWCAP_EDSP|\
				 COMPAT_HWCAP_TLS|COMPAT_HWCAP_IDIV|\
				 COMPAT_HWCAP_LPAE)
unsigned int compat_elf_hwcap __read_mostly = COMPAT_ELF_HWCAP_DEFAULT;
unsigned int compat_elf_hwcap2 __read_mostly;
#endif

DECLARE_BITMAP(system_cpucaps, ARM64_NCAPS);
EXPORT_SYMBOL(system_cpucaps);
static struct arm64_cpu_capabilities const __ro_after_init *cpucap_ptrs[ARM64_NCAPS];

DECLARE_BITMAP(boot_cpucaps, ARM64_NCAPS);

bool arm64_use_ng_mappings = false;
EXPORT_SYMBOL(arm64_use_ng_mappings);

DEFINE_PER_CPU_READ_MOSTLY(const char *, this_cpu_vector) = vectors;

/*
 * Permit PER_LINUX32 and execve() of 32-bit binaries even if not all CPUs
 * support it?
 */
static bool __read_mostly allow_mismatched_32bit_el0;

/*
 * Static branch enabled only if allow_mismatched_32bit_el0 is set and we have
 * seen at least one CPU capable of 32-bit EL0.
 */
DEFINE_STATIC_KEY_FALSE(arm64_mismatched_32bit_el0);

/*
 * Mask of CPUs supporting 32-bit EL0.
 * Only valid if arm64_mismatched_32bit_el0 is enabled.
 */
static cpumask_var_t cpu_32bit_el0_mask __cpumask_var_read_mostly;

void dump_cpu_features(void)
{
	/* file-wide pr_fmt adds "CPU features: " prefix */
	pr_emerg("0x%*pb\n", ARM64_NCAPS, &system_cpucaps);
}

#define ARM64_CPUID_FIELDS(reg, field, min_value)			\
		.sys_reg = SYS_##reg,							\
		.field_pos = reg##_##field##_SHIFT,						\
		.field_width = reg##_##field##_WIDTH,						\
		.sign = reg##_##field##_SIGNED,							\
		.min_field_value = reg##_##field##_##min_value,

#define __ARM64_FTR_BITS(SIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	{						\
		.sign = SIGNED,				\
		.visible = VISIBLE,			\
		.strict = STRICT,			\
		.type = TYPE,				\
		.shift = SHIFT,				\
		.width = WIDTH,				\
		.safe_val = SAFE_VAL,			\
	}

/* Define a feature with unsigned values */
#define ARM64_FTR_BITS(VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	__ARM64_FTR_BITS(FTR_UNSIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL)

/* Define a feature with a signed value */
#define S_ARM64_FTR_BITS(VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	__ARM64_FTR_BITS(FTR_SIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL)

#define ARM64_FTR_END					\
	{						\
		.width = 0,				\
	}

static void cpu_enable_cnp(struct arm64_cpu_capabilities const *cap);

static bool __system_matches_cap(unsigned int n);

/*
 * NOTE: Any changes to the visibility of features should be kept in
 * sync with the documentation of the CPU feature register ABI.
 */
static const struct arm64_ftr_bits ftr_id_aa64isar0[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_RNDR_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_TLB_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_TS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_FHM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_DP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_SM4_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_SM3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_SHA3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_RDM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_ATOMIC_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_CRC32_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_SHA2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_SHA1_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_EL1_AES_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64isar1[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_I8MM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_DGH_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_BF16_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_SPECRES_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_SB_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_FRINTTS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_PTR_AUTH),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_GPI_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_PTR_AUTH),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_GPA_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_LRCPC_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_FCMA_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_JSCVT_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_PTR_AUTH),
		       FTR_STRICT, FTR_EXACT, ID_AA64ISAR1_EL1_API_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_PTR_AUTH),
		       FTR_STRICT, FTR_EXACT, ID_AA64ISAR1_EL1_APA_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR1_EL1_DPB_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64isar2[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64ISAR2_EL1_CSSC_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64ISAR2_EL1_RPRFM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR2_EL1_CLRBHB_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR2_EL1_BC_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR2_EL1_MOPS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_PTR_AUTH),
		       FTR_STRICT, FTR_EXACT, ID_AA64ISAR2_EL1_APA3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_PTR_AUTH),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR2_EL1_GPA3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64ISAR2_EL1_RPRES_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64ISAR2_EL1_WFxT_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64pfr0[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_CSV3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_CSV2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_DIT_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_AMU_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_MPAM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_SEL2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
				   FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_SVE_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_RAS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_GIC_SHIFT, 4, 0),
	S_ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_AdvSIMD_SHIFT, 4, ID_AA64PFR0_EL1_AdvSIMD_NI),
	S_ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_FP_SHIFT, 4, ID_AA64PFR0_EL1_FP_NI),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_EL3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_EL2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_EL1_SHIFT, 4, ID_AA64PFR0_EL1_ELx_64BIT_ONLY),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR0_EL1_EL0_SHIFT, 4, ID_AA64PFR0_EL1_ELx_64BIT_ONLY),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64pfr1[] = {
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_SME_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_MPAM_frac_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_RAS_frac_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_MTE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_MTE_SHIFT, 4, ID_AA64PFR1_EL1_MTE_NI),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_SSBS_SHIFT, 4, ID_AA64PFR1_EL1_SSBS_NI),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_BTI),
				    FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_BT_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64zfr0[] = {
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_F64MM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_F32MM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_I8MM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_SM4_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_SHA3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_BF16_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_BitPerm_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_AES_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SVE),
		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ZFR0_EL1_SVEver_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64smfr0[] = {
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_FA64_SHIFT, 1, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_SMEver_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_I16I64_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_F64F64_SHIFT, 1, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_I16I32_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_B16B16_SHIFT, 1, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_F16F16_SHIFT, 1, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_I8I32_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_F16F32_SHIFT, 1, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_B16F32_SHIFT, 1, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_BI32I32_SHIFT, 1, 0),
	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
		       FTR_STRICT, FTR_EXACT, ID_AA64SMFR0_EL1_F32F32_SHIFT, 1, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64mmfr0[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_ECV_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_FGT_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_EXS_SHIFT, 4, 0),
	/*
	 * Page size not being supported at Stage-2 is not fatal. You
	 * just give up KVM if PAGE_SIZE isn't supported there. Go fix
	 * your favourite nesting hypervisor.
	 *
	 * There is a small corner case where the hypervisor explicitly
	 * advertises a given granule size at Stage-2 (value 2) on some
	 * vCPUs, and uses the fallback to Stage-1 (value 0) for other
	 * vCPUs. Although this is not forbidden by the architecture, it
	 * indicates that the hypervisor is being silly (or buggy).
	 *
	 * We make no effort to cope with this and pretend that if these
	 * fields are inconsistent across vCPUs, then it isn't worth
	 * trying to bring KVM up.
	 */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_EXACT, ID_AA64MMFR0_EL1_TGRAN4_2_SHIFT, 4, 1),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_EXACT, ID_AA64MMFR0_EL1_TGRAN64_2_SHIFT, 4, 1),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_EXACT, ID_AA64MMFR0_EL1_TGRAN16_2_SHIFT, 4, 1),
	/*
	 * We already refuse to boot CPUs that don't support our configured
	 * page size, so we can only detect mismatches for a page size other
	 * than the one we're currently using. Unfortunately, SoCs like this
	 * exist in the wild so, even though we don't like it, we'll have to go
	 * along with it and treat them as non-strict.
	 */
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_TGRAN4_SHIFT, 4, ID_AA64MMFR0_EL1_TGRAN4_NI),
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_TGRAN64_SHIFT, 4, ID_AA64MMFR0_EL1_TGRAN64_NI),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_TGRAN16_SHIFT, 4, ID_AA64MMFR0_EL1_TGRAN16_NI),

	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_BIGENDEL0_SHIFT, 4, 0),
	/* Linux shouldn't care about secure memory */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_SNSMEM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_BIGEND_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_ASIDBITS_SHIFT, 4, 0),
	/*
	 * Differing PARange is fine as long as all peripherals and memory are mapped
	 * within the minimum PARange of all CPUs
	 */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_EL1_PARANGE_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64mmfr1[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_TIDCP1_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_AFP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_HCX_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_ETS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_TWED_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_XNX_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_HIGHER_SAFE, ID_AA64MMFR1_EL1_SpecSEI_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_PAN_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_LO_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_HPDS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_VH_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_VMIDBits_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_EL1_HAFDBS_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64mmfr2[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_E0PD_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_EVT_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_BBM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_TTL_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_FWB_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_IDS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_AT_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_ST_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_NV_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_CCIDX_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_VARange_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_IESB_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_LSM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_UAO_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR2_EL1_CnP_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64mmfr3[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR3_EL1_S1PIE_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR3_EL1_TCRX_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_ctr[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_EXACT, 31, 1, 1), /* RES1 */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, CTR_EL0_DIC_SHIFT, 1, 1),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, CTR_EL0_IDC_SHIFT, 1, 1),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_HIGHER_OR_ZERO_SAFE, CTR_EL0_CWG_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_HIGHER_OR_ZERO_SAFE, CTR_EL0_ERG_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, CTR_EL0_DminLine_SHIFT, 4, 1),
	/*
	 * Linux can handle differing I-cache policies. Userspace JITs will
	 * make use of *minLine.
	 * If we have differing I-cache policies, report it as the weakest - VIPT.
	 */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_EXACT, CTR_EL0_L1Ip_SHIFT, 2, CTR_EL0_L1Ip_VIPT),	/* L1Ip */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, CTR_EL0_IminLine_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static struct arm64_ftr_override __ro_after_init no_override = { };

struct arm64_ftr_reg arm64_ftr_reg_ctrel0 = {
	.name		= "SYS_CTR_EL0",
	.ftr_bits	= ftr_ctr,
	.override	= &no_override,
};

static const struct arm64_ftr_bits ftr_id_mmfr0[] = {
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR0_EL1_InnerShr_SHIFT, 4, 0xf),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR0_EL1_FCSE_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_MMFR0_EL1_AuxReg_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR0_EL1_TCM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR0_EL1_ShareLvl_SHIFT, 4, 0),
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR0_EL1_OuterShr_SHIFT, 4, 0xf),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR0_EL1_PMSA_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR0_EL1_VMSA_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_aa64dfr0[] = {
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64DFR0_EL1_DoubleLock_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64DFR0_EL1_PMSVer_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64DFR0_EL1_CTX_CMPs_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64DFR0_EL1_WRPs_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64DFR0_EL1_BRPs_SHIFT, 4, 0),
	/*
	 * We can instantiate multiple PMU instances with different levels
	 * of support.
	 */
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_EXACT, ID_AA64DFR0_EL1_PMUVer_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64DFR0_EL1_DebugVer_SHIFT, 4, 0x6),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_mvfr0[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR0_EL1_FPRound_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR0_EL1_FPShVec_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR0_EL1_FPSqrt_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR0_EL1_FPDivide_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR0_EL1_FPTrap_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, MVFR0_EL1_FPDP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR0_EL1_FPSP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR0_EL1_SIMDReg_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_mvfr1[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, MVFR1_EL1_SIMDFMAC_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, MVFR1_EL1_FPHP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, MVFR1_EL1_SIMDHP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, MVFR1_EL1_SIMDSP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, MVFR1_EL1_SIMDInt_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, MVFR1_EL1_SIMDLS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR1_EL1_FPDNaN_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR1_EL1_FPFtZ_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_mvfr2[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR2_EL1_FPMisc_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, MVFR2_EL1_SIMDMisc_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_dczid[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_EXACT, DCZID_EL0_DZP_SHIFT, 1, 1),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, DCZID_EL0_BS_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_gmid[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, GMID_EL1_BS_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_isar0[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR0_EL1_Divide_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR0_EL1_Debug_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR0_EL1_Coproc_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR0_EL1_CmpBranch_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR0_EL1_BitField_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR0_EL1_BitCount_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR0_EL1_Swap_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_isar5[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR5_EL1_RDM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR5_EL1_CRC32_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR5_EL1_SHA2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR5_EL1_SHA1_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR5_EL1_AES_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR5_EL1_SEVL_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_mmfr4[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR4_EL1_EVT_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR4_EL1_CCIDX_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR4_EL1_LSM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR4_EL1_HPDS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR4_EL1_CnP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR4_EL1_XNX_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR4_EL1_AC2_SHIFT, 4, 0),

	/*
	 * SpecSEI = 1 indicates that the PE might generate an SError on an
	 * external abort on speculative read. It is safe to assume that an
	 * SError might be generated than it will not be. Hence it has been
	 * classified as FTR_HIGHER_SAFE.
	 */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_HIGHER_SAFE, ID_MMFR4_EL1_SpecSEI_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_isar4[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR4_EL1_SWP_frac_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR4_EL1_PSR_M_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR4_EL1_SynchPrim_frac_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR4_EL1_Barrier_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR4_EL1_SMC_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR4_EL1_Writeback_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR4_EL1_WithShifts_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR4_EL1_Unpriv_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_mmfr5[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_MMFR5_EL1_ETS_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_isar6[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR6_EL1_I8MM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR6_EL1_BF16_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR6_EL1_SPECRES_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR6_EL1_SB_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR6_EL1_FHM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR6_EL1_DP_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_ISAR6_EL1_JSCVT_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_pfr0[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR0_EL1_DIT_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_PFR0_EL1_CSV2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR0_EL1_State3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR0_EL1_State2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR0_EL1_State1_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR0_EL1_State0_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_pfr1[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR1_EL1_GIC_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR1_EL1_Virt_frac_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR1_EL1_Sec_frac_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR1_EL1_GenTimer_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR1_EL1_Virtualization_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR1_EL1_MProgMod_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR1_EL1_Security_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_PFR1_EL1_ProgMod_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_pfr2[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_PFR2_EL1_SSBS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_PFR2_EL1_CSV3_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_dfr0[] = {
	/* [31:28] TraceFilt */
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_EXACT, ID_DFR0_EL1_PerfMon_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_DFR0_EL1_MProfDbg_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_DFR0_EL1_MMapTrc_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_DFR0_EL1_CopTrc_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_DFR0_EL1_MMapDbg_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_DFR0_EL1_CopSDbg_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_DFR0_EL1_CopDbg_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_id_dfr1[] = {
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_DFR1_EL1_MTPMU_SHIFT, 4, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_zcr[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE,
		ZCR_ELx_LEN_SHIFT, ZCR_ELx_LEN_WIDTH, 0),	/* LEN */
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_smcr[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE,
		SMCR_ELx_LEN_SHIFT, SMCR_ELx_LEN_WIDTH, 0),	/* LEN */
	ARM64_FTR_END,
};

/*
 * Common ftr bits for a 32bit register with all hidden, strict
 * attributes, with 4bit feature fields and a default safe value of
 * 0. Covers the following 32bit registers:
 * id_isar[1-3], id_mmfr[1-3]
 */
static const struct arm64_ftr_bits ftr_generic_32bits[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 28, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 24, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 20, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 16, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 12, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 8, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 4, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 0, 4, 0),
	ARM64_FTR_END,
};

/* Table for a single 32bit feature value */
static const struct arm64_ftr_bits ftr_single32[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 0, 32, 0),
	ARM64_FTR_END,
};

static const struct arm64_ftr_bits ftr_raz[] = {
	ARM64_FTR_END,
};

#define __ARM64_FTR_REG_OVERRIDE(id_str, id, table, ovr) {	\
		.sys_id = id,					\
		.reg = 	&(struct arm64_ftr_reg){		\
			.name = id_str,				\
			.override = (ovr),			\
			.ftr_bits = &((table)[0]),		\
	}}

#define ARM64_FTR_REG_OVERRIDE(id, table, ovr)	\
	__ARM64_FTR_REG_OVERRIDE(#id, id, table, ovr)

#define ARM64_FTR_REG(id, table)		\
	__ARM64_FTR_REG_OVERRIDE(#id, id, table, &no_override)

struct arm64_ftr_override __ro_after_init id_aa64mmfr1_override;
struct arm64_ftr_override __ro_after_init id_aa64pfr0_override;
struct arm64_ftr_override __ro_after_init id_aa64pfr1_override;
struct arm64_ftr_override __ro_after_init id_aa64zfr0_override;
struct arm64_ftr_override __ro_after_init id_aa64smfr0_override;
struct arm64_ftr_override __ro_after_init id_aa64isar1_override;
struct arm64_ftr_override __ro_after_init id_aa64isar2_override;

struct arm64_ftr_override arm64_sw_feature_override;

static const struct __ftr_reg_entry {
	u32			sys_id;
	struct arm64_ftr_reg 	*reg;
} arm64_ftr_regs[] = {

	/* Op1 = 0, CRn = 0, CRm = 1 */
	ARM64_FTR_REG(SYS_ID_PFR0_EL1, ftr_id_pfr0),
	ARM64_FTR_REG(SYS_ID_PFR1_EL1, ftr_id_pfr1),
	ARM64_FTR_REG(SYS_ID_DFR0_EL1, ftr_id_dfr0),
	ARM64_FTR_REG(SYS_ID_MMFR0_EL1, ftr_id_mmfr0),
	ARM64_FTR_REG(SYS_ID_MMFR1_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_MMFR2_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_MMFR3_EL1, ftr_generic_32bits),

	/* Op1 = 0, CRn = 0, CRm = 2 */
	ARM64_FTR_REG(SYS_ID_ISAR0_EL1, ftr_id_isar0),
	ARM64_FTR_REG(SYS_ID_ISAR1_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_ISAR2_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_ISAR3_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_ISAR4_EL1, ftr_id_isar4),
	ARM64_FTR_REG(SYS_ID_ISAR5_EL1, ftr_id_isar5),
	ARM64_FTR_REG(SYS_ID_MMFR4_EL1, ftr_id_mmfr4),
	ARM64_FTR_REG(SYS_ID_ISAR6_EL1, ftr_id_isar6),

	/* Op1 = 0, CRn = 0, CRm = 3 */
	ARM64_FTR_REG(SYS_MVFR0_EL1, ftr_mvfr0),
	ARM64_FTR_REG(SYS_MVFR1_EL1, ftr_mvfr1),
	ARM64_FTR_REG(SYS_MVFR2_EL1, ftr_mvfr2),
	ARM64_FTR_REG(SYS_ID_PFR2_EL1, ftr_id_pfr2),
	ARM64_FTR_REG(SYS_ID_DFR1_EL1, ftr_id_dfr1),
	ARM64_FTR_REG(SYS_ID_MMFR5_EL1, ftr_id_mmfr5),

	/* Op1 = 0, CRn = 0, CRm = 4 */
	ARM64_FTR_REG_OVERRIDE(SYS_ID_AA64PFR0_EL1, ftr_id_aa64pfr0,
			       &id_aa64pfr0_override),
	ARM64_FTR_REG_OVERRIDE(SYS_ID_AA64PFR1_EL1, ftr_id_aa64pfr1,
			       &id_aa64pfr1_override),
	ARM64_FTR_REG_OVERRIDE(SYS_ID_AA64ZFR0_EL1, ftr_id_aa64zfr0,
			       &id_aa64zfr0_override),
	ARM64_FTR_REG_OVERRIDE(SYS_ID_AA64SMFR0_EL1, ftr_id_aa64smfr0,
			       &id_aa64smfr0_override),

	/* Op1 = 0, CRn = 0, CRm = 5 */
	ARM64_FTR_REG(SYS_ID_AA64DFR0_EL1, ftr_id_aa64dfr0),
	ARM64_FTR_REG(SYS_ID_AA64DFR1_EL1, ftr_raz),

	/* Op1 = 0, CRn = 0, CRm = 6 */
	ARM64_FTR_REG(SYS_ID_AA64ISAR0_EL1, ftr_id_aa64isar0),
	ARM64_FTR_REG_OVERRIDE(SYS_ID_AA64ISAR1_EL1, ftr_id_aa64isar1,
			       &id_aa64isar1_override),
	ARM64_FTR_REG_OVERRIDE(SYS_ID_AA64ISAR2_EL1, ftr_id_aa64isar2,
			       &id_aa64isar2_override),

	/* Op1 = 0, CRn = 0, CRm = 7 */
	ARM64_FTR_REG(SYS_ID_AA64MMFR0_EL1, ftr_id_aa64mmfr0),
	ARM64_FTR_REG_OVERRIDE(SYS_ID_AA64MMFR1_EL1, ftr_id_aa64mmfr1,
			       &id_aa64mmfr1_override),
	ARM64_FTR_REG(SYS_ID_AA64MMFR2_EL1, ftr_id_aa64mmfr2),
	ARM64_FTR_REG(SYS_ID_AA64MMFR3_EL1, ftr_id_aa64mmfr3),

	/* Op1 = 0, CRn = 1, CRm = 2 */
	ARM64_FTR_REG(SYS_ZCR_EL1, ftr_zcr),
	ARM64_FTR_REG(SYS_SMCR_EL1, ftr_smcr),

	/* Op1 = 1, CRn = 0, CRm = 0 */
	ARM64_FTR_REG(SYS_GMID_EL1, ftr_gmid),

	/* Op1 = 3, CRn = 0, CRm = 0 */
	{ SYS_CTR_EL0, &arm64_ftr_reg_ctrel0 },
	ARM64_FTR_REG(SYS_DCZID_EL0, ftr_dczid),

	/* Op1 = 3, CRn = 14, CRm = 0 */
	ARM64_FTR_REG(SYS_CNTFRQ_EL0, ftr_single32),
};

static int search_cmp_ftr_reg(const void *id, const void *regp)
{
	return (int)(unsigned long)id - (int)((const struct __ftr_reg_entry *)regp)->sys_id;
}

/*
 * get_arm64_ftr_reg_nowarn - Looks up a feature register entry using
 * its sys_reg() encoding. With the array arm64_ftr_regs sorted in the
 * ascending order of sys_id, we use binary search to find a matching
 * entry.
 *
 * returns - Upon success,  matching ftr_reg entry for id.
 *         - NULL on failure. It is upto the caller to decide
 *	     the impact of a failure.
 */
static struct arm64_ftr_reg *get_arm64_ftr_reg_nowarn(u32 sys_id)
{
	const struct __ftr_reg_entry *ret;

	ret = bsearch((const void *)(unsigned long)sys_id,
			arm64_ftr_regs,
			ARRAY_SIZE(arm64_ftr_regs),
			sizeof(arm64_ftr_regs[0]),
			search_cmp_ftr_reg);
	if (ret)
		return ret->reg;
	return NULL;
}

/*
 * get_arm64_ftr_reg - Looks up a feature register entry using
 * its sys_reg() encoding. This calls get_arm64_ftr_reg_nowarn().
 *
 * returns - Upon success,  matching ftr_reg entry for id.
 *         - NULL on failure but with an WARN_ON().
 */
struct arm64_ftr_reg *get_arm64_ftr_reg(u32 sys_id)
{
	struct arm64_ftr_reg *reg;

	reg = get_arm64_ftr_reg_nowarn(sys_id);

	/*
	 * Requesting a non-existent register search is an error. Warn
	 * and let the caller handle it.
	 */
	WARN_ON(!reg);
	return reg;
}

static u64 arm64_ftr_set_value(const struct arm64_ftr_bits *ftrp, s64 reg,
			       s64 ftr_val)
{
	u64 mask = arm64_ftr_mask(ftrp);

	reg &= ~mask;
	reg |= (ftr_val << ftrp->shift) & mask;
	return reg;
}

s64 arm64_ftr_safe_value(const struct arm64_ftr_bits *ftrp, s64 new,
				s64 cur)
{
	s64 ret = 0;

	switch (ftrp->type) {
	case FTR_EXACT:
		ret = ftrp->safe_val;
		break;
	case FTR_LOWER_SAFE:
		ret = min(new, cur);
		break;
	case FTR_HIGHER_OR_ZERO_SAFE:
		if (!cur || !new)
			break;
		fallthrough;
	case FTR_HIGHER_SAFE:
		ret = max(new, cur);
		break;
	default:
		BUG();
	}

	return ret;
}

static void __init sort_ftr_regs(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(arm64_ftr_regs); i++) {
		const struct arm64_ftr_reg *ftr_reg = arm64_ftr_regs[i].reg;
		const struct arm64_ftr_bits *ftr_bits = ftr_reg->ftr_bits;
		unsigned int j = 0;

		/*
		 * Features here must be sorted in descending order with respect
		 * to their shift values and should not overlap with each other.
		 */
		for (; ftr_bits->width != 0; ftr_bits++, j++) {
			unsigned int width = ftr_reg->ftr_bits[j].width;
			unsigned int shift = ftr_reg->ftr_bits[j].shift;
			unsigned int prev_shift;

			WARN((shift  + width) > 64,
				"%s has invalid feature at shift %d\n",
				ftr_reg->name, shift);

			/*
			 * Skip the first feature. There is nothing to
			 * compare against for now.
			 */
			if (j == 0)
				continue;

			prev_shift = ftr_reg->ftr_bits[j - 1].shift;
			WARN((shift + width) > prev_shift,
				"%s has feature overlap at shift %d\n",
				ftr_reg->name, shift);
		}

		/*
		 * Skip the first register. There is nothing to
		 * compare against for now.
		 */
		if (i == 0)
			continue;
		/*
		 * Registers here must be sorted in ascending order with respect
		 * to sys_id for subsequent binary search in get_arm64_ftr_reg()
		 * to work correctly.
		 */
		BUG_ON(arm64_ftr_regs[i].sys_id <= arm64_ftr_regs[i - 1].sys_id);
	}
}

/*
 * Initialise the CPU feature register from Boot CPU values.
 * Also initiliases the strict_mask for the register.
 * Any bits that are not covered by an arm64_ftr_bits entry are considered
 * RES0 for the system-wide value, and must strictly match.
 */
static void init_cpu_ftr_reg(u32 sys_reg, u64 new)
{
	u64 val = 0;
	u64 strict_mask = ~0x0ULL;
	u64 user_mask = 0;
	u64 valid_mask = 0;

	const struct arm64_ftr_bits *ftrp;
	struct arm64_ftr_reg *reg = get_arm64_ftr_reg(sys_reg);

	if (!reg)
		return;

	for (ftrp = reg->ftr_bits; ftrp->width; ftrp++) {
		u64 ftr_mask = arm64_ftr_mask(ftrp);
		s64 ftr_new = arm64_ftr_value(ftrp, new);
		s64 ftr_ovr = arm64_ftr_value(ftrp, reg->override->val);

		if ((ftr_mask & reg->override->mask) == ftr_mask) {
			s64 tmp = arm64_ftr_safe_value(ftrp, ftr_ovr, ftr_new);
			char *str = NULL;

			if (ftr_ovr != tmp) {
				/* Unsafe, remove the override */
				reg->override->mask &= ~ftr_mask;
				reg->override->val &= ~ftr_mask;
				tmp = ftr_ovr;
				str = "ignoring override";
			} else if (ftr_new != tmp) {
				/* Override was valid */
				ftr_new = tmp;
				str = "forced";
			} else if (ftr_ovr == tmp) {
				/* Override was the safe value */
				str = "already set";
			}

			if (str)
				pr_warn("%s[%d:%d]: %s to %llx\n",
					reg->name,
					ftrp->shift + ftrp->width - 1,
					ftrp->shift, str, tmp);
		} else if ((ftr_mask & reg->override->val) == ftr_mask) {
			reg->override->val &= ~ftr_mask;
			pr_warn("%s[%d:%d]: impossible override, ignored\n",
				reg->name,
				ftrp->shift + ftrp->width - 1,
				ftrp->shift);
		}

		val = arm64_ftr_set_value(ftrp, val, ftr_new);

		valid_mask |= ftr_mask;
		if (!ftrp->strict)
			strict_mask &= ~ftr_mask;
		if (ftrp->visible)
			user_mask |= ftr_mask;
		else
			reg->user_val = arm64_ftr_set_value(ftrp,
							    reg->user_val,
							    ftrp->safe_val);
	}

	val &= valid_mask;

	reg->sys_val = val;
	reg->strict_mask = strict_mask;
	reg->user_mask = user_mask;
}

extern const struct arm64_cpu_capabilities arm64_errata[];
static const struct arm64_cpu_capabilities arm64_features[];

static void __init
init_cpucap_indirect_list_from_array(const struct arm64_cpu_capabilities *caps)
{
	for (; caps->matches; caps++) {
		if (WARN(caps->capability >= ARM64_NCAPS,
			"Invalid capability %d\n", caps->capability))
			continue;
		if (WARN(cpucap_ptrs[caps->capability],
			"Duplicate entry for capability %d\n",
			caps->capability))
			continue;
		cpucap_ptrs[caps->capability] = caps;
	}
}

static void __init init_cpucap_indirect_list(void)
{
	init_cpucap_indirect_list_from_array(arm64_features);
	init_cpucap_indirect_list_from_array(arm64_errata);
}

static void __init setup_boot_cpu_capabilities(void);

static void init_32bit_cpu_features(struct cpuinfo_32bit *info)
{
	init_cpu_ftr_reg(SYS_ID_DFR0_EL1, info->reg_id_dfr0);
	init_cpu_ftr_reg(SYS_ID_DFR1_EL1, info->reg_id_dfr1);
	init_cpu_ftr_reg(SYS_ID_ISAR0_EL1, info->reg_id_isar0);
	init_cpu_ftr_reg(SYS_ID_ISAR1_EL1, info->reg_id_isar1);
	init_cpu_ftr_reg(SYS_ID_ISAR2_EL1, info->reg_id_isar2);
	init_cpu_ftr_reg(SYS_ID_ISAR3_EL1, info->reg_id_isar3);
	init_cpu_ftr_reg(SYS_ID_ISAR4_EL1, info->reg_id_isar4);
	init_cpu_ftr_reg(SYS_ID_ISAR5_EL1, info->reg_id_isar5);
	init_cpu_ftr_reg(SYS_ID_ISAR6_EL1, info->reg_id_isar6);
	init_cpu_ftr_reg(SYS_ID_MMFR0_EL1, info->reg_id_mmfr0);
	init_cpu_ftr_reg(SYS_ID_MMFR1_EL1, info->reg_id_mmfr1);
	init_cpu_ftr_reg(SYS_ID_MMFR2_EL1, info->reg_id_mmfr2);
	init_cpu_ftr_reg(SYS_ID_MMFR3_EL1, info->reg_id_mmfr3);
	init_cpu_ftr_reg(SYS_ID_MMFR4_EL1, info->reg_id_mmfr4);
	init_cpu_ftr_reg(SYS_ID_MMFR5_EL1, info->reg_id_mmfr5);
	init_cpu_ftr_reg(SYS_ID_PFR0_EL1, info->reg_id_pfr0);
	init_cpu_ftr_reg(SYS_ID_PFR1_EL1, info->reg_id_pfr1);
	init_cpu_ftr_reg(SYS_ID_PFR2_EL1, info->reg_id_pfr2);
	init_cpu_ftr_reg(SYS_MVFR0_EL1, info->reg_mvfr0);
	init_cpu_ftr_reg(SYS_MVFR1_EL1, info->reg_mvfr1);
	init_cpu_ftr_reg(SYS_MVFR2_EL1, info->reg_mvfr2);
}

void __init init_cpu_features(struct cpuinfo_arm64 *info)
{
	/* Before we start using the tables, make sure it is sorted */
	sort_ftr_regs();

	init_cpu_ftr_reg(SYS_CTR_EL0, info->reg_ctr);
	init_cpu_ftr_reg(SYS_DCZID_EL0, info->reg_dczid);
	init_cpu_ftr_reg(SYS_CNTFRQ_EL0, info->reg_cntfrq);
	init_cpu_ftr_reg(SYS_ID_AA64DFR0_EL1, info->reg_id_aa64dfr0);
	init_cpu_ftr_reg(SYS_ID_AA64DFR1_EL1, info->reg_id_aa64dfr1);
	init_cpu_ftr_reg(SYS_ID_AA64ISAR0_EL1, info->reg_id_aa64isar0);
	init_cpu_ftr_reg(SYS_ID_AA64ISAR1_EL1, info->reg_id_aa64isar1);
	init_cpu_ftr_reg(SYS_ID_AA64ISAR2_EL1, info->reg_id_aa64isar2);
	init_cpu_ftr_reg(SYS_ID_AA64MMFR0_EL1, info->reg_id_aa64mmfr0);
	init_cpu_ftr_reg(SYS_ID_AA64MMFR1_EL1, info->reg_id_aa64mmfr1);
	init_cpu_ftr_reg(SYS_ID_AA64MMFR2_EL1, info->reg_id_aa64mmfr2);
	init_cpu_ftr_reg(SYS_ID_AA64MMFR3_EL1, info->reg_id_aa64mmfr3);
	init_cpu_ftr_reg(SYS_ID_AA64PFR0_EL1, info->reg_id_aa64pfr0);
	init_cpu_ftr_reg(SYS_ID_AA64PFR1_EL1, info->reg_id_aa64pfr1);
	init_cpu_ftr_reg(SYS_ID_AA64ZFR0_EL1, info->reg_id_aa64zfr0);
	init_cpu_ftr_reg(SYS_ID_AA64SMFR0_EL1, info->reg_id_aa64smfr0);

	if (id_aa64pfr0_32bit_el0(info->reg_id_aa64pfr0))
		init_32bit_cpu_features(&info->aarch32);

	if (IS_ENABLED(CONFIG_ARM64_SVE) &&
	    id_aa64pfr0_sve(read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1))) {
		info->reg_zcr = read_zcr_features();
		init_cpu_ftr_reg(SYS_ZCR_EL1, info->reg_zcr);
		vec_init_vq_map(ARM64_VEC_SVE);
	}

	if (IS_ENABLED(CONFIG_ARM64_SME) &&
	    id_aa64pfr1_sme(read_sanitised_ftr_reg(SYS_ID_AA64PFR1_EL1))) {
		info->reg_smcr = read_smcr_features();
		/*
		 * We mask out SMPS since even if the hardware
		 * supports priorities the kernel does not at present
		 * and we block access to them.
		 */
		info->reg_smidr = read_cpuid(SMIDR_EL1) & ~SMIDR_EL1_SMPS;
		init_cpu_ftr_reg(SYS_SMCR_EL1, info->reg_smcr);
		vec_init_vq_map(ARM64_VEC_SME);
	}

	if (id_aa64pfr1_mte(info->reg_id_aa64pfr1))
		init_cpu_ftr_reg(SYS_GMID_EL1, info->reg_gmid);

	/*
	 * Initialize the indirect array of CPU capabilities pointers before we
	 * handle the boot CPU below.
	 */
	init_cpucap_indirect_list();

	/*
	 * Detect and enable early CPU capabilities based on the boot CPU,
	 * after we have initialised the CPU feature infrastructure.
	 */
	setup_boot_cpu_capabilities();
}

static void update_cpu_ftr_reg(struct arm64_ftr_reg *reg, u64 new)
{
	const struct arm64_ftr_bits *ftrp;

	for (ftrp = reg->ftr_bits; ftrp->width; ftrp++) {
		s64 ftr_cur = arm64_ftr_value(ftrp, reg->sys_val);
		s64 ftr_new = arm64_ftr_value(ftrp, new);

		if (ftr_cur == ftr_new)
			continue;
		/* Find a safe value */
		ftr_new = arm64_ftr_safe_value(ftrp, ftr_new, ftr_cur);
		reg->sys_val = arm64_ftr_set_value(ftrp, reg->sys_val, ftr_new);
	}

}

static int check_update_ftr_reg(u32 sys_id, int cpu, u64 val, u64 boot)
{
	struct arm64_ftr_reg *regp = get_arm64_ftr_reg(sys_id);

	if (!regp)
		return 0;

	update_cpu_ftr_reg(regp, val);
	if ((boot & regp->strict_mask) == (val & regp->strict_mask))
		return 0;
	pr_warn("SANITY CHECK: Unexpected variation in %s. Boot CPU: %#016llx, CPU%d: %#016llx\n",
			regp->name, boot, cpu, val);
	return 1;
}

static void relax_cpu_ftr_reg(u32 sys_id, int field)
{
	const struct arm64_ftr_bits *ftrp;
	struct arm64_ftr_reg *regp = get_arm64_ftr_reg(sys_id);

	if (!regp)
		return;

	for (ftrp = regp->ftr_bits; ftrp->width; ftrp++) {
		if (ftrp->shift == field) {
			regp->strict_mask &= ~arm64_ftr_mask(ftrp);
			break;
		}
	}

	/* Bogus field? */
	WARN_ON(!ftrp->width);
}

static void lazy_init_32bit_cpu_features(struct cpuinfo_arm64 *info,
					 struct cpuinfo_arm64 *boot)
{
	static bool boot_cpu_32bit_regs_overridden = false;

	if (!allow_mismatched_32bit_el0 || boot_cpu_32bit_regs_overridden)
		return;

	if (id_aa64pfr0_32bit_el0(boot->reg_id_aa64pfr0))
		return;

	boot->aarch32 = info->aarch32;
	init_32bit_cpu_features(&boot->aarch32);
	boot_cpu_32bit_regs_overridden = true;
}

static int update_32bit_cpu_features(int cpu, struct cpuinfo_32bit *info,
				     struct cpuinfo_32bit *boot)
{
	int taint = 0;
	u64 pfr0 = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);

	/*
	 * If we don't have AArch32 at EL1, then relax the strictness of
	 * EL1-dependent register fields to avoid spurious sanity check fails.
	 */
	if (!id_aa64pfr0_32bit_el1(pfr0)) {
		relax_cpu_ftr_reg(SYS_ID_ISAR4_EL1, ID_ISAR4_EL1_SMC_SHIFT);
		relax_cpu_ftr_reg(SYS_ID_PFR1_EL1, ID_PFR1_EL1_Virt_frac_SHIFT);
		relax_cpu_ftr_reg(SYS_ID_PFR1_EL1, ID_PFR1_EL1_Sec_frac_SHIFT);
		relax_cpu_ftr_reg(SYS_ID_PFR1_EL1, ID_PFR1_EL1_Virtualization_SHIFT);
		relax_cpu_ftr_reg(SYS_ID_PFR1_EL1, ID_PFR1_EL1_Security_SHIFT);
		relax_cpu_ftr_reg(SYS_ID_PFR1_EL1, ID_PFR1_EL1_ProgMod_SHIFT);
	}

	taint |= check_update_ftr_reg(SYS_ID_DFR0_EL1, cpu,
				      info->reg_id_dfr0, boot->reg_id_dfr0);
	taint |= check_update_ftr_reg(SYS_ID_DFR1_EL1, cpu,
				      info->reg_id_dfr1, boot->reg_id_dfr1);
	taint |= check_update_ftr_reg(SYS_ID_ISAR0_EL1, cpu,
				      info->reg_id_isar0, boot->reg_id_isar0);
	taint |= check_update_ftr_reg(SYS_ID_ISAR1_EL1, cpu,
				      info->reg_id_isar1, boot->reg_id_isar1);
	taint |= check_update_ftr_reg(SYS_ID_ISAR2_EL1, cpu,
				      info->reg_id_isar2, boot->reg_id_isar2);
	taint |= check_update_ftr_reg(SYS_ID_ISAR3_EL1, cpu,
				      info->reg_id_isar3, boot->reg_id_isar3);
	taint |= check_update_ftr_reg(SYS_ID_ISAR4_EL1, cpu,
				      info->reg_id_isar4, boot->reg_id_isar4);
	taint |= check_update_ftr_reg(SYS_ID_ISAR5_EL1, cpu,
				      info->reg_id_isar5, boot->reg_id_isar5);
	taint |= check_update_ftr_reg(SYS_ID_ISAR6_EL1, cpu,
				      info->reg_id_isar6, boot->reg_id_isar6);

	/*
	 * Regardless of the value of the AuxReg field, the AIFSR, ADFSR, and
	 * ACTLR formats could differ across CPUs and therefore would have to
	 * be trapped for virtualization anyway.
	 */
	taint |= check_update_ftr_reg(SYS_ID_MMFR0_EL1, cpu,
				      info->reg_id_mmfr0, boot->reg_id_mmfr0);
	taint |= check_update_ftr_reg(SYS_ID_MMFR1_EL1, cpu,
				      info->reg_id_mmfr1, boot->reg_id_mmfr1);
	taint |= check_update_ftr_reg(SYS_ID_MMFR2_EL1, cpu,
				      info->reg_id_mmfr2, boot->reg_id_mmfr2);
	taint |= check_update_ftr_reg(SYS_ID_MMFR3_EL1, cpu,
				      info->reg_id_mmfr3, boot->reg_id_mmfr3);
	taint |= check_update_ftr_reg(SYS_ID_MMFR4_EL1, cpu,
				      info->reg_id_mmfr4, boot->reg_id_mmfr4);
	taint |= check_update_ftr_reg(SYS_ID_MMFR5_EL1, cpu,
				      info->reg_id_mmfr5, boot->reg_id_mmfr5);
	taint |= check_update_ftr_reg(SYS_ID_PFR0_EL1, cpu,
				      info->reg_id_pfr0, boot->reg_id_pfr0);
	taint |= check_update_ftr_reg(SYS_ID_PFR1_EL1, cpu,
				      info->reg_id_pfr1, boot->reg_id_pfr1);
	taint |= check_update_ftr_reg(SYS_ID_PFR2_EL1, cpu,
				      info->reg_id_pfr2, boot->reg_id_pfr2);
	taint |= check_update_ftr_reg(SYS_MVFR0_EL1, cpu,
				      info->reg_mvfr0, boot->reg_mvfr0);
	taint |= check_update_ftr_reg(SYS_MVFR1_EL1, cpu,
				      info->reg_mvfr1, boot->reg_mvfr1);
	taint |= check_update_ftr_reg(SYS_MVFR2_EL1, cpu,
				      info->reg_mvfr2, boot->reg_mvfr2);

	return taint;
}

/*
 * Update system wide CPU feature registers with the values from a
 * non-boot CPU. Also performs SANITY checks to make sure that there
 * aren't any insane variations from that of the boot CPU.
 */
void update_cpu_features(int cpu,
			 struct cpuinfo_arm64 *info,
			 struct cpuinfo_arm64 *boot)
{
	int taint = 0;

	/*
	 * The kernel can handle differing I-cache policies, but otherwise
	 * caches should look identical. Userspace JITs will make use of
	 * *minLine.
	 */
	taint |= check_update_ftr_reg(SYS_CTR_EL0, cpu,
				      info->reg_ctr, boot->reg_ctr);

	/*
	 * Userspace may perform DC ZVA instructions. Mismatched block sizes
	 * could result in too much or too little memory being zeroed if a
	 * process is preempted and migrated between CPUs.
	 */
	taint |= check_update_ftr_reg(SYS_DCZID_EL0, cpu,
				      info->reg_dczid, boot->reg_dczid);

	/* If different, timekeeping will be broken (especially with KVM) */
	taint |= check_update_ftr_reg(SYS_CNTFRQ_EL0, cpu,
				      info->reg_cntfrq, boot->reg_cntfrq);

	/*
	 * The kernel uses self-hosted debug features and expects CPUs to
	 * support identical debug features. We presently need CTX_CMPs, WRPs,
	 * and BRPs to be identical.
	 * ID_AA64DFR1 is currently RES0.
	 */
	taint |= check_update_ftr_reg(SYS_ID_AA64DFR0_EL1, cpu,
				      info->reg_id_aa64dfr0, boot->reg_id_aa64dfr0);
	taint |= check_update_ftr_reg(SYS_ID_AA64DFR1_EL1, cpu,
				      info->reg_id_aa64dfr1, boot->reg_id_aa64dfr1);
	/*
	 * Even in big.LITTLE, processors should be identical instruction-set
	 * wise.
	 */
	taint |= check_update_ftr_reg(SYS_ID_AA64ISAR0_EL1, cpu,
				      info->reg_id_aa64isar0, boot->reg_id_aa64isar0);
	taint |= check_update_ftr_reg(SYS_ID_AA64ISAR1_EL1, cpu,
				      info->reg_id_aa64isar1, boot->reg_id_aa64isar1);
	taint |= check_update_ftr_reg(SYS_ID_AA64ISAR2_EL1, cpu,
				      info->reg_id_aa64isar2, boot->reg_id_aa64isar2);

	/*
	 * Differing PARange support is fine as long as all peripherals and
	 * memory are mapped within the minimum PARange of all CPUs.
	 * Linux should not care about secure memory.
	 */
	taint |= check_update_ftr_reg(SYS_ID_AA64MMFR0_EL1, cpu,
				      info->reg_id_aa64mmfr0, boot->reg_id_aa64mmfr0);
	taint |= check_update_ftr_reg(SYS_ID_AA64MMFR1_EL1, cpu,
				      info->reg_id_aa64mmfr1, boot->reg_id_aa64mmfr1);
	taint |= check_update_ftr_reg(SYS_ID_AA64MMFR2_EL1, cpu,
				      info->reg_id_aa64mmfr2, boot->reg_id_aa64mmfr2);
	taint |= check_update_ftr_reg(SYS_ID_AA64MMFR3_EL1, cpu,
				      info->reg_id_aa64mmfr3, boot->reg_id_aa64mmfr3);

	taint |= check_update_ftr_reg(SYS_ID_AA64PFR0_EL1, cpu,
				      info->reg_id_aa64pfr0, boot->reg_id_aa64pfr0);
	taint |= check_update_ftr_reg(SYS_ID_AA64PFR1_EL1, cpu,
				      info->reg_id_aa64pfr1, boot->reg_id_aa64pfr1);

	taint |= check_update_ftr_reg(SYS_ID_AA64ZFR0_EL1, cpu,
				      info->reg_id_aa64zfr0, boot->reg_id_aa64zfr0);

	taint |= check_update_ftr_reg(SYS_ID_AA64SMFR0_EL1, cpu,
				      info->reg_id_aa64smfr0, boot->reg_id_aa64smfr0);

	if (IS_ENABLED(CONFIG_ARM64_SVE) &&
	    id_aa64pfr0_sve(read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1))) {
		info->reg_zcr = read_zcr_features();
		taint |= check_update_ftr_reg(SYS_ZCR_EL1, cpu,
					info->reg_zcr, boot->reg_zcr);

		/* Probe vector lengths */
		if (!system_capabilities_finalized())
			vec_update_vq_map(ARM64_VEC_SVE);
	}

	if (IS_ENABLED(CONFIG_ARM64_SME) &&
	    id_aa64pfr1_sme(read_sanitised_ftr_reg(SYS_ID_AA64PFR1_EL1))) {
		info->reg_smcr = read_smcr_features();
		/*
		 * We mask out SMPS since even if the hardware
		 * supports priorities the kernel does not at present
		 * and we block access to them.
		 */
		info->reg_smidr = read_cpuid(SMIDR_EL1) & ~SMIDR_EL1_SMPS;
		taint |= check_update_ftr_reg(SYS_SMCR_EL1, cpu,
					info->reg_smcr, boot->reg_smcr);

		/* Probe vector lengths */
		if (!system_capabilities_finalized())
			vec_update_vq_map(ARM64_VEC_SME);
	}

	/*
	 * The kernel uses the LDGM/STGM instructions and the number of tags
	 * they read/write depends on the GMID_EL1.BS field. Check that the
	 * value is the same on all CPUs.
	 */
	if (IS_ENABLED(CONFIG_ARM64_MTE) &&
	    id_aa64pfr1_mte(info->reg_id_aa64pfr1)) {
		taint |= check_update_ftr_reg(SYS_GMID_EL1, cpu,
					      info->reg_gmid, boot->reg_gmid);
	}

	/*
	 * If we don't have AArch32 at all then skip the checks entirely
	 * as the register values may be UNKNOWN and we're not going to be
	 * using them for anything.
	 *
	 * This relies on a sanitised view of the AArch64 ID registers
	 * (e.g. SYS_ID_AA64PFR0_EL1), so we call it last.
	 */
	if (id_aa64pfr0_32bit_el0(info->reg_id_aa64pfr0)) {
		lazy_init_32bit_cpu_features(info, boot);
		taint |= update_32bit_cpu_features(cpu, &info->aarch32,
						   &boot->aarch32);
	}

	/*
	 * Mismatched CPU features are a recipe for disaster. Don't even
	 * pretend to support them.
	 */
	if (taint) {
		pr_warn_once("Unsupported CPU feature variation detected.\n");
		add_taint(TAINT_CPU_OUT_OF_SPEC, LOCKDEP_STILL_OK);
	}
}

u64 read_sanitised_ftr_reg(u32 id)
{
	struct arm64_ftr_reg *regp = get_arm64_ftr_reg(id);

	if (!regp)
		return 0;
	return regp->sys_val;
}
EXPORT_SYMBOL_GPL(read_sanitised_ftr_reg);

#define read_sysreg_case(r)	\
	case r:		val = read_sysreg_s(r); break;

/*
 * __read_sysreg_by_encoding() - Used by a STARTING cpu before cpuinfo is populated.
 * Read the system register on the current CPU
 */
u64 __read_sysreg_by_encoding(u32 sys_id)
{
	struct arm64_ftr_reg *regp;
	u64 val;

	switch (sys_id) {
	read_sysreg_case(SYS_ID_PFR0_EL1);
	read_sysreg_case(SYS_ID_PFR1_EL1);
	read_sysreg_case(SYS_ID_PFR2_EL1);
	read_sysreg_case(SYS_ID_DFR0_EL1);
	read_sysreg_case(SYS_ID_DFR1_EL1);
	read_sysreg_case(SYS_ID_MMFR0_EL1);
	read_sysreg_case(SYS_ID_MMFR1_EL1);
	read_sysreg_case(SYS_ID_MMFR2_EL1);
	read_sysreg_case(SYS_ID_MMFR3_EL1);
	read_sysreg_case(SYS_ID_MMFR4_EL1);
	read_sysreg_case(SYS_ID_MMFR5_EL1);
	read_sysreg_case(SYS_ID_ISAR0_EL1);
	read_sysreg_case(SYS_ID_ISAR1_EL1);
	read_sysreg_case(SYS_ID_ISAR2_EL1);
	read_sysreg_case(SYS_ID_ISAR3_EL1);
	read_sysreg_case(SYS_ID_ISAR4_EL1);
	read_sysreg_case(SYS_ID_ISAR5_EL1);
	read_sysreg_case(SYS_ID_ISAR6_EL1);
	read_sysreg_case(SYS_MVFR0_EL1);
	read_sysreg_case(SYS_MVFR1_EL1);
	read_sysreg_case(SYS_MVFR2_EL1);

	read_sysreg_case(SYS_ID_AA64PFR0_EL1);
	read_sysreg_case(SYS_ID_AA64PFR1_EL1);
	read_sysreg_case(SYS_ID_AA64ZFR0_EL1);
	read_sysreg_case(SYS_ID_AA64SMFR0_EL1);
	read_sysreg_case(SYS_ID_AA64DFR0_EL1);
	read_sysreg_case(SYS_ID_AA64DFR1_EL1);
	read_sysreg_case(SYS_ID_AA64MMFR0_EL1);
	read_sysreg_case(SYS_ID_AA64MMFR1_EL1);
	read_sysreg_case(SYS_ID_AA64MMFR2_EL1);
	read_sysreg_case(SYS_ID_AA64MMFR3_EL1);
	read_sysreg_case(SYS_ID_AA64ISAR0_EL1);
	read_sysreg_case(SYS_ID_AA64ISAR1_EL1);
	read_sysreg_case(SYS_ID_AA64ISAR2_EL1);

	read_sysreg_case(SYS_CNTFRQ_EL0);
	read_sysreg_case(SYS_CTR_EL0);
	read_sysreg_case(SYS_DCZID_EL0);

	default:
		BUG();
		return 0;
	}

	regp  = get_arm64_ftr_reg(sys_id);
	if (regp) {
		val &= ~regp->override->mask;
		val |= (regp->override->val & regp->override->mask);
	}

	return val;
}

#include <linux/irqchip/arm-gic-v3.h>

static bool
has_always(const struct arm64_cpu_capabilities *entry, int scope)
{
	return true;
}

static bool
feature_matches(u64 reg, const struct arm64_cpu_capabilities *entry)
{
	int val = cpuid_feature_extract_field_width(reg, entry->field_pos,
						    entry->field_width,
						    entry->sign);

	return val >= entry->min_field_value;
}

static u64
read_scoped_sysreg(const struct arm64_cpu_capabilities *entry, int scope)
{
	WARN_ON(scope == SCOPE_LOCAL_CPU && preemptible());
	if (scope == SCOPE_SYSTEM)
		return read_sanitised_ftr_reg(entry->sys_reg);
	else
		return __read_sysreg_by_encoding(entry->sys_reg);
}

static bool
has_user_cpuid_feature(const struct arm64_cpu_capabilities *entry, int scope)
{
	int mask;
	struct arm64_ftr_reg *regp;
	u64 val = read_scoped_sysreg(entry, scope);

	regp = get_arm64_ftr_reg(entry->sys_reg);
	if (!regp)
		return false;

	mask = cpuid_feature_extract_unsigned_field_width(regp->user_mask,
							  entry->field_pos,
							  entry->field_width);
	if (!mask)
		return false;

	return feature_matches(val, entry);
}

static bool
has_cpuid_feature(const struct arm64_cpu_capabilities *entry, int scope)
{
	u64 val = read_scoped_sysreg(entry, scope);
	return feature_matches(val, entry);
}

const struct cpumask *system_32bit_el0_cpumask(void)
{
	if (!system_supports_32bit_el0())
		return cpu_none_mask;

	if (static_branch_unlikely(&arm64_mismatched_32bit_el0))
		return cpu_32bit_el0_mask;

	return cpu_possible_mask;
}

static int __init parse_32bit_el0_param(char *str)
{
	allow_mismatched_32bit_el0 = true;
	return 0;
}
early_param("allow_mismatched_32bit_el0", parse_32bit_el0_param);

static ssize_t aarch32_el0_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	const struct cpumask *mask = system_32bit_el0_cpumask();

	return sysfs_emit(buf, "%*pbl\n", cpumask_pr_args(mask));
}
static const DEVICE_ATTR_RO(aarch32_el0);

static int __init aarch32_el0_sysfs_init(void)
{
	struct device *dev_root;
	int ret = 0;

	if (!allow_mismatched_32bit_el0)
		return 0;

	dev_root = bus_get_dev_root(&cpu_subsys);
	if (dev_root) {
		ret = device_create_file(dev_root, &dev_attr_aarch32_el0);
		put_device(dev_root);
	}
	return ret;
}
device_initcall(aarch32_el0_sysfs_init);

static bool has_32bit_el0(const struct arm64_cpu_capabilities *entry, int scope)
{
	if (!has_cpuid_feature(entry, scope))
		return allow_mismatched_32bit_el0;

	if (scope == SCOPE_SYSTEM)
		pr_info("detected: 32-bit EL0 Support\n");

	return true;
}

static bool has_useable_gicv3_cpuif(const struct arm64_cpu_capabilities *entry, int scope)
{
	bool has_sre;

	if (!has_cpuid_feature(entry, scope))
		return false;

	has_sre = gic_enable_sre();
	if (!has_sre)
		pr_warn_once("%s present but disabled by higher exception level\n",
			     entry->desc);

	return has_sre;
}

static bool has_no_hw_prefetch(const struct arm64_cpu_capabilities *entry, int __unused)
{
	u32 midr = read_cpuid_id();

	/* Cavium ThunderX pass 1.x and 2.x */
	return midr_is_cpu_model_range(midr, MIDR_THUNDERX,
		MIDR_CPU_VAR_REV(0, 0),
		MIDR_CPU_VAR_REV(1, MIDR_REVISION_MASK));
}

static bool has_no_fpsimd(const struct arm64_cpu_capabilities *entry, int __unused)
{
	u64 pfr0 = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);

	return cpuid_feature_extract_signed_field(pfr0,
					ID_AA64PFR0_EL1_FP_SHIFT) < 0;
}

static bool has_cache_idc(const struct arm64_cpu_capabilities *entry,
			  int scope)
{
	u64 ctr;

	if (scope == SCOPE_SYSTEM)
		ctr = arm64_ftr_reg_ctrel0.sys_val;
	else
		ctr = read_cpuid_effective_cachetype();

	return ctr & BIT(CTR_EL0_IDC_SHIFT);
}

static void cpu_emulate_effective_ctr(const struct arm64_cpu_capabilities *__unused)
{
	/*
	 * If the CPU exposes raw CTR_EL0.IDC = 0, while effectively
	 * CTR_EL0.IDC = 1 (from CLIDR values), we need to trap accesses
	 * to the CTR_EL0 on this CPU and emulate it with the real/safe
	 * value.
	 */
	if (!(read_cpuid_cachetype() & BIT(CTR_EL0_IDC_SHIFT)))
		sysreg_clear_set(sctlr_el1, SCTLR_EL1_UCT, 0);
}

static bool has_cache_dic(const struct arm64_cpu_capabilities *entry,
			  int scope)
{
	u64 ctr;

	if (scope == SCOPE_SYSTEM)
		ctr = arm64_ftr_reg_ctrel0.sys_val;
	else
		ctr = read_cpuid_cachetype();

	return ctr & BIT(CTR_EL0_DIC_SHIFT);
}

static bool __maybe_unused
has_useable_cnp(const struct arm64_cpu_capabilities *entry, int scope)
{
	/*
	 * Kdump isn't guaranteed to power-off all secondary CPUs, CNP
	 * may share TLB entries with a CPU stuck in the crashed
	 * kernel.
	 */
	if (is_kdump_kernel())
		return false;

	if (cpus_have_const_cap(ARM64_WORKAROUND_NVIDIA_CARMEL_CNP))
		return false;

	return has_cpuid_feature(entry, scope);
}

/*
 * This check is triggered during the early boot before the cpufeature
 * is initialised. Checking the status on the local CPU allows the boot
 * CPU to detect the need for non-global mappings and thus avoiding a
 * pagetable re-write after all the CPUs are booted. This check will be
 * anyway run on individual CPUs, allowing us to get the consistent
 * state once the SMP CPUs are up and thus make the switch to non-global
 * mappings if required.
 */
bool kaslr_requires_kpti(void)
{
	if (!IS_ENABLED(CONFIG_RANDOMIZE_BASE))
		return false;

	/*
	 * E0PD does a similar job to KPTI so can be used instead
	 * where available.
	 */
	if (IS_ENABLED(CONFIG_ARM64_E0PD)) {
		u64 mmfr2 = read_sysreg_s(SYS_ID_AA64MMFR2_EL1);
		if (cpuid_feature_extract_unsigned_field(mmfr2,
						ID_AA64MMFR2_EL1_E0PD_SHIFT))
			return false;
	}

	/*
	 * Systems affected by Cavium erratum 24756 are incompatible
	 * with KPTI.
	 */
	if (IS_ENABLED(CONFIG_CAVIUM_ERRATUM_27456)) {
		extern const struct midr_range cavium_erratum_27456_cpus[];

		if (is_midr_in_range_list(read_cpuid_id(),
					  cavium_erratum_27456_cpus))
			return false;
	}

	return kaslr_enabled();
}

static bool __meltdown_safe = true;
static int __kpti_forced; /* 0: not forced, >0: forced on, <0: forced off */

static bool unmap_kernel_at_el0(const struct arm64_cpu_capabilities *entry,
				int scope)
{
	/* List of CPUs that are not vulnerable and don't need KPTI */
	static const struct midr_range kpti_safe_list[] = {
		MIDR_ALL_VERSIONS(MIDR_CAVIUM_THUNDERX2),
		MIDR_ALL_VERSIONS(MIDR_BRCM_VULCAN),
		MIDR_ALL_VERSIONS(MIDR_BRAHMA_B53),
		MIDR_ALL_VERSIONS(MIDR_CORTEX_A35),
		MIDR_ALL_VERSIONS(MIDR_CORTEX_A53),
		MIDR_ALL_VERSIONS(MIDR_CORTEX_A55),
		MIDR_ALL_VERSIONS(MIDR_CORTEX_A57),
		MIDR_ALL_VERSIONS(MIDR_CORTEX_A72),
		MIDR_ALL_VERSIONS(MIDR_CORTEX_A73),
		MIDR_ALL_VERSIONS(MIDR_HISI_TSV110),
		MIDR_ALL_VERSIONS(MIDR_NVIDIA_CARMEL),
		MIDR_ALL_VERSIONS(MIDR_QCOM_KRYO_2XX_GOLD),
		MIDR_ALL_VERSIONS(MIDR_QCOM_KRYO_2XX_SILVER),
		MIDR_ALL_VERSIONS(MIDR_QCOM_KRYO_3XX_SILVER),
		MIDR_ALL_VERSIONS(MIDR_QCOM_KRYO_4XX_SILVER),
		{ /* sentinel */ }
	};
	char const *str = "kpti command line option";
	bool meltdown_safe;

	meltdown_safe = is_midr_in_range_list(read_cpuid_id(), kpti_safe_list);

	/* Defer to CPU feature registers */
	if (has_cpuid_feature(entry, scope))
		meltdown_safe = true;

	if (!meltdown_safe)
		__meltdown_safe = false;

	/*
	 * For reasons that aren't entirely clear, enabling KPTI on Cavium
	 * ThunderX leads to apparent I-cache corruption of kernel text, which
	 * ends as well as you might imagine. Don't even try. We cannot rely
	 * on the cpus_have_*cap() helpers here to detect the CPU erratum
	 * because cpucap detection order may change. However, since we know
	 * affected CPUs are always in a homogeneous configuration, it is
	 * safe to rely on this_cpu_has_cap() here.
	 */
	if (this_cpu_has_cap(ARM64_WORKAROUND_CAVIUM_27456)) {
		str = "ARM64_WORKAROUND_CAVIUM_27456";
		__kpti_forced = -1;
	}

	/* Useful for KASLR robustness */
	if (kaslr_requires_kpti()) {
		if (!__kpti_forced) {
			str = "KASLR";
			__kpti_forced = 1;
		}
	}

	if (cpu_mitigations_off() && !__kpti_forced) {
		str = "mitigations=off";
		__kpti_forced = -1;
	}

	if (!IS_ENABLED(CONFIG_UNMAP_KERNEL_AT_EL0)) {
		pr_info_once("kernel page table isolation disabled by kernel configuration\n");
		return false;
	}

	/* Forced? */
	if (__kpti_forced) {
		pr_info_once("kernel page table isolation forced %s by %s\n",
			     __kpti_forced > 0 ? "ON" : "OFF", str);
		return __kpti_forced > 0;
	}

	return !meltdown_safe;
}

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
#define KPTI_NG_TEMP_VA		(-(1UL << PMD_SHIFT))

extern
void create_kpti_ng_temp_pgd(pgd_t *pgdir, phys_addr_t phys, unsigned long virt,
			     phys_addr_t size, pgprot_t prot,
			     phys_addr_t (*pgtable_alloc)(int), int flags);

static phys_addr_t kpti_ng_temp_alloc;

static phys_addr_t kpti_ng_pgd_alloc(int shift)
{
	kpti_ng_temp_alloc -= PAGE_SIZE;
	return kpti_ng_temp_alloc;
}

static void
kpti_install_ng_mappings(const struct arm64_cpu_capabilities *__unused)
{
	typedef void (kpti_remap_fn)(int, int, phys_addr_t, unsigned long);
	extern kpti_remap_fn idmap_kpti_install_ng_mappings;
	kpti_remap_fn *remap_fn;

	int cpu = smp_processor_id();
	int levels = CONFIG_PGTABLE_LEVELS;
	int order = order_base_2(levels);
	u64 kpti_ng_temp_pgd_pa = 0;
	pgd_t *kpti_ng_temp_pgd;
	u64 alloc = 0;

	if (__this_cpu_read(this_cpu_vector) == vectors) {
		const char *v = arm64_get_bp_hardening_vector(EL1_VECTOR_KPTI);

		__this_cpu_write(this_cpu_vector, v);
	}

	/*
	 * We don't need to rewrite the page-tables if either we've done
	 * it already or we have KASLR enabled and therefore have not
	 * created any global mappings at all.
	 */
	if (arm64_use_ng_mappings)
		return;

	remap_fn = (void *)__pa_symbol(idmap_kpti_install_ng_mappings);

	if (!cpu) {
		alloc = __get_free_pages(GFP_ATOMIC | __GFP_ZERO, order);
		kpti_ng_temp_pgd = (pgd_t *)(alloc + (levels - 1) * PAGE_SIZE);
		kpti_ng_temp_alloc = kpti_ng_temp_pgd_pa = __pa(kpti_ng_temp_pgd);

		//
		// Create a minimal page table hierarchy that permits us to map
		// the swapper page tables temporarily as we traverse them.
		//
		// The physical pages are laid out as follows:
		//
		// +--------+-/-------+-/------ +-\\--------+
		// :  PTE[] : | PMD[] : | PUD[] : || PGD[]  :
		// +--------+-\-------+-\------ +-//--------+
		//      ^
		// The first page is mapped into this hierarchy at a PMD_SHIFT
		// aligned virtual address, so that we can manipulate the PTE
		// level entries while the mapping is active. The first entry
		// covers the PTE[] page itself, the remaining entries are free
		// to be used as a ad-hoc fixmap.
		//
		create_kpti_ng_temp_pgd(kpti_ng_temp_pgd, __pa(alloc),
					KPTI_NG_TEMP_VA, PAGE_SIZE, PAGE_KERNEL,
					kpti_ng_pgd_alloc, 0);
	}

	cpu_install_idmap();
	remap_fn(cpu, num_online_cpus(), kpti_ng_temp_pgd_pa, KPTI_NG_TEMP_VA);
	cpu_uninstall_idmap();

	if (!cpu) {
		free_pages(alloc, order);
		arm64_use_ng_mappings = true;
	}
}
#else
static void
kpti_install_ng_mappings(const struct arm64_cpu_capabilities *__unused)
{
}
#endif	/* CONFIG_UNMAP_KERNEL_AT_EL0 */

static int __init parse_kpti(char *str)
{
	bool enabled;
	int ret = kstrtobool(str, &enabled);

	if (ret)
		return ret;

	__kpti_forced = enabled ? 1 : -1;
	return 0;
}
early_param("kpti", parse_kpti);

#ifdef CONFIG_ARM64_HW_AFDBM
static inline void __cpu_enable_hw_dbm(void)
{
	u64 tcr = read_sysreg(tcr_el1) | TCR_HD;

	write_sysreg(tcr, tcr_el1);
	isb();
	local_flush_tlb_all();
}

static bool cpu_has_broken_dbm(void)
{
	/* List of CPUs which have broken DBM support. */
	static const struct midr_range cpus[] = {
#ifdef CONFIG_ARM64_ERRATUM_1024718
		MIDR_ALL_VERSIONS(MIDR_CORTEX_A55),
		/* Kryo4xx Silver (rdpe => r1p0) */
		MIDR_REV(MIDR_QCOM_KRYO_4XX_SILVER, 0xd, 0xe),
#endif
#ifdef CONFIG_ARM64_ERRATUM_2051678
		MIDR_REV_RANGE(MIDR_CORTEX_A510, 0, 0, 2),
#endif
		{},
	};

	return is_midr_in_range_list(read_cpuid_id(), cpus);
}

static bool cpu_can_use_dbm(const struct arm64_cpu_capabilities *cap)
{
	return has_cpuid_feature(cap, SCOPE_LOCAL_CPU) &&
	       !cpu_has_broken_dbm();
}

static void cpu_enable_hw_dbm(struct arm64_cpu_capabilities const *cap)
{
	if (cpu_can_use_dbm(cap))
		__cpu_enable_hw_dbm();
}

static bool has_hw_dbm(const struct arm64_cpu_capabilities *cap,
		       int __unused)
{
	static bool detected = false;
	/*
	 * DBM is a non-conflicting feature. i.e, the kernel can safely
	 * run a mix of CPUs with and without the feature. So, we
	 * unconditionally enable the capability to allow any late CPU
	 * to use the feature. We only enable the control bits on the
	 * CPU, if it actually supports.
	 *
	 * We have to make sure we print the "feature" detection only
	 * when at least one CPU actually uses it. So check if this CPU
	 * can actually use it and print the message exactly once.
	 *
	 * This is safe as all CPUs (including secondary CPUs - due to the
	 * LOCAL_CPU scope - and the hotplugged CPUs - via verification)
	 * goes through the "matches" check exactly once. Also if a CPU
	 * matches the criteria, it is guaranteed that the CPU will turn
	 * the DBM on, as the capability is unconditionally enabled.
	 */
	if (!detected && cpu_can_use_dbm(cap)) {
		detected = true;
		pr_info("detected: Hardware dirty bit management\n");
	}

	return true;
}

#endif

#ifdef CONFIG_ARM64_AMU_EXTN

/*
 * The "amu_cpus" cpumask only signals that the CPU implementation for the
 * flagged CPUs supports the Activity Monitors Unit (AMU) but does not provide
 * information regarding all the events that it supports. When a CPU bit is
 * set in the cpumask, the user of this feature can only rely on the presence
 * of the 4 fixed counters for that CPU. But this does not guarantee that the
 * counters are enabled or access to these counters is enabled by code
 * executed at higher exception levels (firmware).
 */
static struct cpumask amu_cpus __read_mostly;

bool cpu_has_amu_feat(int cpu)
{
	return cpumask_test_cpu(cpu, &amu_cpus);
}

int get_cpu_with_amu_feat(void)
{
	return cpumask_any(&amu_cpus);
}

static void cpu_amu_enable(struct arm64_cpu_capabilities const *cap)
{
	if (has_cpuid_feature(cap, SCOPE_LOCAL_CPU)) {
		pr_info("detected CPU%d: Activity Monitors Unit (AMU)\n",
			smp_processor_id());
		cpumask_set_cpu(smp_processor_id(), &amu_cpus);

		/* 0 reference values signal broken/disabled counters */
		if (!this_cpu_has_cap(ARM64_WORKAROUND_2457168))
			update_freq_counters_refs();
	}
}

static bool has_amu(const struct arm64_cpu_capabilities *cap,
		    int __unused)
{
	/*
	 * The AMU extension is a non-conflicting feature: the kernel can
	 * safely run a mix of CPUs with and without support for the
	 * activity monitors extension. Therefore, unconditionally enable
	 * the capability to allow any late CPU to use the feature.
	 *
	 * With this feature unconditionally enabled, the cpu_enable
	 * function will be called for all CPUs that match the criteria,
	 * including secondary and hotplugged, marking this feature as
	 * present on that respective CPU. The enable function will also
	 * print a detection message.
	 */

	return true;
}
#else
int get_cpu_with_amu_feat(void)
{
	return nr_cpu_ids;
}
#endif

static bool runs_at_el2(const struct arm64_cpu_capabilities *entry, int __unused)
{
	return is_kernel_in_hyp_mode();
}

static void cpu_copy_el2regs(const struct arm64_cpu_capabilities *__unused)
{
	/*
	 * Copy register values that aren't redirected by hardware.
	 *
	 * Before code patching, we only set tpidr_el1, all CPUs need to copy
	 * this value to tpidr_el2 before we patch the code. Once we've done
	 * that, freshly-onlined CPUs will set tpidr_el2, so we don't need to
	 * do anything here.
	 */
	if (!alternative_is_applied(ARM64_HAS_VIRT_HOST_EXTN))
		write_sysreg(read_sysreg(tpidr_el1), tpidr_el2);
}

static bool has_nested_virt_support(const struct arm64_cpu_capabilities *cap,
				    int scope)
{
	if (kvm_get_mode() != KVM_MODE_NV)
		return false;

	if (!has_cpuid_feature(cap, scope)) {
		pr_warn("unavailable: %s\n", cap->desc);
		return false;
	}

	return true;
}

static bool hvhe_possible(const struct arm64_cpu_capabilities *entry,
			  int __unused)
{
	u64 val;

	val = read_sysreg(id_aa64mmfr1_el1);
	if (!cpuid_feature_extract_unsigned_field(val, ID_AA64MMFR1_EL1_VH_SHIFT))
		return false;

	val = arm64_sw_feature_override.val & arm64_sw_feature_override.mask;
	return cpuid_feature_extract_unsigned_field(val, ARM64_SW_FEATURE_OVERRIDE_HVHE);
}

#ifdef CONFIG_ARM64_PAN
static void cpu_enable_pan(const struct arm64_cpu_capabilities *__unused)
{
	/*
	 * We modify PSTATE. This won't work from irq context as the PSTATE
	 * is discarded once we return from the exception.
	 */
	WARN_ON_ONCE(in_interrupt());

	sysreg_clear_set(sctlr_el1, SCTLR_EL1_SPAN, 0);
	set_pstate_pan(1);
}
#endif /* CONFIG_ARM64_PAN */

#ifdef CONFIG_ARM64_RAS_EXTN
static void cpu_clear_disr(const struct arm64_cpu_capabilities *__unused)
{
	/* Firmware may have left a deferred SError in this register. */
	write_sysreg_s(0, SYS_DISR_EL1);
}
#endif /* CONFIG_ARM64_RAS_EXTN */

#ifdef CONFIG_ARM64_PTR_AUTH
static bool has_address_auth_cpucap(const struct arm64_cpu_capabilities *entry, int scope)
{
	int boot_val, sec_val;

	/* We don't expect to be called with SCOPE_SYSTEM */
	WARN_ON(scope == SCOPE_SYSTEM);
	/*
	 * The ptr-auth feature levels are not intercompatible with lower
	 * levels. Hence we must match ptr-auth feature level of the secondary
	 * CPUs with that of the boot CPU. The level of boot cpu is fetched
	 * from the sanitised register whereas direct register read is done for
	 * the secondary CPUs.
	 * The sanitised feature state is guaranteed to match that of the
	 * boot CPU as a mismatched secondary CPU is parked before it gets
	 * a chance to update the state, with the capability.
	 */
	boot_val = cpuid_feature_extract_field(read_sanitised_ftr_reg(entry->sys_reg),
					       entry->field_pos, entry->sign);
	if (scope & SCOPE_BOOT_CPU)
		return boot_val >= entry->min_field_value;
	/* Now check for the secondary CPUs with SCOPE_LOCAL_CPU scope */
	sec_val = cpuid_feature_extract_field(__read_sysreg_by_encoding(entry->sys_reg),
					      entry->field_pos, entry->sign);
	return (sec_val >= entry->min_field_value) && (sec_val == boot_val);
}

static bool has_address_auth_metacap(const struct arm64_cpu_capabilities *entry,
				     int scope)
{
	bool api = has_address_auth_cpucap(cpucap_ptrs[ARM64_HAS_ADDRESS_AUTH_IMP_DEF], scope);
	bool apa = has_address_auth_cpucap(cpucap_ptrs[ARM64_HAS_ADDRESS_AUTH_ARCH_QARMA5], scope);
	bool apa3 = has_address_auth_cpucap(cpucap_ptrs[ARM64_HAS_ADDRESS_AUTH_ARCH_QARMA3], scope);

	return apa || apa3 || api;
}

static bool has_generic_auth(const struct arm64_cpu_capabilities *entry,
			     int __unused)
{
	bool gpi = __system_matches_cap(ARM64_HAS_GENERIC_AUTH_IMP_DEF);
	bool gpa = __system_matches_cap(ARM64_HAS_GENERIC_AUTH_ARCH_QARMA5);
	bool gpa3 = __system_matches_cap(ARM64_HAS_GENERIC_AUTH_ARCH_QARMA3);

	return gpa || gpa3 || gpi;
}
#endif /* CONFIG_ARM64_PTR_AUTH */

#ifdef CONFIG_ARM64_E0PD
static void cpu_enable_e0pd(struct arm64_cpu_capabilities const *cap)
{
	if (this_cpu_has_cap(ARM64_HAS_E0PD))
		sysreg_clear_set(tcr_el1, 0, TCR_E0PD1);
}
#endif /* CONFIG_ARM64_E0PD */

#ifdef CONFIG_ARM64_PSEUDO_NMI
static bool enable_pseudo_nmi;

static int __init early_enable_pseudo_nmi(char *p)
{
	return kstrtobool(p, &enable_pseudo_nmi);
}
early_param("irqchip.gicv3_pseudo_nmi", early_enable_pseudo_nmi);

static bool can_use_gic_priorities(const struct arm64_cpu_capabilities *entry,
				   int scope)
{
	/*
	 * ARM64_HAS_GIC_CPUIF_SYSREGS has a lower index, and is a boot CPU
	 * feature, so will be detected earlier.
	 */
	BUILD_BUG_ON(ARM64_HAS_GIC_PRIO_MASKING <= ARM64_HAS_GIC_CPUIF_SYSREGS);
	if (!cpus_have_cap(ARM64_HAS_GIC_CPUIF_SYSREGS))
		return false;

	return enable_pseudo_nmi;
}

static bool has_gic_prio_relaxed_sync(const struct arm64_cpu_capabilities *entry,
				      int scope)
{
	/*
	 * If we're not using priority masking then we won't be poking PMR_EL1,
	 * and there's no need to relax synchronization of writes to it, and
	 * ICC_CTLR_EL1 might not be accessible and we must avoid reads from
	 * that.
	 *
	 * ARM64_HAS_GIC_PRIO_MASKING has a lower index, and is a boot CPU
	 * feature, so will be detected earlier.
	 */
	BUILD_BUG_ON(ARM64_HAS_GIC_PRIO_RELAXED_SYNC <= ARM64_HAS_GIC_PRIO_MASKING);
	if (!cpus_have_cap(ARM64_HAS_GIC_PRIO_MASKING))
		return false;

	/*
	 * When Priority Mask Hint Enable (PMHE) == 0b0, PMR is not used as a
	 * hint for interrupt distribution, a DSB is not necessary when
	 * unmasking IRQs via PMR, and we can relax the barrier to a NOP.
	 *
	 * Linux itself doesn't use 1:N distribution, so has no need to
	 * set PMHE. The only reason to have it set is if EL3 requires it
	 * (and we can't change it).
	 */
	return (gic_read_ctlr() & ICC_CTLR_EL1_PMHE_MASK) == 0;
}
#endif

#ifdef CONFIG_ARM64_BTI
static void bti_enable(const struct arm64_cpu_capabilities *__unused)
{
	/*
	 * Use of X16/X17 for tail-calls and trampolines that jump to
	 * function entry points using BR is a requirement for
	 * marking binaries with GNU_PROPERTY_AARCH64_FEATURE_1_BTI.
	 * So, be strict and forbid other BRs using other registers to
	 * jump onto a PACIxSP instruction:
	 */
	sysreg_clear_set(sctlr_el1, 0, SCTLR_EL1_BT0 | SCTLR_EL1_BT1);
	isb();
}
#endif /* CONFIG_ARM64_BTI */

#ifdef CONFIG_ARM64_MTE
static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
{
	sysreg_clear_set(sctlr_el1, 0, SCTLR_ELx_ATA | SCTLR_EL1_ATA0);

	mte_cpu_setup();

	/*
	 * Clear the tags in the zero page. This needs to be done via the
	 * linear map which has the Tagged attribute.
	 */
	if (try_page_mte_tagging(ZERO_PAGE(0))) {
		mte_clear_page_tags(lm_alias(empty_zero_page));
		set_page_mte_tagged(ZERO_PAGE(0));
	}

	kasan_init_hw_tags_cpu();
}
#endif /* CONFIG_ARM64_MTE */

static void user_feature_fixup(void)
{
	if (cpus_have_cap(ARM64_WORKAROUND_SPECULATIVE_SSBS)) {
		struct arm64_ftr_reg *regp;

		regp = get_arm64_ftr_reg(SYS_ID_AA64PFR1_EL1);
		if (regp)
			regp->user_mask &= ~ID_AA64PFR1_EL1_SSBS_MASK;
	}
}

static void elf_hwcap_fixup(void)
{
#ifdef CONFIG_ARM64_ERRATUM_1742098
	if (cpus_have_const_cap(ARM64_WORKAROUND_1742098))
		compat_elf_hwcap2 &= ~COMPAT_HWCAP2_AES;
#endif /* ARM64_ERRATUM_1742098 */
}

#ifdef CONFIG_KVM
static bool is_kvm_protected_mode(const struct arm64_cpu_capabilities *entry, int __unused)
{
	return kvm_get_mode() == KVM_MODE_PROTECTED;
}
#endif /* CONFIG_KVM */

static void cpu_trap_el0_impdef(const struct arm64_cpu_capabilities *__unused)
{
	sysreg_clear_set(sctlr_el1, 0, SCTLR_EL1_TIDCP);
}

static void cpu_enable_dit(const struct arm64_cpu_capabilities *__unused)
{
	set_pstate_dit(1);
}

static void cpu_enable_mops(const struct arm64_cpu_capabilities *__unused)
{
	sysreg_clear_set(sctlr_el1, 0, SCTLR_EL1_MSCEn);
}

/* Internal helper functions to match cpu capability type */
static bool
cpucap_late_cpu_optional(const struct arm64_cpu_capabilities *cap)
{
	return !!(cap->type & ARM64_CPUCAP_OPTIONAL_FOR_LATE_CPU);
}

static bool
cpucap_late_cpu_permitted(const struct arm64_cpu_capabilities *cap)
{
	return !!(cap->type & ARM64_CPUCAP_PERMITTED_FOR_LATE_CPU);
}

static bool
cpucap_panic_on_conflict(const struct arm64_cpu_capabilities *cap)
{
	return !!(cap->type & ARM64_CPUCAP_PANIC_ON_CONFLICT);
}

static const struct arm64_cpu_capabilities arm64_features[] = {
	{
		.capability = ARM64_ALWAYS_BOOT,
		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
		.matches = has_always,
	},
	{
		.capability = ARM64_ALWAYS_SYSTEM,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_always,
	},
	{
		.desc = "GIC system register CPU interface",
		.capability = ARM64_HAS_GIC_CPUIF_SYSREGS,
		.type = ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
		.matches = has_useable_gicv3_cpuif,
		ARM64_CPUID_FIELDS(ID_AA64PFR0_EL1, GIC, IMP)
	},
	{
		.desc = "Enhanced Counter Virtualization",
		.capability = ARM64_HAS_ECV,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR0_EL1, ECV, IMP)
	},
	{
		.desc = "Enhanced Counter Virtualization (CNTPOFF)",
		.capability = ARM64_HAS_ECV_CNTPOFF,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR0_EL1, ECV, CNTPOFF)
	},
#ifdef CONFIG_ARM64_PAN
	{
		.desc = "Privileged Access Never",
		.capability = ARM64_HAS_PAN,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		.cpu_enable = cpu_enable_pan,
		ARM64_CPUID_FIELDS(ID_AA64MMFR1_EL1, PAN, IMP)
	},
#endif /* CONFIG_ARM64_PAN */
#ifdef CONFIG_ARM64_EPAN
	{
		.desc = "Enhanced Privileged Access Never",
		.capability = ARM64_HAS_EPAN,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR1_EL1, PAN, PAN3)
	},
#endif /* CONFIG_ARM64_EPAN */
#ifdef CONFIG_ARM64_LSE_ATOMICS
	{
		.desc = "LSE atomic instructions",
		.capability = ARM64_HAS_LSE_ATOMICS,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR0_EL1, ATOMIC, IMP)
	},
#endif /* CONFIG_ARM64_LSE_ATOMICS */
	{
		.desc = "Software prefetching using PRFM",
		.capability = ARM64_HAS_NO_HW_PREFETCH,
		.type = ARM64_CPUCAP_WEAK_LOCAL_CPU_FEATURE,
		.matches = has_no_hw_prefetch,
	},
	{
		.desc = "Virtualization Host Extensions",
		.capability = ARM64_HAS_VIRT_HOST_EXTN,
		.type = ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
		.matches = runs_at_el2,
		.cpu_enable = cpu_copy_el2regs,
	},
	{
		.desc = "Nested Virtualization Support",
		.capability = ARM64_HAS_NESTED_VIRT,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_nested_virt_support,
		ARM64_CPUID_FIELDS(ID_AA64MMFR2_EL1, NV, IMP)
	},
	{
		.capability = ARM64_HAS_32BIT_EL0_DO_NOT_USE,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_32bit_el0,
		ARM64_CPUID_FIELDS(ID_AA64PFR0_EL1, EL0, AARCH32)
	},
#ifdef CONFIG_KVM
	{
		.desc = "32-bit EL1 Support",
		.capability = ARM64_HAS_32BIT_EL1,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64PFR0_EL1, EL1, AARCH32)
	},
	{
		.desc = "Protected KVM",
		.capability = ARM64_KVM_PROTECTED_MODE,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = is_kvm_protected_mode,
	},
	{
		.desc = "HCRX_EL2 register",
		.capability = ARM64_HAS_HCX,
		.type = ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR1_EL1, HCX, IMP)
	},
#endif
	{
		.desc = "Kernel page table isolation (KPTI)",
		.capability = ARM64_UNMAP_KERNEL_AT_EL0,
		.type = ARM64_CPUCAP_BOOT_RESTRICTED_CPU_LOCAL_FEATURE,
		.cpu_enable = kpti_install_ng_mappings,
		.matches = unmap_kernel_at_el0,
		/*
		 * The ID feature fields below are used to indicate that
		 * the CPU doesn't need KPTI. See unmap_kernel_at_el0 for
		 * more details.
		 */
		ARM64_CPUID_FIELDS(ID_AA64PFR0_EL1, CSV3, IMP)
	},
	{
		/* FP/SIMD is not implemented */
		.capability = ARM64_HAS_NO_FPSIMD,
		.type = ARM64_CPUCAP_BOOT_RESTRICTED_CPU_LOCAL_FEATURE,
		.min_field_value = 0,
		.matches = has_no_fpsimd,
	},
#ifdef CONFIG_ARM64_PMEM
	{
		.desc = "Data cache clean to Point of Persistence",
		.capability = ARM64_HAS_DCPOP,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR1_EL1, DPB, IMP)
	},
	{
		.desc = "Data cache clean to Point of Deep Persistence",
		.capability = ARM64_HAS_DCPODP,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR1_EL1, DPB, DPB2)
	},
#endif
#ifdef CONFIG_ARM64_SVE
	{
		.desc = "Scalable Vector Extension",
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.capability = ARM64_SVE,
		.cpu_enable = sve_kernel_enable,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64PFR0_EL1, SVE, IMP)
	},
#endif /* CONFIG_ARM64_SVE */
#ifdef CONFIG_ARM64_RAS_EXTN
	{
		.desc = "RAS Extension Support",
		.capability = ARM64_HAS_RAS_EXTN,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		.cpu_enable = cpu_clear_disr,
		ARM64_CPUID_FIELDS(ID_AA64PFR0_EL1, RAS, IMP)
	},
#endif /* CONFIG_ARM64_RAS_EXTN */
#ifdef CONFIG_ARM64_AMU_EXTN
	{
		/*
		 * The feature is enabled by default if CONFIG_ARM64_AMU_EXTN=y.
		 * Therefore, don't provide .desc as we don't want the detection
		 * message to be shown until at least one CPU is detected to
		 * support the feature.
		 */
		.capability = ARM64_HAS_AMU_EXTN,
		.type = ARM64_CPUCAP_WEAK_LOCAL_CPU_FEATURE,
		.matches = has_amu,
		.cpu_enable = cpu_amu_enable,
		ARM64_CPUID_FIELDS(ID_AA64PFR0_EL1, AMU, IMP)
	},
#endif /* CONFIG_ARM64_AMU_EXTN */
	{
		.desc = "Data cache clean to the PoU not required for I/D coherence",
		.capability = ARM64_HAS_CACHE_IDC,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cache_idc,
		.cpu_enable = cpu_emulate_effective_ctr,
	},
	{
		.desc = "Instruction cache invalidation not required for I/D coherence",
		.capability = ARM64_HAS_CACHE_DIC,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cache_dic,
	},
	{
		.desc = "Stage-2 Force Write-Back",
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.capability = ARM64_HAS_STAGE2_FWB,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR2_EL1, FWB, IMP)
	},
	{
		.desc = "ARMv8.4 Translation Table Level",
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.capability = ARM64_HAS_ARMv8_4_TTL,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR2_EL1, TTL, IMP)
	},
	{
		.desc = "TLB range maintenance instructions",
		.capability = ARM64_HAS_TLB_RANGE,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR0_EL1, TLB, RANGE)
	},
#ifdef CONFIG_ARM64_HW_AFDBM
	{
		/*
		 * Since we turn this on always, we don't want the user to
		 * think that the feature is available when it may not be.
		 * So hide the description.
		 *
		 * .desc = "Hardware pagetable Dirty Bit Management",
		 *
		 */
		.type = ARM64_CPUCAP_WEAK_LOCAL_CPU_FEATURE,
		.capability = ARM64_HW_DBM,
		.matches = has_hw_dbm,
		.cpu_enable = cpu_enable_hw_dbm,
		ARM64_CPUID_FIELDS(ID_AA64MMFR1_EL1, HAFDBS, DBM)
	},
#endif
	{
		.desc = "CRC32 instructions",
		.capability = ARM64_HAS_CRC32,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR0_EL1, CRC32, IMP)
	},
	{
		.desc = "Speculative Store Bypassing Safe (SSBS)",
		.capability = ARM64_SSBS,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, SSBS, IMP)
	},
#ifdef CONFIG_ARM64_CNP
	{
		.desc = "Common not Private translations",
		.capability = ARM64_HAS_CNP,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_useable_cnp,
		.cpu_enable = cpu_enable_cnp,
		ARM64_CPUID_FIELDS(ID_AA64MMFR2_EL1, CnP, IMP)
	},
#endif
	{
		.desc = "Speculation barrier (SB)",
		.capability = ARM64_HAS_SB,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR1_EL1, SB, IMP)
	},
#ifdef CONFIG_ARM64_PTR_AUTH
	{
		.desc = "Address authentication (architected QARMA5 algorithm)",
		.capability = ARM64_HAS_ADDRESS_AUTH_ARCH_QARMA5,
		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
		.matches = has_address_auth_cpucap,
		ARM64_CPUID_FIELDS(ID_AA64ISAR1_EL1, APA, PAuth)
	},
	{
		.desc = "Address authentication (architected QARMA3 algorithm)",
		.capability = ARM64_HAS_ADDRESS_AUTH_ARCH_QARMA3,
		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
		.matches = has_address_auth_cpucap,
		ARM64_CPUID_FIELDS(ID_AA64ISAR2_EL1, APA3, PAuth)
	},
	{
		.desc = "Address authentication (IMP DEF algorithm)",
		.capability = ARM64_HAS_ADDRESS_AUTH_IMP_DEF,
		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
		.matches = has_address_auth_cpucap,
		ARM64_CPUID_FIELDS(ID_AA64ISAR1_EL1, API, PAuth)
	},
	{
		.capability = ARM64_HAS_ADDRESS_AUTH,
		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
		.matches = has_address_auth_metacap,
	},
	{
		.desc = "Generic authentication (architected QARMA5 algorithm)",
		.capability = ARM64_HAS_GENERIC_AUTH_ARCH_QARMA5,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR1_EL1, GPA, IMP)
	},
	{
		.desc = "Generic authentication (architected QARMA3 algorithm)",
		.capability = ARM64_HAS_GENERIC_AUTH_ARCH_QARMA3,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR2_EL1, GPA3, IMP)
	},
	{
		.desc = "Generic authentication (IMP DEF algorithm)",
		.capability = ARM64_HAS_GENERIC_AUTH_IMP_DEF,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR1_EL1, GPI, IMP)
	},
	{
		.capability = ARM64_HAS_GENERIC_AUTH,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_generic_auth,
	},
#endif /* CONFIG_ARM64_PTR_AUTH */
#ifdef CONFIG_ARM64_PSEUDO_NMI
	{
		/*
		 * Depends on having GICv3
		 */
		.desc = "IRQ priority masking",
		.capability = ARM64_HAS_GIC_PRIO_MASKING,
		.type = ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
		.matches = can_use_gic_priorities,
	},
	{
		/*
		 * Depends on ARM64_HAS_GIC_PRIO_MASKING
		 */
		.capability = ARM64_HAS_GIC_PRIO_RELAXED_SYNC,
		.type = ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
		.matches = has_gic_prio_relaxed_sync,
	},
#endif
#ifdef CONFIG_ARM64_E0PD
	{
		.desc = "E0PD",
		.capability = ARM64_HAS_E0PD,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.cpu_enable = cpu_enable_e0pd,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR2_EL1, E0PD, IMP)
	},
#endif
	{
		.desc = "Random Number Generator",
		.capability = ARM64_HAS_RNG,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR0_EL1, RNDR, IMP)
	},
#ifdef CONFIG_ARM64_BTI
	{
		.desc = "Branch Target Identification",
		.capability = ARM64_BTI,
#ifdef CONFIG_ARM64_BTI_KERNEL
		.type = ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
#else
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
#endif
		.matches = has_cpuid_feature,
		.cpu_enable = bti_enable,
		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, BT, IMP)
	},
#endif
#ifdef CONFIG_ARM64_MTE
	{
		.desc = "Memory Tagging Extension",
		.capability = ARM64_MTE,
		.type = ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
		.matches = has_cpuid_feature,
		.cpu_enable = cpu_enable_mte,
		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, MTE, MTE2)
	},
	{
		.desc = "Asymmetric MTE Tag Check Fault",
		.capability = ARM64_MTE_ASYMM,
		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, MTE, MTE3)
	},
#endif /* CONFIG_ARM64_MTE */
	{
		.desc = "RCpc load-acquire (LDAPR)",
		.capability = ARM64_HAS_LDAPR,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR1_EL1, LRCPC, IMP)
	},
	{
		.desc = "Fine Grained Traps",
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.capability = ARM64_HAS_FGT,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR0_EL1, FGT, IMP)
	},
#ifdef CONFIG_ARM64_SME
	{
		.desc = "Scalable Matrix Extension",
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.capability = ARM64_SME,
		.matches = has_cpuid_feature,
		.cpu_enable = sme_kernel_enable,
		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, SME, IMP)
	},
	/* FA64 should be sorted after the base SME capability */
	{
		.desc = "FA64",
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.capability = ARM64_SME_FA64,
		.matches = has_cpuid_feature,
		.cpu_enable = fa64_kernel_enable,
		ARM64_CPUID_FIELDS(ID_AA64SMFR0_EL1, FA64, IMP)
	},
	{
		.desc = "SME2",
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.capability = ARM64_SME2,
		.matches = has_cpuid_feature,
		.cpu_enable = sme2_kernel_enable,
		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, SME, SME2)
	},
#endif /* CONFIG_ARM64_SME */
	{
		.desc = "WFx with timeout",
		.capability = ARM64_HAS_WFXT,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64ISAR2_EL1, WFxT, IMP)
	},
	{
		.desc = "Trap EL0 IMPLEMENTATION DEFINED functionality",
		.capability = ARM64_HAS_TIDCP1,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		.cpu_enable = cpu_trap_el0_impdef,
		ARM64_CPUID_FIELDS(ID_AA64MMFR1_EL1, TIDCP1, IMP)
	},
	{
		.desc = "Data independent timing control (DIT)",
		.capability = ARM64_HAS_DIT,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		.cpu_enable = cpu_enable_dit,
		ARM64_CPUID_FIELDS(ID_AA64PFR0_EL1, DIT, IMP)
	},
	{
		.desc = "Memory Copy and Memory Set instructions",
		.capability = ARM64_HAS_MOPS,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		.cpu_enable = cpu_enable_mops,
		ARM64_CPUID_FIELDS(ID_AA64ISAR2_EL1, MOPS, IMP)
	},
	{
		.capability = ARM64_HAS_TCR2,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR3_EL1, TCRX, IMP)
	},
	{
		.desc = "Stage-1 Permission Indirection Extension (S1PIE)",
		.capability = ARM64_HAS_S1PIE,
		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR3_EL1, S1PIE, IMP)
	},
	{
		.desc = "VHE for hypervisor only",
		.capability = ARM64_KVM_HVHE,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = hvhe_possible,
	},
	{
		.desc = "Enhanced Virtualization Traps",
		.capability = ARM64_HAS_EVT,
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
		.matches = has_cpuid_feature,
		ARM64_CPUID_FIELDS(ID_AA64MMFR2_EL1, EVT, IMP)
	},
	{},
};

#define HWCAP_CPUID_MATCH(reg, field, min_value)			\
		.matches = has_user_cpuid_feature,			\
		ARM64_CPUID_FIELDS(reg, field, min_value)

#define __HWCAP_CAP(name, cap_type, cap)					\
		.desc = name,							\
		.type = ARM64_CPUCAP_SYSTEM_FEATURE,				\
		.hwcap_type = cap_type,						\
		.hwcap = cap,							\

#define HWCAP_CAP(reg, field, min_value, cap_type, cap)		\
	{									\
		__HWCAP_CAP(#cap, cap_type, cap)				\
		HWCAP_CPUID_MATCH(reg, field, min_value) 		\
	}

#define HWCAP_MULTI_CAP(list, cap_type, cap)					\
	{									\
		__HWCAP_CAP(#cap, cap_type, cap)				\
		.matches = cpucap_multi_entry_cap_matches,			\
		.match_list = list,						\
	}

#define HWCAP_CAP_MATCH(match, cap_type, cap)					\
	{									\
		__HWCAP_CAP(#cap, cap_type, cap)				\
		.matches = match,						\
	}

#define HWCAP_CAP_MATCH_ID(match, reg, field, min_value, cap_type, cap)		\
	{									\
		__HWCAP_CAP(#cap, cap_type, cap)				\
		HWCAP_CPUID_MATCH(reg, field, min_value) 			\
		.matches = match,						\
	}

#ifdef CONFIG_ARM64_PTR_AUTH
static const struct arm64_cpu_capabilities ptr_auth_hwcap_addr_matches[] = {
	{
		HWCAP_CPUID_MATCH(ID_AA64ISAR1_EL1, APA, PAuth)
	},
	{
		HWCAP_CPUID_MATCH(ID_AA64ISAR2_EL1, APA3, PAuth)
	},
	{
		HWCAP_CPUID_MATCH(ID_AA64ISAR1_EL1, API, PAuth)
	},
	{},
};

static const struct arm64_cpu_capabilities ptr_auth_hwcap_gen_matches[] = {
	{
		HWCAP_CPUID_MATCH(ID_AA64ISAR1_EL1, GPA, IMP)
	},
	{
		HWCAP_CPUID_MATCH(ID_AA64ISAR2_EL1, GPA3, IMP)
	},
	{
		HWCAP_CPUID_MATCH(ID_AA64ISAR1_EL1, GPI, IMP)
	},
	{},
};
#endif

#ifdef CONFIG_ARM64_SVE
static bool has_sve_feature(const struct arm64_cpu_capabilities *cap, int scope)
{
	return system_supports_sve() && has_user_cpuid_feature(cap, scope);
}
#endif

#ifdef CONFIG_ARM64_SME
static bool has_sme_feature(const struct arm64_cpu_capabilities *cap, int scope)
{
	return system_supports_sme() && has_user_cpuid_feature(cap, scope);
}
#endif

static const struct arm64_cpu_capabilities arm64_elf_hwcaps[] = {
	HWCAP_CAP(ID_AA64ISAR0_EL1, AES, PMULL, CAP_HWCAP, KERNEL_HWCAP_PMULL),
	HWCAP_CAP(ID_AA64ISAR0_EL1, AES, AES, CAP_HWCAP, KERNEL_HWCAP_AES),
	HWCAP_CAP(ID_AA64ISAR0_EL1, SHA1, IMP, CAP_HWCAP, KERNEL_HWCAP_SHA1),
	HWCAP_CAP(ID_AA64ISAR0_EL1, SHA2, SHA256, CAP_HWCAP, KERNEL_HWCAP_SHA2),
	HWCAP_CAP(ID_AA64ISAR0_EL1, SHA2, SHA512, CAP_HWCAP, KERNEL_HWCAP_SHA512),
	HWCAP_CAP(ID_AA64ISAR0_EL1, CRC32, IMP, CAP_HWCAP, KERNEL_HWCAP_CRC32),
	HWCAP_CAP(ID_AA64ISAR0_EL1, ATOMIC, IMP, CAP_HWCAP, KERNEL_HWCAP_ATOMICS),
	HWCAP_CAP(ID_AA64ISAR0_EL1, RDM, IMP, CAP_HWCAP, KERNEL_HWCAP_ASIMDRDM),
	HWCAP_CAP(ID_AA64ISAR0_EL1, SHA3, IMP, CAP_HWCAP, KERNEL_HWCAP_SHA3),
	HWCAP_CAP(ID_AA64ISAR0_EL1, SM3, IMP, CAP_HWCAP, KERNEL_HWCAP_SM3),
	HWCAP_CAP(ID_AA64ISAR0_EL1, SM4, IMP, CAP_HWCAP, KERNEL_HWCAP_SM4),
	HWCAP_CAP(ID_AA64ISAR0_EL1, DP, IMP, CAP_HWCAP, KERNEL_HWCAP_ASIMDDP),
	HWCAP_CAP(ID_AA64ISAR0_EL1, FHM, IMP, CAP_HWCAP, KERNEL_HWCAP_ASIMDFHM),
	HWCAP_CAP(ID_AA64ISAR0_EL1, TS, FLAGM, CAP_HWCAP, KERNEL_HWCAP_FLAGM),
	HWCAP_CAP(ID_AA64ISAR0_EL1, TS, FLAGM2, CAP_HWCAP, KERNEL_HWCAP_FLAGM2),
	HWCAP_CAP(ID_AA64ISAR0_EL1, RNDR, IMP, CAP_HWCAP, KERNEL_HWCAP_RNG),
	HWCAP_CAP(ID_AA64PFR0_EL1, FP, IMP, CAP_HWCAP, KERNEL_HWCAP_FP),
	HWCAP_CAP(ID_AA64PFR0_EL1, FP, FP16, CAP_HWCAP, KERNEL_HWCAP_FPHP),
	HWCAP_CAP(ID_AA64PFR0_EL1, AdvSIMD, IMP, CAP_HWCAP, KERNEL_HWCAP_ASIMD),
	HWCAP_CAP(ID_AA64PFR0_EL1, AdvSIMD, FP16, CAP_HWCAP, KERNEL_HWCAP_ASIMDHP),
	HWCAP_CAP(ID_AA64PFR0_EL1, DIT, IMP, CAP_HWCAP, KERNEL_HWCAP_DIT),
	HWCAP_CAP(ID_AA64ISAR1_EL1, DPB, IMP, CAP_HWCAP, KERNEL_HWCAP_DCPOP),
	HWCAP_CAP(ID_AA64ISAR1_EL1, DPB, DPB2, CAP_HWCAP, KERNEL_HWCAP_DCPODP),
	HWCAP_CAP(ID_AA64ISAR1_EL1, JSCVT, IMP, CAP_HWCAP, KERNEL_HWCAP_JSCVT),
	HWCAP_CAP(ID_AA64ISAR1_EL1, FCMA, IMP, CAP_HWCAP, KERNEL_HWCAP_FCMA),
	HWCAP_CAP(ID_AA64ISAR1_EL1, LRCPC, IMP, CAP_HWCAP, KERNEL_HWCAP_LRCPC),
	HWCAP_CAP(ID_AA64ISAR1_EL1, LRCPC, LRCPC2, CAP_HWCAP, KERNEL_HWCAP_ILRCPC),
	HWCAP_CAP(ID_AA64ISAR1_EL1, FRINTTS, IMP, CAP_HWCAP, KERNEL_HWCAP_FRINT),
	HWCAP_CAP(ID_AA64ISAR1_EL1, SB, IMP, CAP_HWCAP, KERNEL_HWCAP_SB),
	HWCAP_CAP(ID_AA64ISAR1_EL1, BF16, IMP, CAP_HWCAP, KERNEL_HWCAP_BF16),
	HWCAP_CAP(ID_AA64ISAR1_EL1, BF16, EBF16, CAP_HWCAP, KERNEL_HWCAP_EBF16),
	HWCAP_CAP(ID_AA64ISAR1_EL1, DGH, IMP, CAP_HWCAP, KERNEL_HWCAP_DGH),
	HWCAP_CAP(ID_AA64ISAR1_EL1, I8MM, IMP, CAP_HWCAP, KERNEL_HWCAP_I8MM),
	HWCAP_CAP(ID_AA64MMFR2_EL1, AT, IMP, CAP_HWCAP, KERNEL_HWCAP_USCAT),
#ifdef CONFIG_ARM64_SVE
	HWCAP_CAP(ID_AA64PFR0_EL1, SVE, IMP, CAP_HWCAP, KERNEL_HWCAP_SVE),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, SVEver, SVE2p1, CAP_HWCAP, KERNEL_HWCAP_SVE2P1),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, SVEver, SVE2, CAP_HWCAP, KERNEL_HWCAP_SVE2),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, AES, IMP, CAP_HWCAP, KERNEL_HWCAP_SVEAES),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, AES, PMULL128, CAP_HWCAP, KERNEL_HWCAP_SVEPMULL),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, BitPerm, IMP, CAP_HWCAP, KERNEL_HWCAP_SVEBITPERM),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, BF16, IMP, CAP_HWCAP, KERNEL_HWCAP_SVEBF16),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, BF16, EBF16, CAP_HWCAP, KERNEL_HWCAP_SVE_EBF16),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, SHA3, IMP, CAP_HWCAP, KERNEL_HWCAP_SVESHA3),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, SM4, IMP, CAP_HWCAP, KERNEL_HWCAP_SVESM4),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, I8MM, IMP, CAP_HWCAP, KERNEL_HWCAP_SVEI8MM),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, F32MM, IMP, CAP_HWCAP, KERNEL_HWCAP_SVEF32MM),
	HWCAP_CAP_MATCH_ID(has_sve_feature, ID_AA64ZFR0_EL1, F64MM, IMP, CAP_HWCAP, KERNEL_HWCAP_SVEF64MM),
#endif
	HWCAP_CAP(ID_AA64PFR1_EL1, SSBS, SSBS2, CAP_HWCAP, KERNEL_HWCAP_SSBS),
#ifdef CONFIG_ARM64_BTI
	HWCAP_CAP(ID_AA64PFR1_EL1, BT, IMP, CAP_HWCAP, KERNEL_HWCAP_BTI),
#endif
#ifdef CONFIG_ARM64_PTR_AUTH
	HWCAP_MULTI_CAP(ptr_auth_hwcap_addr_matches, CAP_HWCAP, KERNEL_HWCAP_PACA),
	HWCAP_MULTI_CAP(ptr_auth_hwcap_gen_matches, CAP_HWCAP, KERNEL_HWCAP_PACG),
#endif
#ifdef CONFIG_ARM64_MTE
	HWCAP_CAP(ID_AA64PFR1_EL1, MTE, MTE2, CAP_HWCAP, KERNEL_HWCAP_MTE),
	HWCAP_CAP(ID_AA64PFR1_EL1, MTE, MTE3, CAP_HWCAP, KERNEL_HWCAP_MTE3),
#endif /* CONFIG_ARM64_MTE */
	HWCAP_CAP(ID_AA64MMFR0_EL1, ECV, IMP, CAP_HWCAP, KERNEL_HWCAP_ECV),
	HWCAP_CAP(ID_AA64MMFR1_EL1, AFP, IMP, CAP_HWCAP, KERNEL_HWCAP_AFP),
	HWCAP_CAP(ID_AA64ISAR2_EL1, CSSC, IMP, CAP_HWCAP, KERNEL_HWCAP_CSSC),
	HWCAP_CAP(ID_AA64ISAR2_EL1, RPRFM, IMP, CAP_HWCAP, KERNEL_HWCAP_RPRFM),
	HWCAP_CAP(ID_AA64ISAR2_EL1, RPRES, IMP, CAP_HWCAP, KERNEL_HWCAP_RPRES),
	HWCAP_CAP(ID_AA64ISAR2_EL1, WFxT, IMP, CAP_HWCAP, KERNEL_HWCAP_WFXT),
	HWCAP_CAP(ID_AA64ISAR2_EL1, MOPS, IMP, CAP_HWCAP, KERNEL_HWCAP_MOPS),
	HWCAP_CAP(ID_AA64ISAR2_EL1, BC, IMP, CAP_HWCAP, KERNEL_HWCAP_HBC),
#ifdef CONFIG_ARM64_SME
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64PFR1_EL1, SME, IMP, CAP_HWCAP, KERNEL_HWCAP_SME),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, FA64, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_FA64),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, SMEver, SME2p1, CAP_HWCAP, KERNEL_HWCAP_SME2P1),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, SMEver, SME2, CAP_HWCAP, KERNEL_HWCAP_SME2),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, I16I64, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_I16I64),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, F64F64, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_F64F64),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, I16I32, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_I16I32),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, B16B16, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_B16B16),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, F16F16, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_F16F16),
	HWCAP_CAP(ID_MATCH_ID(has_sme_feature, AA64SMFR0_EL1, I8I32, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_I8I32),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, F16F32, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_F16F32),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, B16F32, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_B16F32),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, BI32I32, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_BI32I32),
	HWCAP_CAP_MATCH_ID(has_sme_feature, ID_AA64SMFR0_EL1, F32F32, IMP, CAP_HWCAP, KERNEL_HWCAP_SME_F32F32),
#endif /* CONFIG_ARM64_SME */
	{},
};

#ifdef CONFIG_COMPAT
static bool compat_has_neon(const struct arm64_cpu_capabilities *cap, int scope)
{
	/*
	 * Check that all of MVFR1_EL1.{SIMDSP, SIMDInt, SIMDLS} are available,
	 * in line with that of arm32 as in vfp_init(). We make sure that the
	 * check is future proof, by making sure value is non-zero.
	 */
	u32 mvfr1;

	WARN_ON(scope == SCOPE_LOCAL_CPU && preemptible());
	if (scope == SCOPE_SYSTEM)
		mvfr1 = read_sanitised_ftr_reg(SYS_MVFR1_EL1);
	else
		mvfr1 = read_sysreg_s(SYS_MVFR1_EL1);

	return cpuid_feature_extract_unsigned_field(mvfr1, MVFR1_EL1_SIMDSP_SHIFT) &&
		cpuid_feature_extract_unsigned_field(mvfr1, MVFR1_EL1_SIMDInt_SHIFT) &&
		cpuid_feature_extract_unsigned_field(mvfr1, MVFR1_EL1_SIMDLS_SHIFT);
}
#endif

static const struct arm64_cpu_capabilities compat_elf_hwcaps[] = {
#ifdef CONFIG_COMPAT
	HWCAP_CAP_MATCH(compat_has_neon, CAP_COMPAT_HWCAP, COMPAT_HWCAP_NEON),
	HWCAP_CAP(MVFR1_EL1, SIMDFMAC, IMP, CAP_COMPAT_HWCAP, COMPAT_HWCAP_VFPv4),
	/* Arm v8 mandates MVFR0.FPDP == {0, 2}. So, piggy back on this for the presence of VFP support */
	HWCAP_CAP(MVFR0_EL1, FPDP, VFPv3, CAP_COMPAT_HWCAP, COMPAT_HWCAP_VFP),
	HWCAP_CAP(MVFR0_EL1, FPDP, VFPv3, CAP_COMPAT_HWCAP, COMPAT_HWCAP_VFPv3),
	HWCAP_CAP(MVFR1_EL1, FPHP, FP16, CAP_COMPAT_HWCAP, COMPAT_HWCAP_FPHP),
	HWCAP_CAP(MVFR1_EL1, SIMDHP, SIMDHP_FLOAT, CAP_COMPAT_HWCAP, COMPAT_HWCAP_ASIMDHP),
	HWCAP_CAP(ID_ISAR5_EL1, AES, VMULL, CAP_COMPAT_HWCAP2, COMPAT_HWCAP2_PMULL),
	HWCAP_CAP(ID_ISAR5_EL1, AES, IMP, CAP_COMPAT_HWCAP2, COMPAT_HWCAP2_AES),
	HWCAP_CAP(ID_ISAR5_EL1, SHA1, IMP, CAP_COMPAT_HWCAP2, COMPAT_HWCAP2_SHA1),
	HWCAP_CAP(ID_ISAR5_EL1, SHA2, IMP, CAP_COMPAT_HWCAP2, COMPAT_HWCAP2_SHA2),
	HWCAP_CAP(ID_ISAR5_EL1, CRC32, IMP, CAP_COMPAT_HWCAP2, COMPAT_HWCAP2_CRC32),
	HWCAP_CAP(ID_ISAR6_EL1, DP, IMP, CAP_COMPAT_HWCAP, COMPAT_HWCAP_ASIMDDP),
	HWCAP_CAP(ID_ISAR6_EL1, FHM, IMP, CAP_COMPAT_HWCAP, COMPAT_HWCAP_ASIMDFHM),
	HWCAP_CAP(ID_ISAR6_EL1, SB, IMP, CAP_COMPAT_HWCAP2, COMPAT_HWCAP2_SB),
	HWCAP_CAP(ID_ISAR6_EL1, BF16, IMP, CAP_COMPAT_HWCAP, COMPAT_HWCAP_ASIMDBF16),
	HWCAP_CAP(ID_ISAR6_EL1, I8MM, IMP, CAP_COMPAT_HWCAP, COMPAT_HWCAP_I8MM),
	HWCAP_CAP(ID_PFR2_EL1, SSBS, IMP, CAP_COMPAT_HWCAP2, COMPAT_HWCAP2_SSBS),
#endif
	{},
};

static void cap_set_elf_hwcap(const struct arm64_cpu_capabilities *cap)
{
	switch (cap->hwcap_type) {
	case CAP_HWCAP:
		cpu_set_feature(cap->hwcap);
		break;
#ifdef CONFIG_COMPAT
	case CAP_COMPAT_HWCAP:
		compat_elf_hwcap |= (u32)cap->hwcap;
		break;
	case CAP_COMPAT_HWCAP2:
		compat_elf_hwcap2 |= (u32)cap->hwcap;
		break;
#endif
	default:
		WARN_ON(1);
		break;
	}
}

/* Check if we have a particular HWCAP enabled */
static bool cpus_have_elf_hwcap(const struct arm64_cpu_capabilities *cap)
{
	bool rc;

	switch (cap->hwcap_type) {
	case CAP_HWCAP:
		rc = cpu_have_feature(cap->hwcap);
		break;
#ifdef CONFIG_COMPAT
	case CAP_COMPAT_HWCAP:
		rc = (compat_elf_hwcap & (u32)cap->hwcap) != 0;
		break;
	case CAP_COMPAT_HWCAP2:
		rc = (compat_elf_hwcap2 & (u32)cap->hwcap) != 0;
		break;
#endif
	default:
		WARN_ON(1);
		rc = false;
	}

	return rc;
}

static void setup_elf_hwcaps(const struct arm64_cpu_capabilities *hwcaps)
{
	/* We support emulation of accesses to CPU ID feature registers */
	cpu_set_named_feature(CPUID);
	for (; hwcaps->matches; hwcaps++)
		if (hwcaps->matches(hwcaps, cpucap_default_scope(hwcaps)))
			cap_set_elf_hwcap(hwcaps);
}

static void update_cpu_capabilities(u16 scope_mask)
{
	int i;
	const struct arm64_cpu_capabilities *caps;

	scope_mask &= ARM64_CPUCAP_SCOPE_MASK;
	for (i = 0; i < ARM64_NCAPS; i++) {
		caps = cpucap_ptrs[i];
		if (!caps || !(caps->type & scope_mask) ||
		    cpus_have_cap(caps->capability) ||
		    !caps->matches(caps, cpucap_default_scope(caps)))
			continue;

		if (caps->desc)
			pr_info("detected: %s\n", caps->desc);

		__set_bit(caps->capability, system_cpucaps);

		if ((scope_mask & SCOPE_BOOT_CPU) && (caps->type & SCOPE_BOOT_CPU))
			set_bit(caps->capability, boot_cpucaps);
	}
}

/*
 * Enable all the available capabilities on this CPU. The capabilities
 * with BOOT_CPU scope are handled separately and hence skipped here.
 */
static int cpu_enable_non_boot_scope_capabilities(void *__unused)
{
	int i;
	u16 non_boot_scope = SCOPE_ALL & ~SCOPE_BOOT_CPU;

	for_each_available_cap(i) {
		const struct arm64_cpu_capabilities *cap = cpucap_ptrs[i];

		if (WARN_ON(!cap))
			continue;

		if (!(cap->type & non_boot_scope))
			continue;

		if (cap->cpu_enable)
			cap->cpu_enable(cap);
	}
	return 0;
}

/*
 * Run through the enabled capabilities and enable() it on all active
 * CPUs
 */
static void __init enable_cpu_capabilities(u16 scope_mask)
{
	int i;
	const struct arm64_cpu_capabilities *caps;
	bool boot_scope;

	scope_mask &= ARM64_CPUCAP_SCOPE_MASK;
	boot_scope = !!(scope_mask & SCOPE_BOOT_CPU);

	for (i = 0; i < ARM64_NCAPS; i++) {
		unsigned int num;

		caps = cpucap_ptrs[i];
		if (!caps || !(caps->type & scope_mask))
			continue;
		num = caps->capability;
		if (!cpus_have_cap(num))
			continue;

		if (boot_scope && caps->cpu_enable)
			/*
			 * Capabilities with SCOPE_BOOT_CPU scope are finalised
			 * before any secondary CPU boots. Thus, each secondary
			 * will enable the capability as appropriate via
			 * check_local_cpu_capabilities(). The only exception is
			 * the boot CPU, for which the capability must be
			 * enabled here. This approach avoids costly
			 * stop_machine() calls for this case.
			 */
			caps->cpu_enable(caps);
	}

	/*
	 * For all non-boot scope capabilities, use stop_machine()
	 * as it schedules the work allowing us to modify PSTATE,
	 * instead of on_each_cpu() which uses an IPI, giving us a
	 * PSTATE that disappears when we return.
	 */
	if (!boot_scope)
		stop_machine(cpu_enable_non_boot_scope_capabilities,
			     NULL, cpu_online_mask);
}

/*
 * Run through the list of capabilities to check for conflicts.
 * If the system has already detected a capability, take necessary
 * action on this CPU.
 */
static void verify_local_cpu_caps(u16 scope_mask)
{
	int i;
	bool cpu_has_cap, system_has_cap;
	const struct arm64_cpu_capabilities *caps;

	scope_mask &= ARM64_CPUCAP_SCOPE_MASK;

	for (i = 0; i < ARM64_NCAPS; i++) {
		caps = cpucap_ptrs[i];
		if (!caps || !(caps->type & scope_mask))
			continue;

		cpu_has_cap = caps->matches(caps, SCOPE_LOCAL_CPU);
		system_has_cap = cpus_have_cap(caps->capability);

		if (system_has_cap) {
			/*
			 * Check if the new CPU misses an advertised feature,
			 * which is not safe to miss.
			 */
			if (!cpu_has_cap && !cpucap_late_cpu_optional(caps))
				break;
			/*
			 * We have to issue cpu_enable() irrespective of
			 * whether the CPU has it or not, as it is enabeld
			 * system wide. It is upto the call back to take
			 * appropriate action on this CPU.
			 */
			if (caps->cpu_enable)
				caps->cpu_enable(caps);
		} else {
			/*
			 * Check if the CPU has this capability if it isn't
			 * safe to have when the system doesn't.
			 */
			if (cpu_has_cap && !cpucap_late_cpu_permitted(caps))
				break;
		}
	}

	if (i < ARM64_NCAPS) {
		pr_crit("CPU%d: Detected conflict for capability %d (%s), System: %d, CPU: %d\n",
			smp_processor_id(), caps->capability,
			caps->desc, system_has_cap, cpu_has_cap);

		if (cpucap_panic_on_conflict(caps))
			cpu_panic_kernel();
		else
			cpu_die_early();
	}
}

/*
 * Check for CPU features that are used in early boot
 * based on the Boot CPU value.
 */
static void check_early_cpu_features(void)
{
	verify_cpu_asid_bits();

	verify_local_cpu_caps(SCOPE_BOOT_CPU);
}

static void
__verify_local_elf_hwcaps(const struct arm64_cpu_capabilities *caps)
{

	for (; caps->matches; caps++)
		if (cpus_have_elf_hwcap(caps) && !caps->matches(caps, SCOPE_LOCAL_CPU)) {
			pr_crit("CPU%d: missing HWCAP: %s\n",
					smp_processor_id(), caps->desc);
			cpu_die_early();
		}
}

static void verify_local_elf_hwcaps(void)
{
	__verify_local_elf_hwcaps(arm64_elf_hwcaps);

	if (id_aa64pfr0_32bit_el0(read_cpuid(ID_AA64PFR0_EL1)))
		__verify_local_elf_hwcaps(compat_elf_hwcaps);
}

static void verify_sve_features(void)
{
	u64 safe_zcr = read_sanitised_ftr_reg(SYS_ZCR_EL1);
	u64 zcr = read_zcr_features();

	unsigned int safe_len = safe_zcr & ZCR_ELx_LEN_MASK;
	unsigned int len = zcr & ZCR_ELx_LEN_MASK;

	if (len < safe_len || vec_verify_vq_map(ARM64_VEC_SVE)) {
		pr_crit("CPU%d: SVE: vector length support mismatch\n",
			smp_processor_id());
		cpu_die_early();
	}

	/* Add checks on other ZCR bits here if necessary */
}

static void verify_sme_features(void)
{
	u64 safe_smcr = read_sanitised_ftr_reg(SYS_SMCR_EL1);
	u64 smcr = read_smcr_features();

	unsigned int safe_len = safe_smcr & SMCR_ELx_LEN_MASK;
	unsigned int len = smcr & SMCR_ELx_LEN_MASK;

	if (len < safe_len || vec_verify_vq_map(ARM64_VEC_SME)) {
		pr_crit("CPU%d: SME: vector length support mismatch\n",
			smp_processor_id());
		cpu_die_early();
	}

	/* Add checks on other SMCR bits here if necessary */
}

static void verify_hyp_capabilities(void)
{
	u64 safe_mmfr1, mmfr0, mmfr1;
	int parange, ipa_max;
	unsigned int safe_vmid_bits, vmid_bits;

	if (!IS_ENABLED(CONFIG_KVM))
		return;

	safe_mmfr1 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR1_EL1);
	mmfr0 = read_cpuid(ID_AA64MMFR0_EL1);
	mmfr1 = read_cpuid(ID_AA64MMFR1_EL1);

	/* Verify VMID bits */
	safe_vmid_bits = get_vmid_bits(safe_mmfr1);
	vmid_bits = get_vmid_bits(mmfr1);
	if (vmid_bits < safe_vmid_bits) {
		pr_crit("CPU%d: VMID width mismatch\n", smp_processor_id());
		cpu_die_early();
	}

	/* Verify IPA range */
	parange = cpuid_feature_extract_unsigned_field(mmfr0,
				ID_AA64MMFR0_EL1_PARANGE_SHIFT);
	ipa_max = id_aa64mmfr0_parange_to_phys_shift(parange);
	if (ipa_max < get_kvm_ipa_limit()) {
		pr_crit("CPU%d: IPA range mismatch\n", smp_processor_id());
		cpu_die_early();
	}
}

/*
 * Run through the enabled system capabilities and enable() it on this CPU.
 * The capabilities were decided based on the available CPUs at the boot time.
 * Any new CPU should match the system wide status of the capability. If the
 * new CPU doesn't have a capability which the system now has enabled, we
 * cannot do anything to fix it up and could cause unexpected failures. So
 * we park the CPU.
 */
static void verify_local_cpu_capabilities(void)
{
	/*
	 * The capabilities with SCOPE_BOOT_CPU are checked from
	 * check_early_cpu_features(), as they need to be verified
	 * on all secondary CPUs.
	 */
	verify_local_cpu_caps(SCOPE_ALL & ~SCOPE_BOOT_CPU);
	verify_local_elf_hwcaps();

	if (system_supports_sve())
		verify_sve_features();

	if (system_supports_sme())
		verify_sme_features();

	if (is_hyp_mode_available())
		verify_hyp_capabilities();
}

void check_local_cpu_capabilities(void)
{
	/*
	 * All secondary CPUs should conform to the early CPU features
	 * in use by the kernel based on boot CPU.
	 */
	check_early_cpu_features();

	/*
	 * If we haven't finalised the system capabilities, this CPU gets
	 * a chance to update the errata work arounds and local features.
	 * Otherwise, this CPU should verify that it has all the system
	 * advertised capabilities.
	 */
	if (!system_capabilities_finalized())
		update_cpu_capabilities(SCOPE_LOCAL_CPU);
	else
		verify_local_cpu_capabilities();
}

static void __init setup_boot_cpu_capabilities(void)
{
	/* Detect capabilities with either SCOPE_BOOT_CPU or SCOPE_LOCAL_CPU */
	update_cpu_capabilities(SCOPE_BOOT_CPU | SCOPE_LOCAL_CPU);
	/* Enable the SCOPE_BOOT_CPU capabilities alone right away */
	enable_cpu_capabilities(SCOPE_BOOT_CPU);
}

bool this_cpu_has_cap(unsigned int n)
{
	if (!WARN_ON(preemptible()) && n < ARM64_NCAPS) {
		const struct arm64_cpu_capabilities *cap = cpucap_ptrs[n];

		if (cap)
			return cap->matches(cap, SCOPE_LOCAL_CPU);
	}

	return false;
}
EXPORT_SYMBOL_GPL(this_cpu_has_cap);

/*
 * This helper function is used in a narrow window when,
 * - The system wide safe registers are set with all the SMP CPUs and,
 * - The SYSTEM_FEATURE system_cpucaps may not have been set.
 * In all other cases cpus_have_{const_}cap() should be used.
 */
static bool __maybe_unused __system_matches_cap(unsigned int n)
{
	if (n < ARM64_NCAPS) {
		const struct arm64_cpu_capabilities *cap = cpucap_ptrs[n];

		if (cap)
			return cap->matches(cap, SCOPE_SYSTEM);
	}
	return false;
}

void cpu_set_feature(unsigned int num)
{
	set_bit(num, elf_hwcap);
}

bool cpu_have_feature(unsigned int num)
{
	return test_bit(num, elf_hwcap);
}
EXPORT_SYMBOL_GPL(cpu_have_feature);

unsigned long cpu_get_elf_hwcap(void)
{
	/*
	 * We currently only populate the first 32 bits of AT_HWCAP. Please
	 * note that for userspace compatibility we guarantee that bits 62
	 * and 63 will always be returned as 0.
	 */
	return elf_hwcap[0];
}

unsigned long cpu_get_elf_hwcap2(void)
{
	return elf_hwcap[1];
}

static void __init setup_system_capabilities(void)
{
	/*
	 * We have finalised the system-wide safe feature
	 * registers, finalise the capabilities that depend
	 * on it. Also enable all the available capabilities,
	 * that are not enabled already.
	 */
	update_cpu_capabilities(SCOPE_SYSTEM);
	enable_cpu_capabilities(SCOPE_ALL & ~SCOPE_BOOT_CPU);
}

void __init setup_cpu_features(void)
{
	u32 cwg;

	setup_system_capabilities();
	user_feature_fixup();
	setup_elf_hwcaps(arm64_elf_hwcaps);

	if (system_supports_32bit_el0()) {
		setup_elf_hwcaps(compat_elf_hwcaps);
		elf_hwcap_fixup();
	}

	if (system_uses_ttbr0_pan())
		pr_info("emulated: Privileged Access Never (PAN) using TTBR0_EL1 switching\n");

	sve_setup();
	sme_setup();
	minsigstksz_setup();

	/*
	 * Check for sane CTR_EL0.CWG value.
	 */
	cwg = cache_type_cwg();
	if (!cwg)
		pr_warn("No Cache Writeback Granule information, assuming %d\n",
			ARCH_DMA_MINALIGN);
}

static int enable_mismatched_32bit_el0(unsigned int cpu)
{
	/*
	 * The first 32-bit-capable CPU we detected and so can no longer
	 * be offlined by userspace. -1 indicates we haven't yet onlined
	 * a 32-bit-capable CPU.
	 */
	static int lucky_winner = -1;

	struct cpuinfo_arm64 *info = &per_cpu(cpu_data, cpu);
	bool cpu_32bit = id_aa64pfr0_32bit_el0(info->reg_id_aa64pfr0);

	if (cpu_32bit) {
		cpumask_set_cpu(cpu, cpu_32bit_el0_mask);
		static_branch_enable_cpuslocked(&arm64_mismatched_32bit_el0);
	}

	if (cpumask_test_cpu(0, cpu_32bit_el0_mask) == cpu_32bit)
		return 0;

	if (lucky_winner >= 0)
		return 0;

	/*
	 * We've detected a mismatch. We need to keep one of our CPUs with
	 * 32-bit EL0 online so that is_cpu_allowed() doesn't end up rejecting
	 * every CPU in the system for a 32-bit task.
	 */
	lucky_winner = cpu_32bit ? cpu : cpumask_any_and(cpu_32bit_el0_mask,
							 cpu_active_mask);
	get_cpu_device(lucky_winner)->offline_disabled = true;
	setup_elf_hwcaps(compat_elf_hwcaps);
	elf_hwcap_fixup();
	pr_info("Asymmetric 32-bit EL0 support detected on CPU %u; CPU hot-unplug disabled on CPU %u\n",
		cpu, lucky_winner);
	return 0;
}

static int __init init_32bit_el0_mask(void)
{
	if (!allow_mismatched_32bit_el0)
		return 0;

	if (!zalloc_cpumask_var(&cpu_32bit_el0_mask, GFP_KERNEL))
		return -ENOMEM;

	return cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				 "arm64/mismatched_32bit_el0:online",
				 enable_mismatched_32bit_el0, NULL);
}
subsys_initcall_sync(init_32bit_el0_mask);

static void __maybe_unused cpu_enable_cnp(struct arm64_cpu_capabilities const *cap)
{
	cpu_replace_ttbr1(lm_alias(swapper_pg_dir), idmap_pg_dir);
}

/*
 * We emulate only the following system register space.
 * Op0 = 0x3, CRn = 0x0, Op1 = 0x0, CRm = [0, 2 - 7]
 * See Table C5-6 System instruction encodings for System register accesses,
 * ARMv8 ARM(ARM DDI 0487A.f) for more details.
 */
static inline bool __attribute_const__ is_emulated(u32 id)
{
	return (sys_reg_Op0(id) == 0x3 &&
		sys_reg_CRn(id) == 0x0 &&
		sys_reg_Op1(id) == 0x0 &&
		(sys_reg_CRm(id) == 0 ||
		 ((sys_reg_CRm(id) >= 2) && (sys_reg_CRm(id) <= 7))));
}

/*
 * With CRm == 0, reg should be one of :
 * MIDR_EL1, MPIDR_EL1 or REVIDR_EL1.
 */
static inline int emulate_id_reg(u32 id, u64 *valp)
{
	switch (id) {
	case SYS_MIDR_EL1:
		*valp = read_cpuid_id();
		break;
	case SYS_MPIDR_EL1:
		*valp = SYS_MPIDR_SAFE_VAL;
		break;
	case SYS_REVIDR_EL1:
		/* IMPLEMENTATION DEFINED values are emulated with 0 */
		*valp = 0;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int emulate_sys_reg(u32 id, u64 *valp)
{
	struct arm64_ftr_reg *regp;

	if (!is_emulated(id))
		return -EINVAL;

	if (sys_reg_CRm(id) == 0)
		return emulate_id_reg(id, valp);

	regp = get_arm64_ftr_reg_nowarn(id);
	if (regp)
		*valp = arm64_ftr_reg_user_value(regp);
	else
		/*
		 * The untracked registers are either IMPLEMENTATION DEFINED
		 * (e.g, ID_AFR0_EL1) or reserved RAZ.
		 */
		*valp = 0;
	return 0;
}

int do_emulate_mrs(struct pt_regs *regs, u32 sys_reg, u32 rt)
{
	int rc;
	u64 val;

	rc = emulate_sys_reg(sys_reg, &val);
	if (!rc) {
		pt_regs_write_reg(regs, rt, val);
		arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
	}
	return rc;
}

bool try_emulate_mrs(struct pt_regs *regs, u32 insn)
{
	u32 sys_reg, rt;

	if (compat_user_mode(regs) || !aarch64_insn_is_mrs(insn))
		return false;

	/*
	 * sys_reg values are defined as used in mrs/msr instruction.
	 * shift the imm value to get the encoding.
	 */
	sys_reg = (u32)aarch64_insn_decode_immediate(AARCH64_INSN_IMM_16, insn) << 5;
	rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT, insn);
	return do_emulate_mrs(regs, sys_reg, rt) == 0;
}

enum mitigation_state arm64_get_meltdown_state(void)
{
	if (__meltdown_safe)
		return SPECTRE_UNAFFECTED;

	if (arm64_kernel_unmapped_at_el0())
		return SPECTRE_MITIGATED;

	return SPECTRE_VULNERABLE;
}

ssize_t cpu_show_meltdown(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	switch (arm64_get_meltdown_state()) {
	case SPECTRE_UNAFFECTED:
		return sprintf(buf, "Not affected\n");

	case SPECTRE_MITIGATED:
		return sprintf(buf, "Mitigation: PTI\n");

	default:
		return sprintf(buf, "Vulnerable\n");
	}
}
