# SPDX-License-Identifier: GPL-2.0

# List of files in the vdso, has to be asm only for now

# Include the generic Makefile to check the built vdso.
include $(srctree)/lib/vdso/Makefile

obj-vdso32 = sigtramp32-32.o gettimeofday-32.o datapage-32.o cacheflush-32.o note-32.o getcpu-32.o
obj-vdso64 = sigtramp64-64.o gettimeofday-64.o datapage-64.o cacheflush-64.o note-64.o getcpu-64.o

ifneq ($(c-gettimeofday-y),)
  CFLAGS_vgettimeofday-32.o += -include $(c-gettimeofday-y)
# Go prior to 1.16.x assumes r30 is not clobbered by any VDSO code. That used to be true
# by accident when the VDSO was hand-written asm code, but may not be now that the VDSO is
# compiler generated. To avoid breaking Go tell GCC not to use r30. Impact on code
# generation is minimal, it will just use r29 instead.
  CFLAGS_vgettimeofday-64.o += -include $(c-gettimeofday-y) $(call cc-option, -ffixed-r30)
endif

# Build rules

ifdef CROSS32_COMPILE
    VDSOCC := $(CROSS32_COMPILE)gcc
else
    VDSOCC := $(CC)
endif

targets := $(obj-vdso32) vdso32.so.dbg vgettimeofday-32.o
obj-vdso32 := $(addprefix $(obj)/, $(obj-vdso32))
targets += $(obj-vdso64) vdso64.so.dbg vgettimeofday-64.o
obj-vdso64 := $(addprefix $(obj)/, $(obj-vdso64))

GCOV_PROFILE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n
KASAN_SANITIZE := n
KCSAN_SANITIZE := n

ccflags-y := -fno-common -fno-builtin
ccflags-y += $(DISABLE_LATENT_ENTROPY_PLUGIN)
ccflags-y += $(call cc-option, -fno-stack-protector)
ccflags-y += -DDISABLE_BRANCH_PROFILING
ccflags-y += -ffreestanding -fasynchronous-unwind-tables
ccflags-remove-y := $(CC_FLAGS_FTRACE)
ldflags-y := -Wl,--hash-style=both -nostdlib -shared -z noexecstack $(CLANG_FLAGS)
ldflags-$(CONFIG_LD_IS_LLD) += $(call cc-option,--ld-path=$(LD),-fuse-ld=lld)
ldflags-$(CONFIG_LD_ORPHAN_WARN) += -Wl,--orphan-handling=$(CONFIG_LD_ORPHAN_WARN_LEVEL)

# Filter flags that clang will warn are unused for linking
ldflags-y += $(filter-out $(CC_AUTO_VAR_INIT_ZERO_ENABLER) $(CC_FLAGS_FTRACE) -Wa$(comma)%, $(KBUILD_CFLAGS))

CC32FLAGS := -m32
CC32FLAGSREMOVE := -mcmodel=medium -mabi=elfv1 -mabi=elfv2 -mcall-aixdesc -mpcrel
ifdef CONFIG_CC_IS_CLANG
# This flag is supported by clang for 64-bit but not 32-bit so it will cause
# an unused command line flag warning for this file.
CC32FLAGSREMOVE += -fno-stack-clash-protection
# -mstack-protector-guard values from the 64-bit build are not valid for the
# 32-bit one. clang validates the values passed to these arguments during
# parsing, even when -fno-stack-protector is passed afterwards.
CC32FLAGSREMOVE += -mstack-protector-guard%
endif
LD32FLAGS := -Wl,-soname=linux-vdso32.so.1
AS32FLAGS := -D__VDSO32__

LD64FLAGS := -Wl,-soname=linux-vdso64.so.1
AS64FLAGS := -D__VDSO64__

targets += vdso32.lds
CPPFLAGS_vdso32.lds += -P -C -Upowerpc
targets += vdso64.lds
CPPFLAGS_vdso64.lds += -P -C -U$(ARCH)

# link rule for the .so file, .lds has to be first
$(obj)/vdso32.so.dbg: $(src)/vdso32.lds $(obj-vdso32) $(obj)/vgettimeofday-32.o FORCE
	$(call if_changed,vdso32ld_and_check)
$(obj)/vdso64.so.dbg: $(src)/vdso64.lds $(obj-vdso64) $(obj)/vgettimeofday-64.o FORCE
	$(call if_changed,vdso64ld_and_check)

# assembly rules for the .S files
$(obj-vdso32): %-32.o: %.S FORCE
	$(call if_changed_dep,vdso32as)
$(obj)/vgettimeofday-32.o: %-32.o: %.c FORCE
	$(call if_changed_dep,vdso32cc)
$(obj-vdso64): %-64.o: %.S FORCE
	$(call if_changed_dep,vdso64as)
$(obj)/vgettimeofday-64.o: %-64.o: %.c FORCE
	$(call if_changed_dep,cc_o_c)

# Generate VDSO offsets using helper script
gen-vdso32sym := $(srctree)/$(src)/gen_vdso32_offsets.sh
quiet_cmd_vdso32sym = VDSO32SYM $@
      cmd_vdso32sym = $(NM) $< | $(gen-vdso32sym) | LC_ALL=C sort > $@
gen-vdso64sym := $(srctree)/$(src)/gen_vdso64_offsets.sh
quiet_cmd_vdso64sym = VDSO64SYM $@
      cmd_vdso64sym = $(NM) $< | $(gen-vdso64sym) | LC_ALL=C sort > $@

include/generated/vdso32-offsets.h: $(obj)/vdso32.so.dbg FORCE
	$(call if_changed,vdso32sym)
include/generated/vdso64-offsets.h: $(obj)/vdso64.so.dbg FORCE
	$(call if_changed,vdso64sym)

# actual build commands
quiet_cmd_vdso32ld_and_check = VDSO32L $@
      cmd_vdso32ld_and_check = $(VDSOCC) $(ldflags-y) $(CC32FLAGS) $(LD32FLAGS) -o $@ -Wl,-T$(filter %.lds,$^) $(filter %.o,$^); $(cmd_vdso_check)
quiet_cmd_vdso32as = VDSO32A $@
      cmd_vdso32as = $(VDSOCC) $(a_flags) $(CC32FLAGS) $(AS32FLAGS) -c -o $@ $<
quiet_cmd_vdso32cc = VDSO32C $@
      cmd_vdso32cc = $(VDSOCC) $(filter-out $(CC32FLAGSREMOVE), $(c_flags)) $(CC32FLAGS) -c -o $@ $<

quiet_cmd_vdso64ld_and_check = VDSO64L $@
      cmd_vdso64ld_and_check = $(VDSOCC) $(ldflags-y) $(LD64FLAGS) -o $@ -Wl,-T$(filter %.lds,$^) $(filter %.o,$^); $(cmd_vdso_check)
quiet_cmd_vdso64as = VDSO64A $@
      cmd_vdso64as = $(VDSOCC) $(a_flags) $(AS64FLAGS) -c -o $@ $<

OBJECT_FILES_NON_STANDARD := y
