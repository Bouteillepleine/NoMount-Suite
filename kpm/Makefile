# NoMount as a KernelPatch module.
#
# Two translation units compiled against two DIFFERENT include worlds, then
# combined with a relocatable link. This is not an accident of the old port; it
# is forced by what each object has to be:
#
#   nm_kpm_entry.o  KernelPatch SDK headers (KP_FLAGS). It speaks KPM_NAME,
#                   kallsyms lookups and the module entry/exit contract. It must
#                   NOT see kernel headers -- the SDK defines its own ktypes.
#
#   nm_engine.o     Real kernel headers for the TARGET KMI (K_FLAGS). The engine
#                   dereferences struct inode, dentry and super_block, so their
#                   layouts have to be the target kernel's actual ones. It must
#                   NOT see the SDK headers, which describe a different world.
#
# `$(CC) -r` merges them into one relocatable ELF, which is what a .kpm is.
#
# The engine source is INCLUDED by nm_engine.c, never copied: ../hookless/src is
# the single copy in this repository, shared with the in-tree build and the LKM
# variant, so this port cannot silently drift from what the Suite ships.

ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set, e.g. aarch64-linux-android- or aarch64-linux-gnu-)
endif
ifndef KP_DIR
    $(error KP_DIR not set: checkout of KernelPatch / KPatch-Next-EXP)
endif
ifndef KERNEL_DIR
    $(error KERNEL_DIR not set: the configured/built kernel tree for the TARGET KMI (<= 6.6))
endif


# ':=' and not '?=' -- make PREDEFINES CC as 'cc', so '?=' never fires and the
# whole build silently ran through the host x86 compiler against arm64 kernel
# headers. That surfaces as "unsupported size for integer register" from the
# assembler rather than as anything mentioning the wrong compiler. The old port's
# Makefile carried the same latent bug. A command-line CC= still wins over this.
CC := $(TARGET_COMPILE)gcc
LD := $(TARGET_COMPILE)ld
NM := $(TARGET_COMPILE)nm

ENGINE_DIR := ../hookless/src

KP_INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include \
                   linux/tools/arch/arm64/include
KP_FLAGS := $(foreach d,$(KP_INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(d))

CC_INCLUDE := $(shell $(CC) -print-file-name=include)

COMMON := -O2 -fno-stack-protector -fno-pic -ffreestanding -Wall

all: nomount.kpm

nomount.kpm: nm_kpm_entry.o nm_engine.o nm_kpm_tramp.o
	$(CC) -r -o $@ $^

nm_kpm_entry.o: nm_kpm_entry.c nm_kpm_syms.h nm_kpm_table.h
	$(CC) $(COMMON) $(KP_FLAGS) -c -o $@ $<

# The trampolines. Compiled with no kernel headers at all -- the file uses only
# the shared enum, which is the whole point of doing this in asm rather than as
# typed C wrappers.
nm_kpm_tramp.o: nm_kpm_tramp.c nm_kpm_syms.h
	$(CC) $(COMMON) -c -o $@ $<

# Built by kbuild, against the target kernel, with that kernel's own flags.
# See kpm/Kbuild for why this is not a direct compiler invocation.
#
# `M=$(CURDIR)` makes kpm/ an external module directory; kbuild reads Kbuild
# there in preference to this Makefile, so the two do not collide. Only the
# object is wanted -- no modpost, no .ko -- which is why the target is the .o
# and not `modules`.
nm_engine.o: nm_engine.c nm_kpm_shim.h nm_kpm_syms.h Kbuild \
             $(ENGINE_DIR)/nomount.c $(ENGINE_DIR)/nomount.h
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) ARCH=arm64 \
		CROSS_COMPILE=$(TARGET_COMPILE) $@

# THE redirect list, and the reason this target exists.
#
# A .kpm is not loaded by the kernel's module loader, so it gets no relocation
# against the export table: EVERY external symbol has to be resolved through
# kallsyms at load time, exported or not. `nm -u` over the compiled engine is the
# exact and complete answer.
#
# Do not substitute modpost for this. modpost caps its output ("suppressed 90
# unresolved symbol warnings"), so scraping its log under-reports the list and
# silently produces a module that resolves most of what it needs and faults on
# the rest.
.PHONY: undefined
undefined: nm_engine.o
	@$(NM) -u $< | awk '{print $$2}' | sort -u

.PHONY: clean
clean:
	rm -f *.o *.kpm .*.cmd Module.symvers modules.order
	rm -rf .tmp_versions
