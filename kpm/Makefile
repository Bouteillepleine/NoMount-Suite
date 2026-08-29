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
    $(error KERNEL_DIR not set: configured kernel source for the TARGET KMI (<= 6.6))
endif

CC ?= $(TARGET_COMPILE)gcc
LD ?= $(TARGET_COMPILE)ld
NM ?= $(TARGET_COMPILE)nm

ENGINE_DIR := ../hookless/src

KP_INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include \
                   linux/tools/arch/arm64/include
KP_FLAGS := $(foreach d,$(KP_INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(d))

CC_INCLUDE := $(shell $(CC) -print-file-name=include)

K_FLAGS := -nostdinc -isystem $(CC_INCLUDE) -I$(KERNEL_DIR)/include -I$(KERNEL_DIR)/include/uapi \
           -I$(KERNEL_DIR)/include/generated -I$(KERNEL_DIR)/include/generated/uapi \
           -I$(KERNEL_DIR)/arch/arm64/include -I$(KERNEL_DIR)/arch/arm64/include/uapi \
           -I$(KERNEL_DIR)/arch/arm64/include/generated \
           -I$(KERNEL_DIR)/arch/arm64/include/generated/uapi \
           -I$(ENGINE_DIR) \
           -include $(KERNEL_DIR)/include/linux/kconfig.h \
           -D__KERNEL__ -DMODULE -DKBUILD_MODNAME='"nomount"'

COMMON := -O2 -fno-stack-protector -fno-pic -ffreestanding -Wall

all: nomount.kpm

nomount.kpm: nm_kpm_entry.o nm_engine.o
	$(CC) -r -o $@ $^

nm_kpm_entry.o: nm_kpm_entry.c nm_kpm_syms.h
	$(CC) $(COMMON) $(KP_FLAGS) -c -o $@ $<

nm_engine.o: nm_engine.c nm_kpm_shim.h nm_kpm_syms.h $(ENGINE_DIR)/nomount.c $(ENGINE_DIR)/nomount.h
	$(CC) $(COMMON) $(K_FLAGS) -c -o $@ $<

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
	rm -f *.o *.kpm
