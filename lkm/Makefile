# Out-of-tree build of the NoMount engine.
#
#   make -C /path/to/kernel M=$PWD modules
#
# The engine lives in ../hookless/src and is included by nomount_lkm.c rather
# than copied, so -I has to reach it for nomount.h.
obj-m += nomount.o
nomount-y := nomount_lkm.o nm_oot.o nm_defer.o nm_maps_spoof.o nm_xattr_guard.o nm_mount_filter.o nm_ghost_probes.o ghost.o nm_pathhide_probes.o nm_hide.o nm_size_probes.o

# pathhide.c is vendored byte-identical from the in-tree tree, which targets
# 5.10 and newer, which is also where pagemap_pte_hole() has the argument list
# nm_ph_hole() calls it with. Below that it is left out and
# nm_pathhide_probes.c compiles to stubs instead - see the note there.
ifeq ($(shell expr $(VERSION) \* 100 + $(PATCHLEVEL) \>= 510),1)
nomount-y += pathhide.o
endif

ccflags-y += -I$(src) -I$(src)/../hookless/src

# NM_OVL_SRC=<kernel source>/fs lets the out-of-tree build find overlayfs/ovl_entry.h, so
# a synthesized overlay directory takes its number from the overlay's own counter as it does
# in tree. CI points it at the DDK image's source for the KMI. Not -I$(srctree)/fs blindly:
# 9e1a53b did that and incremented ofs->last_ino at the BUILD-TIME offset, on kernels the
# .ko was not built for (ko-loader rewrites vermagic), and was reverted. struct ovl_fs is
# private to overlayfs and not KMI-stable, so nomount.c's nm_ovl_layout_ok() now reads the
# live layout back through invariants overlayfs keeps before anything is written, and leaves
# the counter alone when they do not hold. Without NM_OVL_SRC the #warning in nomount.c says
# which placement this build has.
ifneq ($(NM_OVL_SRC),)
ccflags-y += -I$(NM_OVL_SRC)
endif

# make ... NM_DEBUG=1  turns nm_debug()/nm_info() from no_printk into real printk.
# Off by default: these fire per rule, and a mount pass installs hundreds.
#
# What it is for right now: the `inoseed:` and `inoplace:` lines in nm_place_dir_ino()
# and nm_dev_ino_get(). A synthesized directory takes a free number inside its stock
# siblings' range (local gap, then the overlay counter, then the scanned directory band)
# and goes above everything only when none of those applies -- those lines name which
# branch won and which path was scanned to seed it. One boot is enough:
#
#   dmesg | grep -E 'NoMount.*ino(seed|place)'
#
# KERN_DEBUG, so raise the console loglevel or read the buffer rather than the console.
ifeq ($(NM_DEBUG),1)
ccflags-y += -DNOMOUNT_DEBUG
endif

# The engine is in-tree code being built somewhere it was not written for.
# These are the warnings that produces and that are not defects:
#   unused-function        -- vfs_map_meta_override() has no caller in a module
ccflags-y += -Wno-unused-function

# The missing-header #warning above is DELIBERATE and must not be fatal. The DDK
# containers build with -Werror, so it came back as
#   error: "overlayfs/ovl_entry.h not found..." [-Werror,-W#warnings]
# and killed all eight ko jobs of the release pipeline at once. It had never fired there
# before because 9e1a53b added the #warning and -I$(srctree)/fs in one commit, so the
# warning only became reachable when the include was reverted.
#
# -Wno-error=cpp, not -Wno-error=\#warnings: cpp is the GCC spelling and clang takes it
# as a compat alias, while clang's own spelling is REJECTED by gcc ("no option
# -W#warnings"), which would break the gcc half of lkm-build.yml's matrix -- and the #
# would need escaping here besides. -Wcpp covers #warning directives only, so this masks
# nothing else, and it is scoped to this module rather than disabling -Werror wholesale.
# Upside: the warning now reaches the release logs too, so every shipped .ko has a
# build-time record of which placement variant it is.
ccflags-y += -Wno-error=cpp

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
