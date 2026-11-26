# Out-of-tree build of the NoMount engine.
#
#   make -C /path/to/kernel M=$PWD modules
#
# The engine lives in ../hookless/src and is included by nomount_lkm.c rather
# than copied, so -I has to reach it for nomount.h.
obj-m += nomount.o
nomount-y := nomount_lkm.o nm_oot.o nm_defer.o nm_maps_spoof.o nm_xattr_guard.o nm_mount_filter.o nm_ghost_probes.o ghost.o nm_pathhide_probes.o nm_hide.o

# pathhide.c is vendored byte-identical from the in-tree tree, which targets
# 5.10 and newer, which is also where pagemap_pte_hole() has the argument list
# nm_ph_hole() calls it with. Below that it is left out and
# nm_pathhide_probes.c compiles to stubs instead - see the note there.
ifeq ($(shell expr $(VERSION) \* 100 + $(PATCHLEVEL) \>= 510),1)
nomount-y += pathhide.o
endif

ccflags-y += -I$(src) -I$(src)/../hookless/src

# NO -I$(srctree)/fs here, deliberately, and this comment is the reason.
#
# Adding it would let the out-of-tree build find overlayfs/ovl_entry.h and compile
# nm_ovl_reserve_dir_ino(), which closes a real divergence: in tree the engine is copied
# to fs/nomount.c and finds the header, so the 00_ and 01_ zips place directory inodes
# differently on the same device. It was added on 2026-11-21 (9e1a53b) and reverted the
# same evening, because the cure is worse:
#
#   struct ovl_fs *ofs = sb->s_fs_info;
#   c = (u64)atomic_long_inc_return(&ofs->last_ino);
#
# That INCREMENTS a field at whatever byte offset the BUILD-TIME struct ovl_fs layout
# put it. ovl_fs is private to fs/overlayfs/, is not exported, is not KMI-stable, and
# its field order has moved between versions. In tree that is safe -- one tree, one
# layout. Out of tree the .ko is built in a digest-pinned DDK container and then loaded
# onto a device kernel, and ko-loader rewrites vermagic precisely so a different point
# release will load it: if any field moved ahead of last_ino, that increment writes into
# unrelated overlayfs superblock state. A visible placement difference between the two
# zips beats a cross-kernel write into another filesystem's private state.
#
# The divergence stays VISIBLE instead: nomount.c #warning's when the header is missing,
# and nm_place_dir_ino's `inoplace:` debug line carries ovl=%d, so a dmesg capture says
# which build it came from. Closing it properly needs a layout check that does not exist
# -- an exported accessor, or a KMI-stable way to ask overlayfs for its counter.

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
