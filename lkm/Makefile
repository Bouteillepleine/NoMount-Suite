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

# make ... NM_DEBUG=1  turns nm_debug()/nm_info() from no_printk into real printk.
# Off by default: these fire per rule, and a mount pass installs hundreds.
#
# What it is for right now: the `inoseed:` and `inoplace:` lines in nm_place_dir_ino()
# and nm_dev_ino_get(). A synthesized directory is placed one above the highest number
# in play, and on an OP15 that came out nineteen times above the victim partition's own
# ceiling -- those lines name which of the four inputs produced it, and which path was
# scanned to seed it. One boot is enough:
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

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
