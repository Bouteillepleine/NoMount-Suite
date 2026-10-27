# Out-of-tree build of the NoMount engine.
#
#   make -C /path/to/kernel M=$PWD modules
#
# The engine lives in ../hookless/src and is included by nomount_lkm.c rather
# than copied, so -I has to reach it for nomount.h.
obj-m += nomount.o
nomount-y := nomount_lkm.o nm_oot.o nm_maps_spoof.o nm_xattr_guard.o nm_mount_filter.o nm_ghost_probes.o ghost.o nm_pathhide_probes.o nm_hide.o

# pathhide.c is vendored byte-identical from the in-tree tree, which targets
# 5.10 and newer. On 4.9/4.14/4.19 it does not compile - mmap_read_lock_killable()
# arrived in 5.8 - and editing a vendored file to suit is not on the table, so it
# is left out there and nm_pathhide_probes.c compiles to stubs instead.
ifeq ($(shell expr $(VERSION) \* 100 + $(PATCHLEVEL) \>= 504),1)
nomount-y += pathhide.o
endif

ccflags-y += -I$(src) -I$(src)/../hookless/src

# The engine is in-tree code being built somewhere it was not written for.
# These are the warnings that produces and that are not defects:
#   unused-function        -- vfs_map_meta_override() has no caller in a module
ccflags-y += -Wno-unused-function

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
