/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The /proc/<pid>/maps spoof for the module build. See nm_maps_spoof.c for why
 * it takes two kprobes rather than the single call site the in-tree build gets.
 *
 * Failure to arm is NOT fatal to the module: the engine still redirects paths,
 * it just cannot rewrite the dev/ino pair maps reports. Losing that quietly is
 * the thing to avoid, so both functions log when they cannot.
 */
#ifndef _NM_MAPS_SPOOF_H
#define _NM_MAPS_SPOOF_H

int nm_maps_spoof_init(void);
void nm_maps_spoof_exit(void);

#endif /* _NM_MAPS_SPOOF_H */
