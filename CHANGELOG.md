# Changelog

## v1.0.2

### Added
- **Cloak (maps/fd)** — WebUI › Tools card to select Xposed/LSPosed packages and hide their APKs from every `/proc/<pid>/maps` and `/proc/<pid>/fd` via the kernel `pathhide` interface. Applied live and re-applied on boot from `/data/adb/nomount/pathhide.conf`. Collapsible list + module scanner.

### Fixed
- **metamount.sh module counter** — `grep -c … || echo 0` doubled the `0`, tripping a per-module arithmetic error in the card-refresh path (non-fatal but noisy).

## v1.0.1

### Fixed
- **False "per-UID inconsistency" on the manager card at boot.** The runtime
  self-consistency canary ran a single probe shortly after `boot_completed`, but
  app UIDs have not all launched and materialised their per-UID injection that
  early, so a transient disagreement stamped a scary "⚠️ per-UID inconsistency"
  on the card every boot even when the steady state was healthy. `service.sh`
  now retries the probe across a settle window (up to 6 × 15 s) and keeps the
  *settled* verdict; only a divergence that persists through the whole window —
  a real d_drop-style regression — reaches the card.

## v2.1.0

First release of the reworked hybrid metamodule.

### Mount
- **Mountless VFS redirection** — direct-path module files load at stock system
  paths via the `/dev/nomount` driver, with zero `/proc/mounts` entries.
- **Hybrid RRO overlay support** — module `**/overlay/*.apk` dirs are mounted as
  a real `overlayfs` (staged on tmpfs, because `/data` f2fs `casefold` is
  rejected by overlayfs as a lowerdir) so Android's `idmap2` / `OverlayManager`
  pipeline can enable them. Without this, RRO overlays stay `STATE_NO_IDMAP` and
  theming (e.g. OxygenCustomizer) breaks. Everything else stays mountless.
- **Self-mounting module blocklist** — skip modules that manage their own path
  redirection (built-in list + `/data/adb/nomount/blocklist`).

### Detection hiding (own footprint)
- Overlay mounts are registered with KernelSU's native umount
  (`kernel_umount` + `umount-config`) so they're `MNT_DETACH`ed inside DenyList
  apps' namespaces.
- `/dev/nomount` is hidden from non-root scanners via SUSFS `sus_path`.
- **Per-app UID isolation** — block specific UIDs so the VFS hook returns
  pristine stock for them.

### Manager & WebUI
- **Per-module manager tags** — each module's description is tagged with how
  it's served (`vfs` / `overlay` / `vfs + overlay`).
- **WebUI** — engine status/toggle, remount, bootloop-guard status + re-arm,
  modules list, active rules viewer, overlay-mounts list, and UID exclusions.

### Safety
- **Bootloop guard** — a boot counter self-disables NoMount after repeated
  failed boots and re-arms once the system boots healthy.
- **Install-time sha256 integrity check** — every bundled file is verified
  against a manifest at install; a corrupt or tampered zip aborts.

### Kernel
- Kernel patches for android12-5.10, android13-5.15, android14-6.1,
  android15-6.6, android16-6.12 (raw GKI + SUSFS-compatible variants). The
  recursion guard uses `current->journal_info` — never `android_oem_data1`,
  which OEMs like OnePlus use for their own per-task pointer (writing to it
  soft-locks the device at boot).
