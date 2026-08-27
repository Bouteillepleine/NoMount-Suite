---
name: Bug report
about: Something the Suite does wrong, or a detection it does not close
labels: bug
---

## What happened

<!-- What you saw, and what you expected instead. -->

## Diagnostics

Run this and attach the folder it names:

```
nomount export
```

It writes a timestamped bundle to `/sdcard/Download`. **The per-app hide list is
redacted automatically** when the destination is shared storage — package names
and appids are withheld. Pass a private path (`nomount export /data/adb/nomount`)
if you are willing to include them and can share the bundle privately.

If the module is not running at all and `export` will not work, paste instead:

```
nomount check
uname -r
```

...and the last 40 lines of `/data/adb/nomount/boot.log`.

## Device

- Model / ROM:
- Android version:
- Kernel (`uname -r`):
- Root manager and version (KernelSU / SukiSU / APatch / Magisk):
- Suite version (`nomount version`):
- Which builder the kernel came from, if you built it:

## Anything already tried

<!-- Reboots, reflashes, disabling other modules. Say if the problem started
     after a specific change — that is usually the fastest route to a cause. -->
