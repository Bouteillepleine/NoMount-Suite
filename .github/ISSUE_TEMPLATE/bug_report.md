---
name: Bug report
about: Something the Suite does wrong, or a detection it does not close
labels: bug
---

## What happened

<!-- What you saw, and what you expected instead. -->

## Diagnostics

**Easiest, no PC needed: open the module's WebUI, go to *Check* → *Developer
tools* → *Export*.** Attach the folder it names.

It writes a timestamped bundle to `/sdcard/Download`, already containing
`boot.log`, `check.txt` and the mount table. **The per-app hide list is redacted
automatically** when the destination is shared storage — package names and
appids are withheld. Export to a private path instead if you are willing to
include them and can share the bundle privately.

From a root shell instead — note `nomount` is **not on `PATH`**, it ships inside
the module:

```
/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount export
```

If the module is not running at all and `export` will not work, paste instead:

```
/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount check
uname -r
```

...and the last 40 lines of `/data/adb/nomount/boot.log`.

## Device

- Model / ROM:
- Android version:
- Kernel (`uname -r`):
- Root manager and version (KernelSU / SukiSU / APatch / Magisk):
- Suite version (the WebUI footer, or `... /nomount version`):
- Which builder the kernel came from, if you built it:

## Anything already tried

<!-- Reboots, reflashes, disabling other modules. Say if the problem started
     after a specific change — that is usually the fastest route to a cause. -->
