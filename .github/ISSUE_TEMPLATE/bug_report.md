---
name: Bug report
about: Something the Suite does wrong, or a detection it does not close
labels: bug
---

## What happened

<!-- What you saw, and what you expected instead. -->

## Diagnostics

**Easiest, no PC needed: open the module's WebUI, go to *Diagnostics* →
*Developer tools* → *Export*.** Attach the folder it names.

It writes a timestamped bundle to `/sdcard/Download` containing `check.txt`,
the mount table, the live rules and `dmesg-nomount.txt`. **Anything that names
the apps you hide is withheld automatically** when the destination is shared
storage: the hide-list files, `spoof.conf` and `boot.log` are left out, and the
bundle lists what it withheld. If your report is about boot behaviour we will
probably need `boot.log` too - export to a private path instead
(`nomount export /data/local/tmp/nm-report`) and share that bundle privately.

From a root shell instead - note `nomount` is **not on `PATH`**, it ships inside
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
     after a specific change - that is usually the fastest route to a cause. -->
