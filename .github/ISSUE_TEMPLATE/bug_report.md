---
name: Bug report
about: Something the Suite does wrong, or a detection it does not close
labels: bug
---

## What happened

<!-- What you saw, and what you expected instead. -->

## Checks

**Easiest, no PC needed: open the module's WebUI, go to *Checks*, tap
*Copy report* and paste it below.** It is already redacted.

<details><summary>Report (paste here)</summary>

```
```

</details>

If we ask for more: *Checks* → *Developer tools* → *Export* writes a
timestamped `.zip` to `/sdcard/Download`. Attach that zip (GitHub takes files,
not folders). It holds `check.txt`, the mount table and the live rules.
**Anything that names the apps you hide is withheld automatically** when the
destination is shared storage: the hide-list
files, `spoof.conf` and `boot.log` are left out, and `dmesg-nomount.txt` is
replaced by a stub. The bundle's `WITHHELD.txt` lists what it left out. If your report is about boot behaviour we will
probably need `boot.log` too - run `nomount export /data/adb/nomount/report`, copy it off with
`adb exec-out su -c "tar -C /data/adb/nomount/report -cf - ." > report.tar` (never via /sdcard, which apps can read) and share that privately.

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
