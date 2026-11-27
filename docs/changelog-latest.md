**v1.3.218 — engine v36 · 1.36.6 ([engine] lines need a rebuilt kernel; the LKM zip carries them except FIONREAD)**

- [LKM] ⚠ The 6.12 and 6.18 modules in this release load on no GKI kernel: their symbol versions match no 6.12 or 6.18 kernel. Use v1.3.219.
- [engine] Replaced files answer FIONREAD with the size the caller reads (built-in kernels only), and a hidden app's lookup no longer shows them as "(deleted)" in other apps' maps.
- [engine] Directories the engine takes over list and report file flags like stock ones.
- [engine] Fixed a kernel oops an app could reach by reading fdinfo on /product overlays.
- [LKM] No longer panics the kernel when it loads on 5.10 and 5.15 GKI (since v1.3.207), or on rmmod of a hide=0 build. The 6.1 and 6.6 modules now carry symbol versions, as the 5.10 and 5.15 ones did.
- [Suite] The bootloop guard now parks the Suite when loading the engine module panics the phone.
- [Suite] An app with a DenyList profile is no longer concealed from itself (getpriority on its own uid answered ESRCH).
- [Suite] A shared-storage export says in WITHHELD.txt what it left out.
- [WebUI] Copied reports no longer name hidden apps.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
5058af56cfeade0e9f8fba5fb3d062bd710dc44ea6ba3458d27b502f2e1c8be8  00_NoMount-Module-v1.3.218.zip
231fa5c11caf36cf98a7512dec2205bad3b688e0621d14f5c4998d59e8be5256  01_NoMount-Module-LKM-v1.3.218.zip
```
