**v1.3.218 — engine v36 · 1.36.6 ([engine] lines need a rebuilt kernel; the LKM zip carries them)**

- [engine] Replaced files answer FIONREAD with the size the caller reads, and a hidden app's lookup no longer shows them as "(deleted)" in other apps' maps.
- [engine] Directories the engine takes over list, seek and report file flags like stock ones.
- [LKM] Every module now carries symbol versions, so a kernel it was not built for refuses it instead of loading it, and the 6.18 module loads on 6.18 GKI kernels.
- [Suite] A shared-storage export says in WITHHELD.txt what it left out.
- [WebUI] Copied reports no longer name hidden apps.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
5058af56cfeade0e9f8fba5fb3d062bd710dc44ea6ba3458d27b502f2e1c8be8  00_NoMount-Module-v1.3.218.zip
231fa5c11caf36cf98a7512dec2205bad3b688e0621d14f5c4998d59e8be5256  01_NoMount-Module-LKM-v1.3.218.zip
```
