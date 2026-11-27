**v1.3.219 — engine v36 · 1.36.8 ([engine]: rebuilt kernel or the 01_ zip)**

- [engine] overlay listings end like stock; SEEK_END on taken-over dirs = stat
- [engine] NOWAIT, O_DIRECT, DONTCACHE as stock
- [engine] SEEK_END locks, FIOQSIZE, FIONREAD: the caller's size
- [engine] inherited fds (zygote, providers): stock file for hidden apps
- [engine] hidden chmod/truncate: stock file
- [engine] inotify fhandle on overlay; generation on ext4/f2fs
- [engine] no injection into user-writable dirs; tmpfs dropped
- [engine] no ENOMEM listings during bulk adds
- [LKM] 6.12 loads on GKI again
- [LKM] 6.18 module
- [LKM] kept module survives same-KMI OTAs
- [LKM] overlay dir inodes numbered like stock
- [LKM] size guard: locks, FIOQSIZE, FIONREAD for hidden apps
- [LKM] ghost cloak: held fds answer fstat
- [LKM] load failures logged with the kernel's reason
- [Suite] crash-loop park (system_server x4 before boot)
- [Suite] two quick reboots no longer park
- [Suite] no late passes when the mount pass never ran
- [Suite] read-only OEM overlays counted
- [Suite] safe exports; hidden apps redacted from shared incident logs
- [Suite] ghost row: no false "not fully measured"
- [WebUI] engine offline vs unreachable; declined check falls back
- [WebUI] guard "not armed this boot"; crash-loop chip; last incident kept

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
0fe6a5a201653d7aef90b9deb3fbe867ae9654f5f4bb0633b9d3f047efae3e52  00_NoMount-Module-v1.3.219.zip
aa68cfb0545d09d51e33bbbd88efb121e3f8eb44219eaf5cb266128e1439102a  01_NoMount-Module-LKM-v1.3.219.zip
```
