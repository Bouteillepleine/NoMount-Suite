**v1.3.217 — engine v36 (the engine fixes below need a kernel rebuild; the LKM zip carries them)**

- A synthesized parent directory is absent until its metadata exists, instead of briefly
  readable with a name-hash inode number and a block size of 1. On an OP15 that window was
  about 116 microseconds wide and an app that stat'ed the directory inside it saw numbers no
  real directory on the ROM can produce.
- The engine reports a build version that moves when the engine changes, so `nomount check`
  and the WebUI footer can tell a kernel rebuilt with these fixes from one without them. It
  had been reporting the same string either way, which made the line above unverifiable.
- A file whose name carries an invisible character — an emoji variation selector, a zero-width
  joiner — can be opened and stat'ed again by an app on the hide list. Every such path was
  answered "no such file" whether or not a rule named it, so an app could not reach its own
  downloads, and `open()` refused to create a file in a directory it had just written to.
- On a 4.9 or 4.14 kernel the LKM armed none of its five guards and never hid itself. The module
  loaded and reported success; nothing it closes was closed.
- A bind root added to `ghostpaths` is now hidden from `/proc/self/mountinfo` on the LKM build
  too. The rule reached the engine and the mount record stayed visible.
- Synthesized directories report a creation time on a ROM that has one, and answer the same
  ioctls as a real directory. Both separated them from the directories around them.
- The `/proc/<pid>/maps` device and inode spoof holds 512 pending answers instead of 64, and says
  so when it drops one — a dropped answer printed the real device and inode for that mapping.
- On a kernel too old for the path-hiding guards, the log says they are unavailable instead of
  reporting them armed, and the guard count no longer reads as a complete cloak.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
28deb3f465e2b0662e704dfd3c2588b1ff724cc318b2fac3e806aa08b1d1e03d  00_NoMount-Module-v1.3.217.zip
71c9eed9502802f2e374288dfe1ca64a2b7549a110601a35faa13ba4125e4f8b  01_NoMount-Module-LKM-v1.3.217.zip
```
