**v1.3.217 — engine v36 (the engine fixes below need a kernel rebuild; the LKM zip carries them)**

- Emoji and zero-width filenames work again for hidden apps.
- Synthesized directories no longer flash a wrong inode and block size while being built.
- They now report a creation time and answer ioctls, like real ones.
- The engine's build version moves when the engine does, so a rebuilt kernel is identifiable.
- The LKM arms its guards and hides itself on 4.9 and 4.14; it did neither.
- A `ghostpaths` bind root is hidden from mountinfo on the LKM too.
- The maps dev/ino spoof holds 512 pending answers instead of 64, and says when it drops one.
- Below 5.10 the path-hiding guards report unavailable, not armed.
