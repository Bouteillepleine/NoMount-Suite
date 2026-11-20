**v1.3.215 — engine v36 (the engine fixes below need a kernel rebuild; the LKM zip carries them)**

- A synthesized directory took an inode number above every number on the mount, so one `find -type d -inum +1000` named the injected directories. Each now takes a free number from inside the range its stock siblings occupy.
- On an overlay mount that number is reserved from overlayfs's own counter, which never issues it again, so a directory added when the range is already dense stays in band too.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
716f78b325fde1f8e9f1614fb1f541180769bb98bce5e473c315e792fa43993f  00_NoMount-Module-v1.3.215.zip
2c25f6556af4bfbce5203f45300ff6c026c6d0663dfbb5fa891fc9072f71aa1f  01_NoMount-Module-LKM-v1.3.215.zip
```
