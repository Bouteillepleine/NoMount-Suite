**v1.3.213 — engine v36 (unchanged)**

- `nm --uid-excluded` takes upstream's `C-D` range again, read as those appids, so Morphe's "NoMount only" installs work. v1.3.212 took only a comma-separated list and refused `1000-1000`.
- `nm rule list` answers, which Morphe uses to spot an existing redirect and clear a stale one.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
caf7d6fd0fbeb02ea2869af2a343b836e8d2312978d7250c078b5145e64f445d  00_NoMount-Module-v1.3.213.zip
8a747426c2f201f43c446198a89c890e61c4ae1686d8793144a9baea58e3b231  01_NoMount-Module-LKM-v1.3.213.zip
```
