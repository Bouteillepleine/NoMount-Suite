**v1.3.212 — engine v36 (needs a kernel rebuild)**

- Hide a rule from named apps: `nomount vfs add --uid-excluded <pkg,...>`. One entry covers that app under every user.
- `absorb` can do the same for an absorbed APK. Opt in with `/data/adb/nomount/apkscope`.
- A uid-scoped rule leaked to every uid once a permitted one looked it up. Legacy `--uid` too.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
ad5e378ba4cf0a11eba8b2bfcfdb58970c869e450a0c973637a06d1c9390d957  00_NoMount-Module-v1.3.212.zip
e2325130a43a40a2218b138001f2245615b70368e5a502a59a6be46c2271a06c  01_NoMount-Module-LKM-v1.3.212.zip
```
