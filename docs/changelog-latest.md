**v1.3.207 — engine v34 (the engine fixes below need a kernel rebuild)**

- The LKM's path and stat guards no longer fail open under load: the kretprobes that
  carry them have room for 64 concurrent calls per core, not 8.
- `unbind` restores a SELinux label longer than 256 bytes instead of writing the
  `adb_data_file` default over it.
- The package watcher no longer removes a lock another watcher owns.
- `boot.log` survives a rotation a full `/data` could not write.
- The LKM no longer calls `path_put()` from a kretprobe handler. Dropping the last
  reference there can sleep, and the dentries these two guards fire for are the
  ones `dput()` kills rather than keeps, so it could.
- `/proc/<pid>/maps` and `/proc/<pid>/map_files` are matched by one renderer and
  one rule scan instead of two copies of the same substring test.
- A path carrying any Unicode default-ignorable code point is refused for a hidden
  caller, not just the eight that had been seen in use. The built-in engine needs a
  kernel rebuild for this one.
- The maps spoof parks the answer rather than a pointer to the inode it came from.
- Uninstalling clears the engine's rule table, so it takes effect without a reboot,
  and it keeps `binds.list` when it could not find a binary to unbind with.
- An engine module that loads but whose `nm` probe does not answer says so, instead
  of reporting that no module loads on this kernel.
- The lite zip says it carries no engine module, and names the LKM zip. It bundles
  none by design, so "no bundled module loads on it either" read as a verdict on
  the kernel and sent people to reflash one.
- A netlink socket that was *denied* is told apart from one the kernel does not
  have. `nm` already reported the difference and the installer discarded it, so an
  SELinux denial was answered with "flash a kernel built with CONFIG_NOMOUNT".
- Another metamodule is recognised when its `module.prop` says `metamodule=true`,
  not only `1`. The manager accepts either spelling, so the guard had been blind to
  the one upstream NoMount uses, and two installed at once is silent - whichever
  was flashed last takes the role and the loser's `metamount.sh` is never called.
- Installing no longer deletes the bundled engine modules. It decided they were
  surplus from `lsmod` showing nothing, which is also what a loaded-and-hidden
  module shows.
- The engine module is loaded on the metamodule path too, so its ordering against
  `post-fs-data.sh` no longer decides whether the first boot serves anything.
- The LKM symbol gate reads the module instead of the modpost log, which stops
  after ten warnings - it had been checking ten symbols of a hundred and more.
- The LKM resolves `kallsyms_lookup_name` by kprobe on every kernel. Below 5.7 it
  took the address directly, which android-4.19-stable does not export at all - so
  that build could never have linked there. Found by the gate above.
- Neither build writes the module's name to the kernel log any more. The LKM's
  guards printed their "armed" lines a moment before unlinking the module from
  `/proc/modules`, and the Suite's own boot logging went to `/dev/kmsg` on every
  boot of both builds. `boot.log` carries the same lines; `touch
  /data/adb/nomount/kmsg` puts them back in dmesg, and `hide=0` restores the
  kernel-side ones.
- The subtree scan that places an injected inode can be preempted, instead of
  walking up to 8192 directories without yielding. The built-in engine needs a
  kernel rebuild for this one.
- The engine declares its write on the mount it writes to. Nothing changes on a
  read-only stock mount, which is every rule today. The built-in engine needs a
  kernel rebuild for this one.
- Releases publish `SHA256SUMS`. The install log says the payload is intact rather
  than unmodified, because the manifest ships inside the zip it checks.
- `hookless/README.md` names what the four integration hunks cover and what they
  do not.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
569231a34f178e907dfa3877208360ee28cc9ff672a7c3e0591b8115965ba1bf  00_NoMount-Module-v1.3.207.zip
eb7ead27cf4de0633e4d71896ca9af6d9c009e9c77041ae7113a2cb7d7b5a4b6  01_NoMount-Module-LKM-v1.3.207.zip
```
