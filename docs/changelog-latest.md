**v1.3.203 — engine v34 (unchanged)**

- `uidconceal`: apps on this list read as idle to the callers already hidden from —
  `getpriority` answers `-ESRCH`, the same as a user owning no task.
- `ghostpaths`: extra cloak entries beside the synced ones — absolute paths, and `@name`
  for abstract sockets, which refuse with `-ECONNREFUSED`.
- Both need a kernel built with the `_ghost` patches; the LKM build cannot carry them.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.
