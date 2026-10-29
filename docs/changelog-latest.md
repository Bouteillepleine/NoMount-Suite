**v1.3.204 — engine v34 (unchanged)**

- Module-rooted binds no longer appear in any mount table.
- A path carrying a zero-width or ignorable code point is refused for a hidden caller — closes an `Android/data` bypass. The built-in engine needs a kernel rebuild for this one.
- `uidconceal` and `ghostpaths` survive a module update.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.
