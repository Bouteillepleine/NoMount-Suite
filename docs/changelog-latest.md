**v1.3.210 — engine v34 (the engine fixes below need a kernel rebuild)**

- `statmount`/`listmount` handed a hide-listed app the module mounts that
  `/proc/<pid>/mountinfo` already hid. Both are filtered now, so the two views agree.
- Every app granted root is concealed automatically, and a conceal entry naming a
  package that is gone is reported instead of sitting there.
- A finding you have accepted stays out of the findings and is named once as a note.
- The engine pins itself once a rule exists, so `rmmod` cannot free a live vtable.
- A virtual parent another uid already owns is refused instead of stolen.
- `nm knobs` reads the live knob state back out of the engine.
- `nomount check` no longer calls a check unmeasured when it looked and there was
  nothing yet to look at.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
5535c6289176475d7874ee126d680184a1496f3ce122e16c39508b4ed37ad772  00_NoMount-Module-v1.3.210.zip
b7d1910bf0ec31cbd40a79c33a845ebec2177b1ddfd04f1e9f8838dfdc1c7a96  01_NoMount-Module-LKM-v1.3.210.zip
```
