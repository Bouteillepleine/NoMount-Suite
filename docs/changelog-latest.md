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
b77af5b9a00aa72159d40060996f0a4b9f421313a04c0ca2ab63997d2e402853  00_NoMount-Module-v1.3.210.zip
ec8d42e4a05d848357f3456c2bb9fdf4612c1169e5ddabedbf3a6e486b10a12c  01_NoMount-Module-LKM-v1.3.210.zip
```
