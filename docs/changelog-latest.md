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
bb41e261375ea94c01cd54227c87f080bd588a2e68bca99c4ecaad5858bad200  00_NoMount-Module-v1.3.210.zip
e27c5f4eb5f7afdfd9f840d30de98178623f7a40a2dd75a269b32ff9176d23ba  01_NoMount-Module-LKM-v1.3.210.zip
```
