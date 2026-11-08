**v1.3.210 — engine v34 (the engine fixes below need a kernel rebuild)**

- `statmount`/`listmount` handed a hide-listed app the module mounts that
  `/proc/<pid>/mountinfo` already hid. Both are filtered now, so the two views agree.
- Every app granted root is concealed automatically, and a conceal entry naming a
  package that is gone is reported instead of sitting there.
- A finding you have accepted stays out of the findings and is named once as a note.
- The engine pins itself once a rule exists, so `rmmod` cannot free a live vtable.
- A virtual parent another uid already owns is refused instead of stolen.
- `nm knobs` reads the live knob state back out of the engine.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
ad48a716e9e7ff0ab102ef2dccf73de5cf3a5c6526e0b476b5f6e8a7e9462664  00_NoMount-Module-v1.3.210.zip
73a96947e8813b8b5dae1837a0733f4f7e7e02975c01a2a724eca3b439617b5d  01_NoMount-Module-LKM-v1.3.210.zip
```
