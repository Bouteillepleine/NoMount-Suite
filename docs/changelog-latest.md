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
e24d4a35b37a90029fcf4c1b63c596051d2db5512d8cbf1d1b0f84c517ed6094  00_NoMount-Module-v1.3.210.zip
94099f50b8ad9314e6f2d8f421a206042d0937e738c0e79e73b78c92f3070335  01_NoMount-Module-LKM-v1.3.210.zip
```
