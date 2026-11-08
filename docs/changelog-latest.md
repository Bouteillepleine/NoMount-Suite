**v1.3.210 — engine v34 (needs a kernel rebuild)**

- statmount/listmount leak closed
- root-granted apps concealed automatically
- accepted findings kept out of the report
- module pinned while rules are live
- `nm knobs` reads the live knob state

> `00_` for a kernel with NoMount built in, `01_` LKM for one without.

```
be868bf6f798b7aa71fd0d77f8504966944f809ed2efcae009fc5ed9e106b44c  00_NoMount-Module-v1.3.210.zip
3850557a5ae733f5a5cbbb504eeef44418f20bdc595f996b2369b5a3c281dbef  01_NoMount-Module-LKM-v1.3.210.zip
```
