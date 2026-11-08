**v1.3.210 — engine v34 (needs a kernel rebuild)**

- statmount/listmount leak closed
- root-granted apps concealed automatically
- accepted findings kept out of the report
- module pinned while rules are live
- `nm knobs` reads the live knob state

> `00_` for a kernel with NoMount built in, `01_` LKM for one without.

```
4ae0e3b8e723b03a84b457e59072411bac13650e9786cac92a5fba8aad1e2f41  00_NoMount-Module-v1.3.210.zip
4c2c43b2752813240cb45edeb381dd50659f4ef7eeb3b2b8df68121c033ce037  01_NoMount-Module-LKM-v1.3.210.zip
```
