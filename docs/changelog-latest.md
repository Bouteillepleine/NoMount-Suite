**v1.3.206 — engine v34 (unchanged)**

- Bundled engine modules ship without `.BTF`; some kernels reject it.
- `ko-loader` output reaches the install log instead of being dropped.
- A self-mount with a runtime target is seen, not just a literal path.
- A self-mount note no longer promises absorb will take it over.
- Install ends on `INSTALLED BUT INACTIVE` when no engine answers and no bundled module loads.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.
