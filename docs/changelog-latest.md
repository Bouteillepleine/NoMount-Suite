**v1.3.208 — engine v34 (unchanged)**

- `nomount check` from the WebUI could not run the four checks that need an app's uid
  — it crashed once per check instead. It now says why, and runs them through a
  watcher that can.
- A check that measured nothing no longer overwrites one that measured everything.
- The `su` probes use absolute paths, so they work when the caller has no `PATH`.

> `00_NoMount-Module` for a kernel with NoMount built in, `01_NoMount-Module-LKM` for one without.

```
ab2e5823b9d8e5ac0e553e6637241af3758e32cfe45bc277ec1f2ef98a23eab8  00_NoMount-Module-v1.3.208.zip
f311d25f67ace1f18cba517ac8d2e227fc1db829009bbd21e2e83329b5663181  01_NoMount-Module-LKM-v1.3.208.zip
```
