# 🫥 NoMount Suite — KPM branch

This branch builds the Prism engine as a **KernelPatch module**
(`nomount-<kmi>.kpm`) for APatch / KernelPatch, for a kernel you can't rebuild.
Unlike the LKM it does not appear in `/proc/modules`.

- **Kernels 5.4 to 6.6 only.** KernelPatch doesn't come up on 6.12+, so the
  OnePlus 15 and the android16-6.12 line can't use it.
- **Never loaded on hardware.** It builds for every supported KMI, and that is
  all CI proves.
- **Not in the releases.** Build it from Actions with
  *NoMount KPM - build a KernelPatch module*.
- **Tracks `main`.** It wraps the same engine, `1.34.5`; `git merge main` refreshes it.

How it loads and what it costs: [`kpm/README.md`](kpm/README.md). Install,
commands and everything else: the [main README](../../tree/main#readme).

GPL-3.0, see [LICENSE](LICENSE).
