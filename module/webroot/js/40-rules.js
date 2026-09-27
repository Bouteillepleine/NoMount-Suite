  "use strict";

  async function refreshModules() {
    const box = $("modules");
    const r = (await exec(
      'for d in /data/adb/modules/*/; do [ -d "$d" ] || continue; ' +
      'id=$(basename "$d"); ' +
      'mnt=$(NM_P="/adb/modules/$id" awk \'$4==ENVIRON["NM_P"] || index($4, ENVIRON["NM_P"] "/")==1 {n++} END{print n+0}\' /proc/self/mountinfo 2>/dev/null); ' +
      '[ "$id" = meta-nomount ] && { echo "$id|suite|$mnt"; continue; }; ' +
      '[ "$id" = kernelnosu ] && { echo "$id|su|$mnt"; continue; }; ' +
      'st=on; { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ]; } && st=off; ' +
      'echo "$id|$st|$mnt"; done'
    ));
    if (r.errno !== 0) {
      box.innerHTML = '<div class="empty">Unknown - the module list could not be read.</div>';
      $("modcount").textContent = "?"; $("mMod").textContent = "?";
      return;
    }
    const out = r.stdout.trim();
    if (!out) { box.innerHTML = '<div class="empty">No modules installed.</div>'; $("modcount").textContent = "0"; $("mMod").textContent = "0"; return; }
    const byModule = await planByModule();
    // The check already works out which modules ship files nobody serves
    // and names the owner. Say it on the row, not only in the count.
    const unservedBy = {};
    ((CHECK && CHECK.checks) || []).forEach(function (c) {
      if (c.name === "module content not served" && c.owner) unservedBy[c.owner] = c;
    });
    const rows = out.split("\n").filter(Boolean);
    $("modcount").textContent = rows.length;
    let served = 0;
    box.innerHTML = rows.map((l) => {
      const p = l.split("|");
      const id = p[0];
      const plan = byModule ? (byModule.modules[id] || { files: 0, overlay: false, vfs: false }) : null;
      const cnt = plan ? plan.files : 0;
      const mntRaw = (p[2] || "").trim();
      const mnt = /^\d+$/.test(mntRaw) ? parseInt(mntRaw, 10) : -1;
      let label, cls, showCnt = false, tip = "";
      if (p[1] === "suite") { label = "suite"; cls = "suite"; tip = "The NoMount Suite metamodule itself."; }
      else if (p[1] === "su") { label = "su backend"; cls = "su"; served++; tip = "Provides su; not injected by the Suite."; }
      else if (p[1] === "off") { label = "skipped"; cls = "off"; tip = "Has a disable / remove / skip_mount marker, so the Suite leaves it alone."; }
      else if (!plan) { label = "?"; cls = "off"; tip = "The plan could not be read, so what this module contributes is unknown."; }
      else if (plan.overlay && plan.vfs) { label = "vfs + overlay"; cls = "ov"; served++; showCnt = true; }
      else if (plan.overlay) { label = "overlay"; cls = "ov"; served++; showCnt = true; }
      else if (plan.vfs) { label = "vfs"; cls = "vfs"; served++; showCnt = true; }
      else if (plan.bind) { label = "bind"; cls = "off"; served++; showCnt = true;
                            tip = "Served by a real bind mount, not an injection - a my_* target is bound unless the my_hookless trial is on."; }
      else { label = "nothing to inject"; cls = "off"; tip = "This module ships no files the Suite can serve - scripts, zygisk, binaries, or an empty partition directory."; }
      const files = (showCnt && cnt > 0) ? `<span class="files">${cnt} file${cnt > 1 ? "s" : ""}</span>` : `<span class="files"></span>`;
      const vis = mnt < 0
        ? `<span class="tag off" title="The mount table could not be read, so this module's visibility is unknown - it is not a claim that it owns no mount">mounts unknown</span>`
        : mnt > 0
        ? `<span class="tag info" title="This module has ${mnt} mount(s) of its own in the mount table - visible to a scanner">${mnt} mount${mnt > 1 ? "s" : ""}</span>`
        : `<span class="tag ok" title="Nothing this module owns appears in the mount table">mountless</span>`;
      const uns = unservedBy[id];
      if (uns) {
        label = "not served"; cls = "info"; tip = "";
      }
      const why = uns
        ? `<div class="mwhy">${esc(redactUids(uns.evidence || uns.meaning || ""))}</div>`
        : "";
      return `<div class="mrow${uns ? " unserved" : ""}"><div class="mname">${esc(id)}</div>${why}` +
             `<div class="mmeta">${files}${vis}<span class="tag ${cls}"${tip ? ` title="${esc(tip)}"` : ""}>${label}</span></div></div>`;
    }).join("");
    MOD_SERVED = served;
    paintModuleMetric();
  }

  async function refreshRuleSummary() {
    const d = await ruleDump();
    if (!d.ok) {
      $("rulechip").textContent = "?";
      $("rulebreak").textContent = "Unknown \u2014 the engine did not answer.";
      return;
    }
    const rro = d.rro.length, vfs = d.injects.length - rro;
    $("rulechip").textContent = d.injects.length;
    $("rulebreak").textContent = d.injects.length
      ? `${vfs} file redirect${vfs === 1 ? "" : "s"} · ${rro} RRO overlay APK${rro === 1 ? "" : "s"} - all Prism, no mounts`
      : "No rules active.";
    _paintRuleModuleBar(d.lines.filter((l) => !l.includes("(virtual dir)")));
  }

  const _RM_PALETTE = ["#57e6c3", "#7c9cff", "#c792ea", "#4fd1e0", "#9ccc65", "#a5b4fc", "#5eead4"];
  function _paintRuleModuleBar(lines) {
    const box = $("ruleModuleBar"); if (!box) return;
    if (!lines.length) { box.classList.add("none"); box.innerHTML = ""; return; }
    const counts = {};
    lines.forEach((l) => { const m = _ruleModule(l); counts[m] = (counts[m] || 0) + 1; });
    const entries = Object.keys(counts).map((k) => [k, counts[k]]).sort((a, b) => b[1] - a[1]);
    const total = lines.length;
    const MAX = 5;
    const shown = entries.slice(0, MAX);
    const rest = entries.slice(MAX);
    if (rest.length) shown.push(["other", rest.reduce((a, e) => a + e[1], 0), true]);
    const col = (e, i) => e[2] ? "var(--faint)" : _RM_PALETTE[i % _RM_PALETTE.length];
    const seg = shown.map((e) =>
      `<span title="${esc(e[0])}: ${e[1]}"></span>`
    ).join("");
    const legend = shown.map((e) => {
      const nm = e[2] ? `other (${rest.length} module${rest.length > 1 ? "s" : ""})` : e[0];
      return `<span class="rmleg"><span class="rmsw"></span>` +
             `<span class="rmname" title="${esc(nm)}">${esc(nm)}</span> <b>${e[1]}</b></span>`;
    }).join("");
    box.classList.remove("none");
    box.innerHTML = `<div class="rmbar">${seg}</div><div class="rmlegend">${legend}</div>`;
    // A width and a palette entry are computed per module, so neither can live in
    // the stylesheet, and a style= attribute is what style-src 'self' refuses. The
    // CSSOM is not governed by CSP, so the same two declarations are set here.
    const bars = box.querySelectorAll(".rmbar > span");
    const swatches = box.querySelectorAll(".rmsw");
    shown.forEach((e, i) => {
      if (bars[i]) {
        bars[i].style.width = `${(e[1] / total * 100).toFixed(2)}%`;
        bars[i].style.background = col(e, i);
      }
      if (swatches[i]) swatches[i].style.background = col(e, i);
    });
  }

  var _files = [];
  async function refreshFiles() {
    const box = $("vfsdirs");
    const d = await ruleDump();
    if (!d.ok) {
      $("vfscount").textContent = "?";
      box.innerHTML = '<div class="empty">Unknown \u2014 the engine did not answer.</div>';
      _files = [];
      return;
    }
    const isOv = (p) => /\/overlay\/[^\s]*\.apk$/.test(p);
    const dirs = {};
    _files = d.injects.filter(Boolean).sort();
    for (const vp of _files) {
      const dir = vp.replace(/\/[^/]*$/, "") || "/";
      const e = dirs[dir] || (dirs[dir] = { n: 0, ov: 0 });
      e.n++; if (isOv(vp)) e.ov++;
    }
    const keys = Object.keys(dirs).sort((a, b) => dirs[b].n - dirs[a].n || a.localeCompare(b));
    $("vfscount").textContent = _files.length;
    if (!keys.length) box.innerHTML = '<div class="empty">No rules active.</div>';
    else box.innerHTML = keys.map((k) => {
      const e = dirs[k], ov = e.ov === e.n;
      return `<div class="row"><span class="name mono">${esc(k)}</span>` +
        `<span class="sub hint-inline">${e.n} ` +
        `${ov ? "apk" : "file"}${e.n > 1 ? "s" : ""}</span>` +
        `<span class="tag ${ov ? "ov" : "vfs"}">${ov ? "RRO" : "Prism"}</span></div>`;
    }).join("");
    if (!$("vfsfull").classList.contains("none")) renderFilesFull();
  }
  const WO_PATH_RE = /^\/[^\x00-\x1f\x7f]+$/;
  function toggleWhiteouts(h) {
    const on = h.classList.toggle("open");
    setExp(h);
    $("wobody").classList.toggle("none", !(on));
    if (on) refreshWhiteouts();
  }
  async function whiteoutSets() {
    const r = await nm("whiteout list");
    if (r.errno !== 0) return { ok: false, durable: [], auto: [] };
    const durable = (r.stdout || "").split("\n").map(x => x.trim())
      .filter(Boolean).filter(l => !/^no whiteouts/.test(l));
    const live = await ruleDump();
    const auto = live.ok
      ? live.lines.filter(l => l.includes("(whiteout)"))
          .map(l => (l.split(" (whiteout)")[0] || "").trim())
          .filter(p => p && !durable.some(x => x.split("	")[0] === p))
      : [];
    return { ok: true, durable, auto };
  }

  async function woChipOnly() {
    const w = await whiteoutSets();
    $("wochip").textContent = w.ok ? String(w.durable.length + w.auto.length) : "?";
  }
  async function refreshWhiteouts() {
    const box = $("woList");
    const w = await whiteoutSets();
    if (!w.ok) {
      $("wochip").textContent = "?";
      box.innerHTML = '<div class="empty">Unknown - the list could not be read.</div>';
      return;
    }
    const lines = w.durable;
    const auto = w.auto;
    const autoHtml = auto.map((p) =>
      `<div class="row abrow"><span class="ab-main">` +
      `<div class="ab-path">${esc(p)}</div>` +
      `<div class="ab-why">managed automatically - it goes when the module that asked for it goes</div>` +
      `</span><span class="tag vfs">from a module</span></div>`).join("");

    if (!lines.length) {
      $("wochip").textContent = String(auto.length);
      box.innerHTML = auto.length
        ? '<div class="empty">Nothing saved by you. The Suite hid ' + auto.length +
          ' ROM path' + (auto.length > 1 ? 's' : '') +
          " in place of a module's tmpfs:</div>" + autoHtml
        : '<div class="empty">Nothing hidden.</div>';
      return;
    }
    $("wochip").textContent = String(lines.length + auto.length);
    box.innerHTML = lines.map(l => {
      const path = l.split("\t")[0];
      const st = (l.split("\t")[1] || "").trim();
      const cls = /^hidden/.test(st) ? "vfs"
        : /^not applied \(and no such path/.test(st) ? "off" : "info";
      const hint = /^not applied - run/.test(st) ? "saved, not live yet - tap Reload on Status"
                 : /^applied, but still visible/.test(st) ? "the engine is not serving it - tap Reload on Status"
                 : /^not applied \(and no such path/.test(st) ? "this ROM has no such path - nothing to hide"
                 : "";
      const tag = /^not applied \(/.test(st) ? "not applied" : st.split(" - ")[0];
      return `<div class="row abrow"><span class="ab-main">` +
             `<div class="ab-path">${esc(path)}</div>` +
             (hint ? `<div class="ab-why">${esc(hint)}</div>` : "") + `</span>` +
             `<span class="tag ${cls}">${esc(tag)}</span>` +
             `<button class="bx" title="Stop hiding" data-act="wodel" data-nmp="${esc(path)}">✕</button></div>`;
    }).join("") + autoHtml;
  }
  async function woAdd(btn) {
    const v = ($("woPath").value || "").trim();
    if (!v) { toast("Enter an absolute path", "bad"); return; }
    if (!WO_PATH_RE.test(v)) { toast("An absolute path, on one line", "bad"); return; }
    const done = busy(btn, "Hiding...");
    const r = await woApply(v);
    if (r.errno === 0) $("woPath").value = "";
    RULES = null;
    PLAN_BY_MODULE = null;
    done(); refreshWhiteouts(); refreshStatus();
  }
  async function woApply(path) {
    const r = await nm(`whiteout add ${shq(path)}`);
    const txt = ((r.stdout || "") + (r.stderr || "")).trim();
    toast(r.errno === 0 ? (txt.split("\n").pop() || "Hidden") : failText(r, txt),
          r.errno === 0 ? "ok" : "bad");
    return r;
  }
  async function woRemove(path, btn) {
    if (!(await confirmAction(
      "Stop hiding " + path + "?",
      "That path becomes visible again to every app the moment it next looks, and the entry " +
      "is removed from your list. A module that hid it will hide it again on the next boot; " +
      "one you added by hand will not come back.",
      "Stop hiding"))) return;
    const done = busy(btn);
    const r = await nm(`whiteout remove ${shq(path)}`);
    const txt = ((r.stdout || "") + (r.stderr || "")).trim();
    toast(r.errno === 0 ? "No longer hidden" : "Failed: " + (txt || "error"),
          r.errno === 0 ? "ok" : "bad");
    RULES = null;
    PLAN_BY_MODULE = null;
    done(); refreshWhiteouts(); refreshStatus();
  }
  function absorbable(r) {
    const c = findCheck(r, "zero-mount-posture");
    if (!c) return -1;
    if (c.verdict === "pass") return 0;
    if (c.verdict === "unmeasured") return -1;
    if (c.verdict === "note" || c.verdict === "warn") return 0;
    const m = c.evidence && c.evidence.match(/(\d+)\s+module mount\(s\) visible/);
    return m ? parseInt(m[1], 10) : -1;
  }
  async function refreshAbsorbed() {
    const box = $("abDone");
    if (!box) return;
    const r = await exec(
      "while IFS= read -r l; do case \"$l\" in ''|'#'*) continue;; esac; " +
      "t=${l%%\t*}; s=${l#*\t}; " +
      "[ \"$t\" = \"$s\" ] && continue; " +
      "printf '%s\\t%s\\t%s\\n' \"$t\" \"$s\" \"$([ -e \"$s\" ] && echo live || echo gone)\"; " +
      "done < /data/adb/nomount/absorbed.list 2>/dev/null"
    );
    const rows = (r.stdout || "").split("\n").map(x => x.trim()).filter(Boolean);
    ABSORBED_N = rows.length;
    paintModuleMetric();
    if (!rows.length) { box.innerHTML = ""; return; }
    const owner = (s) => {
      const m = s.match(/\/data\/adb\/modules(?:_update)?\/([^/]+)/);
      return m ? m[1] : s;
    };
    box.innerHTML = `<div class="blk-head">Already absorbed · ${rows.length}</div>` +
      rows.map(function (l) {
        const p = l.split("\t"), tgt = p[0] || "", src = p[1] || "", live = p[2] === "live";
        return `<div class="row abrow"><span class="ab-main">` +
               `<div class="ab-path">${esc(tgt)}</div>` +
               `<div class="ab-why">from ${esc(owner(src))}` +
               (live ? "" : " - module no longer installed") + `</div>` +
               `</span><span class="tag ${live ? "vfs" : "off"}">` +
               (live ? "absorbed" : "stale entry") + `</span></div>`;
      }).join("");
  }

  let ABSORBED_N = -1;
  let MOD_SERVED = -1;
  // Coverage is the thing the Suite exists to get right, so it goes on Status
  // rather than in a check nobody opens. Painted by whichever of refreshModules
  // and refreshAbsorbed finishes last: they run in parallel.
  function paintModuleMetric() {
    if (MOD_SERVED < 0) return;
    // "0 unserved" is the strongest claim this page makes: the module set is
    // fully covered. With no cached report -- absent audit.json, or service.sh
    // deleting it after a check that timed out or did not finish -- filtering an
    // empty list also yields 0, and the card asserted full coverage having
    // measured nothing. Unmeasured is not clean.
    //
    // The question is "is there a report", NOT `ranSection(CHECK,"plan")`: the
    // plan half emits a finding only when it HAS one, so a device whose module
    // set is perfectly clean produces zero plan checks and `sections` omits
    // "plan" entirely. Keying on that rendered "coverage unchecked" on exactly
    // the fully-covered device the metric exists to praise -- the inverse of
    // this bug. See check.rs's `ran()`, which cannot tell clean from absent.
    const measured = !!(CHECK && Array.isArray(CHECK.checks));
    const unserved = measured
      ? CHECK.checks.filter(function (c) { return c.name === "module content not served"; }).length
      : -1;
    // the bare number needs its word, or "4 0 unserved" reads as two figures
    const rest = [];
    if (ABSORBED_N > 0) rest.push(ABSORBED_N + " absorbed");
    rest.push(unserved < 0 ? "coverage unchecked" : unserved + " unserved");
    $("mMod").innerHTML = MOD_SERVED +
      "<small>served · " + rest.join(" · ") + "</small>";
  }

  async function refreshAbsorb() {
    await refreshAbsorbed();
    paintAbsorbChip();
  }
  function paintAbsorbChip() {
    const chip = $("abchip");
    if (!chip) return;
    const n = absorbable(CHECK);
    if (n < 0) { chip.textContent = " - "; chip.className = "chip"; return; }
    chip.textContent = n === 0 ? (ABSORBED_N > 0 ? "none left" : "none") : String(n);
    chip.className = n === 0 ? "chip ok" : "chip info";
  }

  async function abScan(btn) {
    const done = busy(btn, "Scanning...");
    const r = await nm("absorb --dry-run");
    const out = ((r.stdout || "") + (r.stderr || "")).trim();
    const box = $("abFound");
    box.classList.remove("none");
    const lines = out.split("\n").map(x => x.trim()).filter(Boolean);
    if (!lines.length) {
      box.innerHTML = '<div class="empty">No answer from absorb.</div>';
    } else {
      const KINDS = [
        [/^skipping the tmpfs over /, "off",  "left alone"],
        [/^skipping /,                "off",  "left alone"],
        [/^would skip directory bind /, "off", "needs --include-dirs"],
        [/^would drop redundant mount /, "vfs", "already served"],
        [/^redundant /,               "vfs",  "already served"],
        [/^would absorb /,            "info", "would absorb"],
        [/^would empty /,             "info", "would empty"],
        [/^nomount: LEAK /,           "info", "absorb cannot fix"],
        [/^nomount absorb: \d+ my_\* mount\(s\) deferred/, "info", "deferred to next boot"],
      ];
      const owner = (s) => {
        const m = s.match(/\/data\/adb\/modules(?:_update)?\/([^/]+)/);
        return m ? m[1] : s;
      };
      box.innerHTML = lines.map(function (l) {
        let kind = null;
        for (var i = 0; i < KINDS.length && !kind; i++) if (KINDS[i][0].test(l)) kind = KINDS[i];
        if (!kind) {
          if (/^nomount absorb:/.test(l))
            return `<div class="empty">${esc(l.replace(/^nomount absorb:\s*/, ""))}</div>`;
          return `<div class="empty">${esc(l)}</div>`;
        }
        if (kind[2] === "absorb cannot fix" || kind[2] === "deferred to next boot")
          return `<div class="row abrow"><span class="ab-main">` +
                 `<div class="ab-why">` +
                 esc(l.replace(/^nomount: LEAK /, "").replace(/^nomount absorb: /, "")) +
                 `</div></span><span class="tag ${kind[1]}">${kind[2]}</span></div>`;

        let rest = l.replace(kind[0], "");
        let why = "";
        const paren = rest.match(/\s*\(([^)]*)\)\s*$/);
        if (paren) { why = paren[1]; rest = rest.slice(0, paren.index); }
        const arrow = rest.split(" <- ");
        const path = arrow[0].trim();
        if (why === kind[2]) why = "";
        if (arrow[1]) why = (why ? why + " · " : "") + "from " + owner(arrow[1].trim());
        return `<div class="row abrow"><span class="ab-main">` +
               `<div class="ab-path">${esc(path)}</div>` +
               (why ? `<div class="ab-why">${esc(why)}</div>` : "") +
               `</span><span class="tag ${kind[1]}">${kind[2]}</span></div>`;
      }).join("");
    }
    done();
  }

  async function abAbsorb(btn) {
    const n = absorbable(CHECK);
    if (n === 0) { toast("Nothing to absorb", "ok"); return; }
    if (!(await confirmAction(
      "Absorb other modules' mounts?",
      "Each bind another module made is re-served as a Prism injection and then unmounted. " +
      "The files still reach apps; the mounts stop existing. Hook-framework binds are left alone. " +
      "If something depended on the mount itself rather than its contents, reboot to restore it.",
      "Absorb"))) return;
    const done = busy(btn, "Absorbing...");
    const r = await nm("absorb");
    const out = ((r.stdout || "") + (r.stderr || "")).trim();
    $("abFound").classList.remove("none");
    $("abFound").innerHTML = `<div class="empty">${esc(out || "(no output)")}</div>`;
    // The deferred line is printed before absorb decides whether anything else was taken, so it
    // can sit alongside a summary that absorbed plenty. Only say nothing was absorbed when the
    // summary itself says so. The deferral is also conditional on the my_hookless trial, which
    // the old wording dropped - without the marker those mounts are not taken at the next boot
    // either, so promising "the next boot" was wrong on a default install.
    const deferred = /deferred to the pre-zygote pass/.test(out);
    const absorbedNone = /nothing to absorb/.test(out) || /: 0 mount\(s\) absorbed/.test(out);
    toast(r.errno !== 0 ? failText(r)
          : deferred
            ? (absorbedNone
                ? "Deferred - my_* mounts cannot be absorbed while Android is running"
                : "Absorbed, with my_* mounts deferred")
            : "Absorb complete",
          r.errno === 0 ? "ok" : "bad");
    await runCheck(null);
    RULES = null;
    PLAN_BY_MODULE = null;
    refreshStatus();
    refreshAbsorb();
    done();
  }

  async function woScan(btn) {
    const done = busy(btn, "Scanning...");
    const r = await nm("whiteout suggest");
    if (r.errno !== 0) {
      $("woFound").classList.remove("none");
      $("woFound").innerHTML = '<div class="empty">Scan did not run - ' +
        esc((r.stderr || "").trim() || "the command failed") + "</div>";
      toast("Scan did not run", "bad");
      done();
      return;
    }
    const out = (r.stdout || "") + (r.stderr || "");
    const box = $("woFound");
    const cands = out.split("\n").map(x => x.trim()).filter(l => l.indexOf("\t") > 0);
    const notes = out.split("\n").map(x => x.trim())
      .filter(l => /^\(|^nothing to suggest/.test(l)).join(" ");
    box.classList.remove("none");
    if (!cands.length) {
      box.innerHTML = `<div class="empty">${esc(notes || "Nothing found.")}</div>`;
      toast("Nothing to hide on this device", "ok");
    } else {
      box.innerHTML =
        `<div class="blk-head">Found · ${cands.length}</div>` +
        cands.map(l => {
          const p = l.split("\t")[0], why = l.split("\t")[1] || "";
          return `<div class="row"><span class="name mono" title="${esc(p)}">${esc(p)}</span>` +
                 `<span class="tag info" title="${esc(why)}">${esc(why.split(";")[0])}</span>` +
                 `<button class="bx" title="Hide this path" data-act="woadd" data-nmp="${esc(p)}">+</button></div>`;
        }).join("") +
        (notes ? `<div class="empty">${esc(notes)}</div>` : "");
      toast(cands.length + " candidate(s) found", "ok");
    }
    done();
  }
  document.getElementById("wobody").addEventListener("click", async ev => {
    const b = ev.target.closest("button[data-act]");
    if (!b) return;
    const p = b.getAttribute("data-nmp") || "";
    if (!WO_PATH_RE.test(p)) { toast("That path has characters nomount won't take", "bad"); return; }
    if (b.getAttribute("data-act") === "wodel") { woRemove(p, b); return; }
    const done = busy(b);
    const r = await woApply(p);
    if (r.errno === 0) { RULES = null; PLAN_BY_MODULE = null; }
    done(); refreshWhiteouts();
    if (r.errno === 0) {
      const row = b.closest(".row");
      if (row) row.remove();
      refreshStatus();
    }
  });

  function renderFilesFull() {
    const q = ($("vfsfilter").value || "").trim().toLowerCase();
    const f = q ? _files.filter(p => p.toLowerCase().indexOf(q) !== -1) : _files;
    $("vfsfull").innerHTML = !f.length ? '<div class="empty">(no match)</div>'
      : f.map(p => {
          const ov = /\/overlay\/[^\s]*\.apk$/.test(p);
          return `<div class="row"><span class="name mono" title="${esc(p)}">` +
                 `${esc(p.replace(/^.*\//, ""))}</span>` +
                 `<span class="tag ${ov ? "ov" : "vfs"}">${ov ? "RRO" : "Prism"}</span></div>`;
        }).join("");
  }
  function toggleModules(h) {
    const on = h.classList.toggle("open");
    setExp(h);
    $("modules").classList.toggle("none", !(on));
  }
  let rulesShown = false;
  let _fileView = false;
  function toggleFileView(btn) {
    _fileView = !_fileView;
    if (btn) btn.textContent = _fileView ? "By module" : "By file";
    // Same six panes toggleRules drives; both must respect the collapse or switching
    // view while the card is shut reveals the list under a closed header.
    $("vfsdirs").classList.toggle("none", !(rulesShown && _fileView));
    $("vfsfull").classList.toggle("none", !(rulesShown && _fileView));
    $("vfsfilterbar").classList.toggle("none", !(rulesShown && _fileView));
    $("ruleslist").classList.toggle("none", !(rulesShown && !_fileView));
    $("rulefilterbar").querySelector("#rulefilter").classList.toggle("none", !!(_fileView));
    const gb = $("rulegroupBtn");
    if (gb) gb.classList.toggle("none", !!(_fileView));
    if (_fileView) renderFilesFull();
  }

  async function loadRules() {
    const d = await ruleDump();
    if (!d.ok) {
      _rulesRaw = "";
      $("ruleslist").textContent = "unknown - the engine did not answer";
      $("rulecount").classList.add("none");
      return;
    }
    _rulesRaw = d.raw;
    if (!_rulesRaw) {
      $("ruleslist").textContent = "no rules";
      $("rulecount").classList.add("none");
      return;
    }
    filterRules();
  }
  async function toggleRules(h) {
    rulesShown = h.classList.toggle("open");
    setExp(h);
    $("rulefilterbar").classList.toggle("none", !(rulesShown));
    $("rulecount").classList.toggle("none", !(rulesShown));
    // The card has no id, so applyCardState's `.card.collapsed > :not(.card-h)` rule
    // never reaches these; visibility is only ever these explicit writes. Driving
    // three of the six left the By-file panes under a closed header.
    $("ruleslist").classList.toggle("none", !(rulesShown && !_fileView));
    $("vfsdirs").classList.toggle("none", !(rulesShown && _fileView));
    $("vfsfull").classList.toggle("none", !(rulesShown && _fileView));
    $("vfsfilterbar").classList.toggle("none", !(rulesShown && _fileView));
    if (rulesShown) { $("ruleslist").textContent = "Loading..."; loadRules(); }
  }

  async function reloadRules(btn) {
    const svg = btn.querySelector("svg");
    btn.disabled = true; if (svg) svg.classList.add("spin");
    const r = await nm("reload");
    const out = (r.stdout || "").trim();
    if (r.errno === 0) {
      toast((out.split("\n")[0] || "").replace(/^nomount reload:\s*/, "") || "Reloaded", "ok");
    }
    else toast(failText(r), "bad");
    if (svg) svg.classList.remove("spin"); btn.disabled = false;
    await refreshAll().catch(refreshFailed);
    const w = $("incwarn");
    if (w && r.errno === 0 && /REBOOT REQUIRED/.test(out)) {
      w.hidden = false;
      w.innerHTML = "⚠️ A system APK changed - <b>reboot to finish</b>. " +
        "Until then, apps over those APKs can force-close.";
    }
  }
  async function clearRules(btn) {
    if (!(await confirmAction(
      "Clear every injection rule?",
      "Every file your modules add disappears straight away - apps go back to seeing the stock " +
      "ROM, and anything relying on an injected file may misbehave until you put them back. " +
      "Nothing is uninstalled: Reload, or a reboot, restores all of it.",
      "Clear rules"))) return;
    const done = busy(btn, "Clearing...");
    const r = await nm("vfs clear");
    if (r.errno === 0) toast((r.stdout || "").replace(/^ok\b\s*/, "Rules cleared ").trim() || "Rules cleared", "ok");
    else toast(/could not be re-applied/.test(r.stderr || "")
                 ? "Rules cleared - but the hide list could not be re-applied: those apps are not hidden"
                 : failText(r), "bad");
    RULES = null;
    PLAN_BY_MODULE = null;
    done();
    refreshAll().catch(refreshFailed);
  }
  async function rearm(btn) {
    if (!(await confirmAction(
      "Re-arm the bootloop guard?",
      "This deletes the record of the boot that failed, including the crash log - which is the " +
      "only copy and usually names the file that caused it. Read or copy it first. The Suite " +
      "stays off until you reboot.",
      "Delete and re-arm"))) return;
    btn.disabled = true;
    await exec("rm -rf /data/adb/nomount/disabled /data/adb/nomount/bootcount /data/adb/nomount/incident.log");
    toast("Guard re-armed - reboot to re-enable", "ok");
    btn.disabled = false; refreshGuard(); refreshIncident();
  }
