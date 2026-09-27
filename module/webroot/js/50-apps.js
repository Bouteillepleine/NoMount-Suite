  "use strict";

  const UID_TARGET_RE = /^[A-Za-z0-9._*]+$/;
  async function uidOp(op, btn) {
    const v = $("uid").value.trim();
    if (!v) { toast("Enter a package name or UID", "bad"); return; }
    if (!UID_TARGET_RE.test(v)) { toast("Letters, digits, dots, underscores, and * for a glob", "bad"); return; }
    if (op === "unblock" && !(await confirmAction(
      "Stop hiding " + v + "?",
      v.indexOf("*") >= 0
        ? "That entry is a pattern. Every app it matches stops being hidden - now, and any that " +
          "install later - and the pattern itself is deleted from your list."
        : "This app sees your injected files again the moment it next looks, and the entry is " +
          "removed from your list.",
      "Stop hiding"))) return;
    const done = busy(btn, op === "block" ? "Hiding..." : "Unhiding...");
    const r = await nm(`uid ${op} ${shq(v)}`);
    if (r.errno === 0) {
      toast((r.stdout || "").replace(/^ok:\s*/, "").trim() || `${v} ${op === "block" ? "hidden" : "unhidden"}`, "ok");
      if (op === "block") $("uid").value = "";
      refreshBlocked();
    } else {
      toast("Failed: " + (r.stderr || "error"), "bad");
    }
    done();
  }
  async function refreshBlocked() {
    const box = $("blocked");
    const r = await nm("uid list");
    if (r.errno !== 0) {
      const uc0 = $("uidchip");
      if (uc0) uc0.textContent = "?";
      box.innerHTML = `<div class="blk-none">Unknown \u2014 the hide list could not be read.</div>`;
      return;
    }
    const lines = (r.stdout || "").split("\n").map(s => s.trim()).filter(Boolean);
    const none = !lines.length || lines[0] === "no blocked apps";
    const uc = $("uidchip");
    if (none && uc) uc.textContent = "0";
    if (none) {
      box.innerHTML = `<div class="blk-none">No per-UID hiding active - no apps hidden.</div>`;
      return;
    }
    const rows = lines.map(l => {
      const [name, stateRaw] = l.split("\t");
      const s = (stateRaw || "").trim();
      let cls = "live";
      // Every string here is one `nomount uid list` really emits. `/unreachable/`
      // used to be in the "gone" set and nothing has ever produced it.
      if (/unread/.test(s)) cls = "unknown";
      else if (/not installed/.test(s) ||
          /no match/.test(s) || /invalid glob/.test(s)) cls = "gone";
      else if (/not applied/.test(s)) cls = "pending";
      else if (/not saved/.test(s)) cls = "drift";
      const uidM = s.match(/uid (\d+)/);
      const viaM = s.match(/^via (\S+)/);
      const target = viaM ? viaM[1]
        : (/^uid \d+$/.test(name) ? (uidM ? uidM[1] : name) : name);
      const xTitle = viaM ? `Remove ${viaM[1]} - the rule hiding this app` : "Unhide";
      const actionable = UID_TARGET_RE.test(target);
      const covIdx = s.indexOf(" \u00b7 also covered by ");
      const sHead = covIdx === -1 ? s : s.slice(0, covIdx);
      const sCov  = covIdx === -1 ? "" : s.slice(covIdx + 3);
      const save = cls === "drift" && actionable
        ? `<button class="bx save" title="Save so it survives reboot" data-act="save" data-nmt="${esc(target)}">💾</button>` : "";
      return { active: cls === "live" || cls === "pending" || cls === "drift",
               hiding: cls === "live" || cls === "drift",
               unknown: cls === "unknown",
               key: uidM ? uidM[1] : name,
               html: `<div class="blk ${cls}">
        <span class="dot"></span>
        <span class="bmid">
          <span class="btop"><span class="bn">${esc(name)}</span><span class="bs">${esc(sHead)}</span></span>
          ${sCov ? `<span class="bcov">${esc(sCov)}</span>` : ""}
        </span>
        ${save}
        ${actionable ? `<button class="bx" title="${esc(xTitle)}" data-act="unblock" data-nmt="${esc(target)}">✕</button>` : ""}
      </div>` };
    });
    const active = rows.filter(function (x) { return x.active; });
    const unknown = rows.filter(function (x) { return x.unknown; });
    const waiting = rows.filter(function (x) { return !x.active && !x.unknown; });
    const hiding = new Set(rows.filter(function (x) { return x.hiding; })
                               .map(function (x) { return x.key; })).size;
    const htmlOf = function (a) { return a.map(function (x) { return x.html; }).join(""); };
    if (uc) uc.textContent = unknown.length ? "?" : String(hiding);
    box.innerHTML =
      (active.length ? `<div class="blk-head">Hidden apps · ${hiding}</div>` + htmlOf(active) : "") +
      (unknown.length ? `<div class="blk-head">Could not be checked · ${unknown.length}</div>` +
        `<div class="blk-sub">These are saved, but the engine did not answer, so whether they are
          in force right now is unknown.</div>` + htmlOf(unknown) : "") +
      (waiting.length ? `<div class="blk-head">Waiting · ${waiting.length}</div>` +
        `<div class="blk-sub">Nothing installed matches these yet. A glob keeps watching, so a
          detector installed later is hidden the moment it appears.</div>` + htmlOf(waiting) : "");
  }

  document.getElementById("blocked").addEventListener("click", ev => {
    const b = ev.target.closest("button[data-act]");
    if (!b) return;
    const t = b.getAttribute("data-nmt") || "";
    if (!UID_TARGET_RE.test(t)) { toast("That entry has characters nomount won't take", "bad"); return; }
    if (b.getAttribute("data-act") === "save") saveOne(t, b); else unblockOne(t, b);
  });
  function usPickFrom(row) {
    if (!row) return;
    const t = row.getAttribute("data-nmt") || "";
    if (!UID_TARGET_RE.test(t)) { toast("That entry has characters nomount won't take", "bad"); return; }
    usPick(t);
  }
  document.getElementById("usList").addEventListener("click", ev => {
    usPickFrom(ev.target.closest("[data-act='uspick']"));
  });
  document.getElementById("usList").addEventListener("keydown", ev => {
    if (ev.key !== "Enter" && ev.key !== " ") return;
    const row = ev.target.closest("[data-act='uspick']");
    if (!row) return;
    ev.preventDefault();
    usPickFrom(row);
  });
  var _pkgsLoaded = false, _pkgs = [], _pkgSel = -1;
  async function loadPkgList() {
    if (_pkgsLoaded) return;
    const r = await exec("pm list packages -3 -U 2>/dev/null | sort");
    _pkgs = (r.stdout || "").split("\n").map(function (l) {
      const m = l.match(/^package:(\S+)\s+uid:(\d+)/);
      return m ? { name: m[1], uid: m[2] } : null;
    }).filter(Boolean);
    if (_pkgs.length) _pkgsLoaded = true;
  }
  function pkgHide() { const d = $("pkgdd"); d.classList.remove("show"); d.innerHTML = ""; _pkgSel = -1; }
  function pkgBlur() { setTimeout(pkgHide, 130); }
  function pkgFilter() {
    const q = ($("uid").value || "").trim().toLowerCase();
    const d = $("pkgdd"); _pkgSel = -1;
    if (!_pkgs.length) { pkgHide(); return; }
    const matches = q
      ? _pkgs.filter(function (p) { return p.name.toLowerCase().indexOf(q) !== -1 || p.uid.indexOf(q) !== -1; })
      : _pkgs;
    if (!matches.length) { d.innerHTML = '<div class="none">No matching installed app</div>'; d.classList.add("show"); return; }
    const head = '<div class="pkghead">' + matches.length + ' app' + (matches.length > 1 ? 's' : '') +
                 (q ? ' match' : '') + ' · type to filter</div>';
    d.innerHTML = head + matches.map(function (p) {
      return '<div class="opt" data-nm="' + esc(p.name) + '" onmousedown="pkgPick(this)">' +
             '<span class="pn">' + esc(p.name) + '</span>' +
             '<span class="pu">uid ' + esc(p.uid) + '</span></div>';
    }).join("");
    d.classList.add("show");
  }
  function pkgPick(el) { $("uid").value = el.getAttribute("data-nm"); pkgHide(); }
  function pkgKey(e) {
    const d = $("pkgdd"); if (!d.classList.contains("show")) return;
    const opts = d.querySelectorAll(".opt");
    if (e.key === "Escape") { pkgHide(); return; }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!opts.length) return;
      _pkgSel = (_pkgSel + (e.key === "ArrowDown" ? 1 : -1) + opts.length) % opts.length;
      opts.forEach(function (o, i) { o.classList.toggle("sel", i === _pkgSel); });
      opts[_pkgSel].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter" && _pkgSel >= 0 && opts[_pkgSel]) {
      e.preventDefault(); pkgPick(opts[_pkgSel]);
    }
  }
  const ISO_MODES = {
    both:      "Hiding covers every isolated process.",
    appzygote: "Hiding covers the app-zygote pool only.",
    platform:  "Hiding covers the platform pool (99000-99999) only.",
    off:       "Isolated processes are not hidden from.",
  };
  function isoPaint(mode, note, bad) {
    const seg = $("isoSeg"), st = $("isoState");
    const known = Object.prototype.hasOwnProperty.call(ISO_MODES, mode);
    seg.classList.toggle("unknown", !known);
    seg.querySelectorAll(".seg-b").forEach(function (b) {
      const on = known && b.dataset.v === mode;
      b.classList.toggle("on", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    st.textContent = note || (known ? ISO_MODES[mode] : "");
    st.classList.toggle("bad", !!bad);
  }
  async function refreshIsolated() {
    if (!(await ruleDump()).ok) {
      isoPaint(null, "Engine not responding - this is the saved policy, not what the kernel is doing.", true);
      return;
    }
    const r = await nm("uid isolated");
    const m = (r.stdout || "").trim().match(/^(both|appzygote|platform|off)/);
    if (r.errno === 0 && m) isoPaint(m[1]);
    else isoPaint(null, "Could not read the saved policy.", true);
  }
  async function setIsolated(mode) {
    const seg = $("isoSeg");
    const btns = Array.prototype.slice.call(seg.querySelectorAll(".seg-b"));
    btns.forEach(function (b) { b.disabled = true; });
    try {
      const r = await nm(`uid isolated ${mode}`);
      if (r.errno === 0) {
        toast((r.stdout || "").replace(/^ok:/, "").trim() || "Updated", "ok");
        isoPaint(mode);
      } else {
        toast("Failed: " + (r.stderr || "error"), "bad");
        await refreshIsolated();
      }
    } finally {
      btns.forEach(function (b) { b.disabled = false; });
    }
  }

  const US = new Map();
  let usShown = false;
  const US_REASONS = {
    detector:       { label: "known detector",   cls: "r-det",  pick: true },
    "queries-root": { label: "looks for root",   cls: "r-qr",   pick: true },
    "su-perm":      { label: "wants superuser",  cls: "r-su",   pick: false },
    "queries-all":  { label: "enumerates apps",  cls: "r-qa",   pick: false },
  };
  function usParse(out) {
    (out || "").split("\n").forEach(function (l) {
      const [pkg, raw] = l.replace(/\r/g, "").split("\t");
      if (!pkg || !raw) return;
      const reasons = raw.trim().split(",").filter(Boolean);
      const prev = US.get(pkg);
      const pick = reasons.some(function (r) { return US_REASONS[r] && US_REASONS[r].pick; });
      US.set(pkg, { reasons: reasons, pick: prev ? prev.pick : pick });
    });
  }
  async function uidScan(btn) {
    const done = busy(btn, "Scanning...");
    const r = await exec("sh /data/adb/modules/meta-nomount/uidscan.sh");
    if (r.errno !== 0) {
      done();
      toast("Scan did not run - " +
            (((r.stderr || "").trim().split("\n")[0]) || "the script failed"), "bad");
      return;
    }
    const degraded = /no detector inventory/i.test(r.stderr || "");
    usParse(r.stdout);
    const cur = await nm("uid list");
    (cur.stdout || "").split("\n").forEach(function (l) {
      const name = l.split("\t")[0].trim();
      if (name && US.has(name)) US.delete(name);
    });
    done();
    if (!usShown) usToggle($("usShow"));
    usRender();
    const note = degraded ? " (by manifest only - the detector name list was unavailable)" : "";
    toast(
      US.size ? `${US.size} candidate(s)${note}` : `Nothing worth hiding found${note}`,
      US.size ? "ok" : ""
    );
  }
  function usToggle(btn) {
    usShown = !usShown;
    $("usList").style.display = usShown ? "" : "none";
    btn.style.display = "";
    btn.textContent = usShown ? "Hide list" : "Show list";
  }
  function usPick(pkg) {
    const e = US.get(pkg); if (!e) return;
    e.pick = !e.pick; usRender();
  }
  function usRender() {
    const box = $("usList");
    $("usShow").style.display = US.size ? "" : "none";
    if (!US.size) {
      box.innerHTML = '<div class="blk-none">Nothing left to pick - scan again after installing apps.</div>';
      return;
    }
    const order = ["detector", "queries-root", "su-perm", "queries-all"];
    const rank = (e) => Math.min.apply(null, e.reasons.map(function (r) {
      const i = order.indexOf(r); return i < 0 ? 9 : i;
    }));
    const rows = [...US.entries()].sort(function (a, b) {
      return rank(a[1]) - rank(b[1]) || a[0].localeCompare(b[0]);
    }).map(function ([pkg, e]) {
      const chips = e.reasons.map(function (r) {
        const d = US_REASONS[r] || { label: r, cls: "" };
        return `<span class="rch ${d.cls}">${esc(d.label)}</span>`;
      }).join("");
      return `<div class="usrow${e.pick ? " on" : ""}" data-act="uspick" data-nmt="${esc(pkg)}"
        role="checkbox" tabindex="0" aria-checked="${e.pick ? "true" : "false"}"
        aria-label="${esc(pkg)}">
        <span class="uscb">${e.pick ? "✓" : ""}</span>
        <span class="usn">${esc(pkg)}</span>
        <span class="usr">${chips}</span>
      </div>`;
    }).join("");
    const n = [...US.values()].filter(function (e) { return e.pick; }).length;
    box.innerHTML = `<div class="blk-head">Candidates · ${US.size}</div>${rows}
      <div class="usfoot">
        <button class="act primary" onclick="usApply(this)"${n ? "" : " disabled"}>Hide ${n} selected</button>
        <span class="presethint">Picked by default: known detectors and apps that look for a root
          manager. Apps that merely request superuser are left unpicked - those are usually your own
          root tools, and hiding shows them the stock tree instead of your module content.</span>
      </div>`;
  }
  async function usApply(btn) {
    const picks = [...US.entries()].filter(function ([, e]) { return e.pick; }).map(function ([p]) { return p; });
    if (!picks.length) return;
    const done = busy(btn, "Hiding...");
    const b = await bin();
    const nmClient = b.replace(/nomount$/, "nm");
    await exec(`NM_BIN=${shq(nmClient)} ` +
               picks.map(function (p) { return `${shq(b)} uid block ${shq(p)}`; }).join("; "));
    const after = await nm("uid list");
    const listed = {};
    (after.stdout || "").split("\n").forEach(function (l) {
      const n = (l.split("\t")[0] || "").trim();
      if (n) listed[n] = 1;
    });
    let ok = 0, bad = 0;
    picks.forEach(function (p) {
      if (listed[p]) { ok++; US.delete(p); } else bad++;
    });
    done();
    usRender();
    refreshBlocked();
    toast(bad ? `${ok} hidden, ${bad} failed` : `${ok} app(s) hidden`, bad ? "bad" : "ok");
  }
  async function addGlobs(btn) {
    const done = busy(btn, "Adding...");
    const r = await nm("uid preset detectors --globs");
    if (r.errno === 0) toast((r.stdout || "").replace(/^preset /, "").trim() || "Added", "ok");
    else toast("Failed: " + (r.stderr || "error"), "bad");
    done();
    refreshBlocked();
  }

  async function unblockOne(target, btn) {
    if (!(await confirmAction(
      "Stop hiding " + target + "?",
      target.indexOf("*") >= 0
        ? "That entry is a pattern. Every app it matches stops being hidden - now, and any that " +
          "install later - and the pattern itself is deleted from your list."
        : "This app sees your injected files again the moment it next looks, and the entry is " +
          "removed from your list.",
      "Stop hiding"))) return;
    btn.disabled = true;
    const r = await nm(`uid unblock ${shq(target)}`);
    if (r.errno === 0) toast(`${target} unhidden`, "ok");
    else toast("Failed: " + (r.stderr || "error"), "bad");
    refreshBlocked();
  }
  async function saveOne(target, btn) {
    btn.disabled = true;
    const r = await nm(`uid block ${shq(target)}`);
    if (r.errno === 0) toast(`${target} saved`, "ok");
    else toast("Failed: " + (r.stderr || "error"), "bad");
    refreshBlocked();
  }

  function setExp(h) {
    if (h) h.setAttribute("aria-expanded", h.classList.contains("open") ? "true" : "false");
  }
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" && e.key !== " " && e.key !== "Spacebar") return;
    const h = e.target && e.target.closest && e.target.closest(".card-h.clp");
    if (!h) return;
    e.preventDefault();
    h.click();
  });
