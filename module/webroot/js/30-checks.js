  "use strict";

  let CHECK = null;

  // Every spelling of a hidden appid that any producer emits. Keep in step with
  // `hidden_uid_label` in src/audit.rs AND src/doctor.rs.
  function redactUids(s) {
    return String(s == null ? "" : s)
      .replace(/uid \d+ \(hidden\)/g, "uid <redacted> (hidden)")
      .replace(/hidden uid \d+/g, "hidden uid <redacted>");
  }

  function parseJson(r) {
    const raw = (r.stdout || "").trim();
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) {}
    const a = raw.indexOf("{"), b = raw.lastIndexOf("}");
    if (a < 0 || b <= a) return null;
    try { return JSON.parse(raw.slice(a, b + 1)); } catch (e) { return null; }
  }

  function ranSection(r, s) {
    if (!r) return false;
    if (r.sections && r.sections.length) return r.sections.indexOf(s) >= 0;
    return !!(r.checks || []).some(function (c) { return c.section === s; });
  }

  function findCheck(r, id) {
    const cs = (r && r.checks) || [];
    for (var i = 0; i < cs.length; i++) if (cs[i].id === id) return cs[i];
    return null;
  }
  function checkById(id) { return findCheck(CHECK, id); }

  function engineDown(r) {
    if (ENGINE_LIVE === false) return true;
    return !!r && ranSection(r, "device") && r.engine === null;
  }
  function guardTripped(r) {
    if (GUARD_TRIPPED !== null) return GUARD_TRIPPED;
    const g = findCheck(r, "boot-guard-armed");
    return !!g && g.verdict === "fail";
  }

  const VERDICT_LABEL = {
    fail: "worth knowing",
    reboot: "reboot to finish",
    warn: "worth a look",
    unmeasured: "not measured",
    note: "for information",
  };

  // Only a finding that carries an oracle - a named way an app would actually observe it - may
  // claim a detector can see it. Half the warn findings are not visibility problems at all
  // ("module content not served", "planned rule not live", "target claimed twice"), and
  // stamping them all with the detector line told the user they were exposed by something no
  // app can look at, directly above evidence saying the files are served by nothing.
  function verdictLabel(c) {
    if ((c.verdict === "warn" || c.verdict === "fail") && c.oracle) return "a detector can see this";
    return VERDICT_LABEL[c.verdict] || c.verdict;
  }
  function isAttention(v) { return v === "fail" || v === "reboot" || v === "warn"; }

  // How many findings the last check left open. Returns 0 when nothing has been checked, so a
  // device with no report reads as "no news", never as "N things wrong".
  function checkAttention() {
    const s = CHECK && CHECK.summary;
    if (!s) return 0;
    return (s.open_failures || 0) + (s.warn || 0);
  }
  function isShown(v) { return isAttention(v) || v === "unmeasured"; }

  function auAge(ts) {
    if (!ts) return "";
    const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
    if (secs < 90) return "just now";
    const mins = Math.round(secs / 60);
    if (mins < 90) return mins + " min ago";
    const hrs = Math.round(mins / 60);
    if (hrs < 36) return hrs + "h ago";
    return Math.round(hrs / 24) + "d ago";
  }

  function paintHealthLine(r) {
    const el = $("healthline"), dot = $("hlDot"), txt = $("hlTxt");
    if (!el) return;
    el.classList.remove("attn", "down");
    // engineDown() and guardTripped() answer from ENGINE_LIVE/GUARD_TRIPPED without needing a
    // report, so they are asked first. Testing !r first told the one user who most needs an
    // answer - the kernel has no engine, so no check can ever produce a report - that they had
    // simply not run a check yet, and sent them to press a button that does not exist.
    if (engineDown(r) || guardTripped(r)) {
      el.classList.add("attn", "down");
      dot.className = "hl-dot info";
      txt.innerHTML = engineDown(r)
        ? "<b>The engine isn’t running</b> <span class=\"age\">· nothing is being injected</span>"
        : "<b>The bootloop guard tripped</b> <span class=\"age\">· the Suite disabled itself</span>";
      return;
    }
    if (!r || !r.summary) {
      dot.className = "hl-dot";
      txt.innerHTML = "<b>Not checked yet</b> <span class=\"age\"> - tap to run a check</span>";
      return;
    }
    const s = r.summary;
    const attn = (s.open_failures || 0) + (s.warn || 0);
    const unm = s.unmeasured || 0;
    const age = r.ts ? ' <span class="age">· checked ' + esc(auAge(r.ts)) + "</span>" : "";
    if (attn > 0) {
      dot.className = "hl-dot ok";
      txt.innerHTML = "<b>" + attn + (attn > 1 ? " findings" : " finding") +
                      " worth reading</b>" + age;
    } else if (!ranSection(r, "device")) {
      dot.className = "hl-dot info";
      txt.innerHTML = "<b>Only your plan was checked</b> " +
                      "<span class=\"age\"> - tap to check the device too</span>";
    } else if (unm > 0 || s.complete === false) {
      dot.className = "hl-dot info";
      txt.innerHTML = "<b>Not fully checked yet</b> <span class=\"age\"> - " +
                      (unm || 1) + (unm === 1 ? " check" : " checks") +
                      " had nothing to look at</span>";
    } else {
      dot.className = "hl-dot ok";
      txt.innerHTML = "<b>Nothing found</b>" + age;
    }
    el.classList.remove("u-hide");
  }

  let CHECK_RUNNING = false;
  async function runCheck(btn) {
    if (CHECK_RUNNING) { toast("A check is already running", "info"); return; }
    const done = busy(btn, "Checking...");
    $("findlist").innerHTML = '<div class="empty">Checking...</div>';
    CHECK_RUNNING = true;
    try {
      const r0 = await nm("check --json --write");
      const rep = parseJson(r0);
      if (rep) CHECK = rep;
      else toast("Check did not run - " +
                 (((r0.stderr || "").trim().split("\n")[0]) || "no output"), "bad");
      renderCheck(CHECK);
      refreshStealth(); refreshStatus(); paintModuleMetric();
    } finally { CHECK_RUNNING = false; done(); }
  }

  const CHECK_FRESH_SECS = 60;
  async function autoCheck() {
    if (CHECK_RUNNING) return;
    const ts = CHECK && typeof CHECK.ts === "number" ? CHECK.ts : 0;
    const fresh = ts && (Math.floor(Date.now() / 1000) - ts) < CHECK_FRESH_SECS;
    if (fresh && ranSection(CHECK, "device")) return;
    CHECK_RUNNING = true;
    try {
      const r = parseJson(await nm("check --json --write"));
      if (r) { CHECK = r; renderCheck(CHECK); refreshStealth(); refreshStatus(); paintModuleMetric(); }
    } catch (e) {
    } finally { CHECK_RUNNING = false; }
  }

  async function loadCheckCache() {
    CHECK = parseJson(await exec("cat /data/adb/nomount/audit.json 2>/dev/null"));
    renderCheck(CHECK);
  }

  function renderCheck(r) {
    const list = $("findlist"), chip = $("fchip"), sub = $("fsub"), age = $("auage");
    paintHealthLine(r);
    paintAbsorbChip();
    // Keep Copy report reachable when the engine is down. That is the state a bug report is
    // most needed in, and it is exactly the state that produces no report to gate the button on.
    $("auCopy").classList.toggle("u-hide", !((r || engineDown(r))));

    if (!r || !r.checks) {
      list.innerHTML = engineDown(r)
        ? '<div class="empty">No kernel driver, so there is nothing to check yet. Use <b>Copy report</b> to get the details for a bug report.</div>'
        : '<div class="empty">Not checked yet - press <b>Re-run</b>.</div>';
      chip.textContent = engineDown(r) ? "engine down" : "not checked";
      chip.className = "chip info";
      age.classList.add("u-hide");
      return;
    }

    // runCheck does not set NM_REDACT_HIDE_LIST, so the raw report carries real appids. This
    // pane is the one users screenshot and paste into a bug report, and copyReport already
    // redacts on the way out - the same rule has to hold here.
    $("auditout").textContent = redactUids(JSON.stringify(r, null, 1));
    age.classList.remove("u-hide");
    age.textContent = "Checked " + (auAge(r.ts) || "now") + " · " +
      (r.sections && r.sections.length ? r.sections.join(" + ") : "unknown") + " · " +
      (r.verdict || "");

    const rows = r.checks.filter(function (c) { return isShown(c.verdict); });
    const attention = rows.filter(function (c) { return isAttention(c.verdict); });
    const unmeasured = rows.filter(function (c) { return c.verdict === "unmeasured"; });
    const down = engineDown(r);

    if (down) { chip.textContent = "engine down"; chip.className = "chip info"; }
    else if (guardTripped(r)) { chip.textContent = "guard tripped"; chip.className = "chip info"; }
    else if (attention.length) {
      chip.textContent = attention.length + (attention.length > 1 ? " findings" : " finding");
      chip.className = "chip ok";
    }
    else if (!ranSection(r, "device")) { chip.textContent = "plan only"; chip.className = "chip info"; }
    else if (unmeasured.length) { chip.textContent = unmeasured.length + " not measured"; chip.className = "chip info"; }
    else { chip.textContent = "all clear"; chip.className = "chip ok"; }

    const s = r.summary || {};
    const clean = (s.pass || 0) + (s.not_applicable || 0) + (s.note || 0);

    const group = function (title, gr) {
      return gr.length
        ? '<div class="fgroup">' + title + ' <span class="cnt">' + gr.length + "</span></div>" +
          gr.map(checkRow).join("")
        : "";
    };

    if (down || guardTripped(r)) {
      sub.textContent = down
        ? "The engine is not answering, so nothing here describes what is being served."
        : "The Suite disabled itself, so nothing is being injected.";
      list.innerHTML =
        '<div class="frow"><div class="fname">' +
        (down ? "The engine isn’t running" : "The bootloop guard tripped") + "</div>" +
        '<div class="fmean">' +
        (down
          ? "Nothing is being injected, so a clean result below says nothing about how you " +
            "look to an app."
          : "Re-arm it in Bootloop guard on Status, then reboot.") +
        '</div><div class="fmeta"><span class="tag info">' +
        (down ? "engine down" : "guard tripped") + "</span></div></div>" +
        group("Worth knowing", attention);
      return;
    }
    if (!rows.length && ranSection(r, "device")) {
      sub.textContent = clean + " check" + (clean === 1 ? "" : "s") +
        " ran across " + (r.sections || []).join(" and ") + ". Nothing to report.";
      list.innerHTML = "";
      return;
    }

    sub.textContent = "Everything that passed is left out. What is left is information about this device - the Suite is working, and nothing here has to be fixed for it to keep working.";
    let head = "";
    if (!ranSection(r, "device")) {
      head = '<div class="frow"><div class="fname">Only your plan was checked</div>' +
        '<div class="fmean">This report covers what your module set will do at the next boot. ' +
        "Nothing on the device itself was measured, so nothing here says whether what you " +
        "serve is detectable.</div>" +
        '<div class="fmeta"><span class="tag info">plan only</span>' +
        '<button class="act u-btn-end" ' +
        'onclick="runCheck(this)">Check the device</button></div></div>';
    }
    let unmHead = "";
    if (unmeasured.length || s.complete === false) {
      unmHead = '<div class="frow"><div class="fname">' +
        (attention.length ? "Not a complete answer" : "Not everything could be measured") + "</div>" +
        '<div class="fmean">' + unmeasured.length + " check" +
        (unmeasured.length === 1 ? "" : "s") + " had nothing to look at when this ran, so " +
        (unmeasured.length === 1 ? "it is" : "they are") + " not " +
        (unmeasured.length === 1 ? "a pass" : "passes") + ". " +
        (attention.length
          ? "Read what is above first - several of these depend on it."
          : "The usual reason is timing: the boot pass runs before any app has opened an " +
            "injected file, so the checks that need a running app cannot answer then. " +
            "Run them now that the device is up.") + "</div>" +
        '<div class="fmeta"><span class="tag info">not measured</span>' +
        '<button class="act u-btn-end" ' +
        'onclick="runCheck(this)">Run them now</button></div></div>';
    }
    list.innerHTML = head +
      group("Worth knowing", attention) +
      (unmeasured.length ? '<div class="fgroup">Not measured <span class="cnt">' +
        unmeasured.length + "</span></div>" + unmHead + unmeasured.map(checkRow).join("")
        : unmHead);
  }

  function checkRow(c) {
    const b = [];
    b.push('<div class="frow" id="chk-' + esc(c.id) + '">');
    // Lead with the plain-English meaning the backend already writes for 65 of these, and keep
    // the check's own name as the secondary technical label. Leading with "readdir ino vs stat
    // ino" told the reader nothing they could act on.
    if (c.meaning) {
      b.push('<div class="fname">' + esc(redactUids(c.meaning)) + "</div>");
      b.push('<div class="fmean">' + esc(c.name) + "</div>");
    } else {
      b.push('<div class="fname">' + esc(c.name) + "</div>");
    }
    if (c.verdict === "reboot") {
      b.push('<div class="fmean"><b>Next:</b> reboot to finish this one.</div>');
    }
    if (c.owner) b.push('<div class="fowner">From: <b>' + esc(c.owner) + "</b></div>");
    b.push('<div class="fmeta"><span class="tag ' + (c.verdict === "note" ? "off" : "info") + '">' +
           esc(verdictLabel(c)) + "</span>" +
           '<span class="tag off">' + esc(c.section || "") + "</span></div>");
    b.push('<details><summary>What was measured</summary><div class="ev">' +
           esc(redactUids(c.evidence || "(nothing recorded)")) +
           (c.oracle ? "\n\nhow an app would use it: " + esc(c.oracle) : "") +
           "</div></details>");
    b.push("</div>");
    return b.join("");
  }

  async function copyReport(btn) {
    if (!CHECK && !engineDown(CHECK)) { toast("Run the check first."); return; }
    if (!CHECK) {
      // No engine means no report will ever exist, so hand over what can be gathered without
      // one rather than refusing - this is the install that most needs to be reportable.
      const d = busy(btn, "Copying...");
      const e = await exec(
        'echo "$(getprop ro.product.marketname)|$(getprop ro.build.version.release)|' +
        '$(getprop ro.build.id)|$(uname -r)|$(uname -v)|$(getprop ro.product.model)|' +
        '$(lsmod 2>/dev/null | grep -c -i kernelsu)"'
      );
      const q = (e.stdout || "").trim().split("|");
      const t = [
        "NoMount Suite " + SUITE_VERSION +
          (SUITE_COMMIT && SUITE_COMMIT !== "dev" ? " (" + SUITE_COMMIT + ")" : "") + " - check",
        "device: " + (q[0] || q[5] || "?") + " · Android " + (q[1] || "?") + " · " + (q[2] || "?"),
        "kernel: " + (q[3] || "?") + (q[4] ? " · " + q[4] : ""),
        "root: " + (q[6] && q[6] !== "0" ? "LKM - kernelsu.ko is loaded, so the running kernel is not a NoMount build" : "built into the kernel, or unknown"),
        "engine: not responding - no CONFIG_NOMOUNT kernel, so no check could run",
      ].join("\n");
      let copied = false;
      try {
        await navigator.clipboard.writeText(t);
        copied = true;
      } catch (err) { copied = false; }
      d();
      if (copied) toast("Report copied.");
      else {
        $("auditout").textContent = t;
        const dd = $("auditout").closest("details");
        if (dd) dd.open = true;
        $("devtools").open = true;
        toast("Clipboard unavailable - the report is in Raw report, ready to select.");
      }
      return;
    }
    const done = busy(btn, "Copying...");
    const env = await exec(
      'echo "$(getprop ro.product.marketname)|$(getprop ro.build.version.release)|' +
      '$(getprop ro.build.id)|$(uname -r)|$(uname -v)|$(getprop ro.product.model)|' +
      '$(lsmod 2>/dev/null | grep -c -i kernelsu)"'
    );
    const p = (env.stdout || "").trim().split("|");
    const s = CHECK.summary || {};
    const lines = [
      "NoMount Suite " + (CHECK.suite || SUITE_VERSION) +
        (SUITE_COMMIT && SUITE_COMMIT !== "dev" ? " (" + SUITE_COMMIT + ")" : "") + " - check",
      "device: " + (p[0] || p[5] || "?") + " · Android " + (p[1] || "?") + " · " + (p[2] || "?"),
      "kernel: " + (p[3] || "?") + (p[4] ? " · " + p[4] : ""),
      "root: " + (p[6] && p[6] !== "0" ? "LKM - kernelsu.ko is loaded, so the running kernel is not a NoMount build" : "built into the kernel, or unknown"),
      "engine: " + (CHECK.engine === null || CHECK.engine === undefined ? "not responding" : "v" + CHECK.engine),
      "sections: " + ((CHECK.sections || []).join(", ") || "?"),
      "rules: " + (CHECK.rules === null || CHECK.rules === undefined
        ? "could not enumerate"
        : CHECK.rules + " across " + (CHECK.directories === null || CHECK.directories === undefined
            ? "?" : CHECK.directories) + " directories"),
      "summary: " + (s.fail || 0) + " failed, " + (s.reboot || 0) + " pending reboot, " +
        (s.unmeasured || 0) + " unmeasured, " + (s.warn || 0) + " warnings, " +
        (s.pass || 0) + " passed, " + (s.not_applicable || 0) + " n/a, " + (s.note || 0) + " notes",
      "verdict: " + (CHECK.verdict || "?"),
      ""
    ];
    (CHECK.checks || []).forEach(function (c) {
      if (!isShown(c.verdict)) return;
      lines.push("[" + String(c.verdict).toUpperCase() + "] " + c.name + " (" + c.section + ")");
      if (c.owner) lines.push("  from: " + c.owner);
      // BOTH label formats: audit.rs writes "uid N (hidden)", doctor.rs writes
      // "hidden uid N". `runCheck` does not set NM_REDACT_HIDE_LIST, so the real appid is in
      // the JSON and this is the only thing standing between it and a pasted bug report.
      lines.push("  measured: " + redactUids(c.evidence));
      if (c.meaning) lines.push("  means: " + redactUids(c.meaning));
      lines.push("");
    });
    const text = lines.join("\n");
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (e) { ok = false; }
    done();
    if (ok) toast("Report copied.");
    else {
      $("auditout").textContent = text;
      const d = $("auditout").closest("details");
      if (d) d.open = true;
      $("devtools").open = true;
      toast("Clipboard unavailable - the report is in Raw report, ready to select.");
    }
  }

  function _healthShow(txt) { const o = $("healthout"); o.classList.remove("u-hide"); o.textContent = txt.trim() || "(no output)"; }

  async function runSnapshot(btn) {
    const had = (await exec("[ -f /data/adb/nomount/snapshot.txt ] && echo 1 || echo 0")).stdout.trim() === "1";
    if (had && !(await confirmAction(
      "Replace the saved baseline?",
      "Verify compares this device against the snapshot you took when you were happy with it. " +
      "A new one overwrites that reference with today's state - including anything that has " +
      "drifted since - and the old baseline cannot be recovered.",
      "Replace"))) return;
    const done = busy(btn, "Saving...");
    const r = await nm("snapshot");
    _healthShow((r.stdout || "") + (r.stderr || ""));
    toast(r.errno === 0 ? "Snapshot saved as baseline" : "Snapshot failed", r.errno === 0 ? "ok" : "bad");
    done();
  }
  async function runVerify(btn) {
    const done = busy(btn, "Verifying...");
    const r = await nm("verify");
    const txt = (r.stdout || "") + (r.stderr || "");
    _healthShow(txt);
    if (r.errno !== 0 || !txt.trim()) toast("Verify did not run", "bad");
    else if (/DRIFT/.test(txt)) toast("Drift from snapshot - see output", "bad");
    else if (/no snapshot yet/.test(txt)) toast("No baseline yet - take a snapshot first", "");
    else if (/no drift/.test(txt)) toast("Matches snapshot", "ok");
    else toast("Verify gave no verdict - see output", "");
    done();
  }
  async function runExport(btn) {
    if (!(await confirmAction(
      "Write diagnostics to /sdcard/Download?",
      "Any app with storage permission can read that folder. The check report, the fingerprint, " +
      "your rule list and your mount table go there. The apps you hide from, and what is being " +
      "spoofed, are deliberately left out of a shared destination.",
      "Export"))) return;
    const done = busy(btn, "Exporting...");
    const r = await nm("export");
    const txt = (r.stdout || "") + (r.stderr || "");
    _healthShow(txt);
    const path = (txt.match(/exported to (\S+)/) || [])[1];
    toast(path ? "Exported to " + path : "Export failed", path ? "ok" : "bad");
    done();
  }

  async function refreshIncident() {
    const r = await exec("cat /data/adb/nomount/incident.log 2>/dev/null");
    const txt = (r.stdout || "").trim();
    const card = $("incidentcard");
    if (!txt) {
      card.classList.add("u-hide");
      const w = $("incwarn");
      if (w) w.hidden = true;
      return;
    }
    card.classList.remove("u-hide");
    $("incidentout").textContent = txt;
    const el = $("incwarn");
    if (el) {
      const dr = await exec("[ -e /data/adb/nomount/disabled ] && echo 1 || echo 0");
      const off = ((dr && dr.stdout) || "").trim() === "1";
      const btn = '<button class="act u-btn-mid" onclick="openDetail()">'
        + 'See what happened</button>';
      el.hidden = false;
      el.innerHTML = off
        ? "\u26a0\ufe0f The bootloop guard tripped and disabled the Suite. " +
          "<b>Nothing is being injected</b> until you re-arm it. " + btn
        : "\u26a0\ufe0f An earlier boot recorded an incident. The Suite is running now \u2014 " +
          "this is a saved record, not current state. " + btn;
    }
  }
  async function clearIncident(btn) {
    if (!(await confirmAction(
      "Delete the incident record?",
      "The saved crash from the boot that disabled the Suite is removed for good. It is the only " +
      "copy, and it usually names the file that caused the failure.",
      "Delete"))) return;
    { const el = $("incwarn"); if (el) el.hidden = true; }
    btn.disabled = true;
    await exec("rm -f /data/adb/nomount/incident.log");
    toast("Incident record cleared", "ok");
    btn.disabled = false; refreshIncident();
  }
