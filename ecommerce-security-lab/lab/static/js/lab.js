/* CyberSim Lab front-end.
   - connection monitor (store API status)
   - module runner: start -> poll run -> animated execution log -> results panel
   All server text is inserted with textContent (never innerHTML) to prevent XSS. */
(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  const csrf = () => ($('meta[name="csrf-token"]') || {}).content || "";
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => (k === "class" ? (n.className = v) : n.setAttribute(k, v)));
    kids.flat().forEach((k) => k !== null && k !== undefined && n.appendChild(typeof k === "object" ? k : document.createTextNode(String(k))));
    return n;
  }
  async function api(url, method, body) {
    const r = await fetch(url, {
      method: method || "GET", credentials: "same-origin",
      headers: { "X-CSRF-Token": csrf(), "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : (method === "POST" ? "{}" : undefined),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.message || data.error || "HTTP " + r.status);
    return data;
  }
  function toast(title, msg, level) {
    const t = el("div", { class: "toast " + (level || "") }, el("div", { class: "t-title" }, title), el("div", { class: "t-msg" }, msg));
    $("#toasts").appendChild(t);
    setTimeout(() => t.remove(), 6000);
  }
  const rp = (v) => "Rp " + Number(v || 0).toLocaleString("id-ID");

  const toggle = $("#sidebarToggle");
  if (toggle) toggle.addEventListener("click", () => $("#sidebar").classList.toggle("open"));

  // ------------------------------------------------ connection monitor
  const root = $("#labRoot");
  if (root && root.dataset.status) {
    const check = async () => {
      let d;
      try { d = await api(root.dataset.status); } catch (e) { d = { online: false, error: e.message }; }
      const pill = $("#connPill");
      if (pill) {
        pill.className = "status-pill " + (d.online ? "status-ok" : "status-danger");
        pill.textContent = d.online ? "STORE API ONLINE" : "STORE OFFLINE";
      }
      if ($("#cDot")) {
        $("#cDot").className = "dot " + (d.online ? "on" : "off");
        $("#cText").textContent = d.online ? (d.shop.sim_api_enabled ? "Online · authenticated (HMAC)" : "Online · API disabled by store") : "Unreachable";
        $("#cError").textContent = d.online ? "" : "⚠ " + (d.error || "") + " Start the store with: python run_shop.py";
        if (d.online) {
          $("#cRecords").textContent = d.shop.synthetic_records;
          $("#cIncidents").textContent = d.shop.open_incidents.length;
          const t = $("#cThreat");
          t.className = "status-pill status-" + d.shop.security_status.level;
          t.textContent = d.shop.security_status.label;
        }
      }
    };
    check();
    setInterval(check, 5000);
  }

  // ------------------------------------------------ shared run player
  function makeRunner(app) {
    const term = $("#term"), status = $("#runStatus");
    let queue = [], playing = false;
    const setStatus = (s) => {
      status.textContent = s;
      status.className = "badge-s " + ({ running: "sev-critical", completed: "tag-ok", stopped: "sev-medium", failed: "tag-bad" }[s] || "sev-info");
    };
    const play = async () => {
      if (playing) return;
      playing = true;
      while (queue.length) {
        const l = queue.shift();
        term.appendChild(el("div", { class: "line " + l.level }, "[" + l.ts.slice(11) + "] " + l.message));
        term.scrollTop = term.scrollHeight;
        await sleep(l.level === "warn" ? 120 : 260);
      }
      playing = false;
    };
    // Poll a run until it ends; onUpdate(result) is called on every poll.
    async function follow(runId, onUpdate) {
      let after = 0, run;
      setStatus("running");
      while (true) {
        run = await api(app.dataset.runs + runId + "?after=" + after);
        if (run.logs.length) { after = run.logs[run.logs.length - 1].id; queue.push(...run.logs); play(); }
        if (onUpdate) onUpdate(run);
        if (run.status !== "running") break;
        await sleep(800);
      }
      while (queue.length || playing) await sleep(100);
      setStatus(run.status);
      return run;
    }
    return { term, follow, setStatus, clear: () => { term.replaceChildren(); queue = []; } };
  }

  // ------------------------------------------------ module pages
  const app = $("#moduleApp");
  if (app) {
    const runner = makeRunner(app);
    const results = $("#results");
    const startBtn = $("#startBtn");
    const mod = app.dataset.module;
    const renderers = {};

    // ---- spyware results
    renderers.spyware = (run) => {
      const r = run.result;
      if (!r || !r.records) { if (r && r.error) results.replaceChildren(el("div", { class: "flash flash-danger" }, r.error)); return; }
      const rows = r.records.map((x) => el("tr", {},
        el("td", { class: "mono" }, x.customer_id), el("td", {}, x.full_name), el("td", { class: "mono break" }, x.email),
        el("td", { class: "mono" }, x.phone), el("td", { class: "small" }, x.address), el("td", { class: "mono" }, x.orders),
        el("td", { class: "mono" }, rp(x.total_spent))));
      results.replaceChildren(
        el("div", { class: "grid grid-3 mb" },
          el("div", {}, el("div", { class: "big-number" }, r.count), el("div", { class: "small muted" }, "synthetic records accessed")),
          el("div", {}, el("div", { class: "big-number", style: "color:var(--warning)" }, (r.bytes / 1024).toFixed(1) + " KB"), el("div", { class: "small muted" }, "data exposed")),
          el("div", {}, el("div", { class: "big-number", style: "color:var(--ok)" }, r.real_customers_protected), el("div", { class: "small muted" }, "real accounts protected"))),
        el("div", { class: "flash flash-warning small mb" }, "⚠ SIMULATED EXPOSURE · synthetic test records only. Passwords: " + r.records[0].password + " · Payment data: " + r.records[0].payment_data),
        el("div", { class: "table-wrap", style: "max-height:420px;overflow:auto" }, el("table", {},
          el("thead", {}, el("tr", {}, ...["ID", "Name", "Email", "Phone", "Address", "Orders", "Spent"].map((h) => el("th", {}, h)))),
          el("tbody", {}, rows))));
    };

    // ---- ransomware results
    const renderFiles = (d) => {
      const files = d.files || [];
      const head = d.attacked
        ? el("div", { class: "flash flash-danger mb" }, "🔒 FILES LOCKED (SIMULATED) · Victim ID " + d.state.victim_id + " · Ransom " + d.state.ransom + " · Wallet " + d.state.wallet)
        : el("div", { class: "flash flash-success mb" }, "✓ Sandbox clean: " + files.length + " files intact" + (d.integrity_ok !== undefined ? (d.integrity_ok ? " · integrity check PASSED (hashes identical)" : " · integrity check FAILED") : ""));
      results.replaceChildren(head, el("div", { class: "lock-grid" }, ...files.map((f) =>
        el("div", { class: "lock-tile" + (f.locked ? " locked" : "") }, (f.locked ? "🔒 " : "📄 ") + f.display_name,
          el("div", { class: "h" }, "SHA-256 " + f.sha256.slice(0, 20) + "… · " + f.size + " B")))));
    };
    renderers.ransomware = (run) => {
      if (run.result && run.result.files) renderFiles(run.result);
      else if (run.result && run.result.error) results.replaceChildren(el("div", { class: "flash flash-danger" }, run.result.error));
    };

    // ---- trojan results
    renderers.trojan = (run) => {
      const r = run.result || {};
      if (r.error) { results.replaceChildren(el("div", { class: "flash flash-danger" }, r.error)); return; }
      const traffic = r.traffic || [];
      if (!traffic.length) return;
      const beacons = traffic.filter((t) => t.kind === "beacon");
      const bytes = traffic.reduce((a, t) => a + t.bytes, 0);
      const detected = traffic.some((t) => t.detected);
      results.replaceChildren(
        el("div", { class: "grid grid-3 mb" },
          el("div", {}, el("div", { class: "big-number", style: "color:var(--accent-2)" }, beacons.length), el("div", { class: "small muted" }, "C2 beacons sent")),
          el("div", {}, el("div", { class: "big-number", style: "color:var(--warning)" }, bytes + " B"), el("div", { class: "small muted" }, "outbound traffic")),
          el("div", {}, el("div", { class: "big-number", style: "color:" + (detected ? "var(--critical)" : "var(--muted)") }, detected ? "YES" : "not yet"), el("div", { class: "small muted" }, "detected by store IDS"))),
        el("p", { class: "small muted" }, "Bot " + r.bot_id + " · interval " + r.interval + " s · destination " + (traffic[0] || {}).dest),
        el("div", { class: "table-wrap", style: "max-height:380px;overflow:auto" }, el("table", {},
          el("thead", {}, el("tr", {}, ...["Time", "Type", "Seq", "Bytes", "C2 reply", "IDS"].map((h) => el("th", {}, h)))),
          el("tbody", {}, ...traffic.slice().reverse().map((t) => el("tr", {},
            el("td", { class: "ts" }, t.ts), el("td", {}, el("span", { class: "badge-s " + (t.kind === "exfil" ? "sev-critical" : t.kind === "beacon" ? "sev-high" : "sev-info") }, t.kind)),
            el("td", { class: "mono" }, t.seq), el("td", { class: "mono" }, t.bytes), el("td", { class: "mono" }, t.reply),
            el("td", {}, t.detected ? el("span", { class: "badge-s sev-critical" }, "flagged") : "-")))))));
    };

    const render = renderers[mod];
    const run = async (url, body) => {
      startBtn.disabled = true;
      runner.clear();
      try {
        const { run_id } = await api(url, "POST", body);
        const stopBtn = $("#stopBtn");
        if (stopBtn) stopBtn.disabled = false;
        const final = await runner.follow(run_id, render);
        if (stopBtn) stopBtn.disabled = true;
        render(final);
        if (final.status === "completed") toast("✓ Simulation finished", "Check the LabMart admin tab for the alerts.", "");
        if (final.status === "failed") toast("✗ Simulation failed", (final.result || {}).error || "See the execution log.", "high");
      } catch (e) {
        runner.term.appendChild(el("div", { class: "line error" }, "✗ " + e.message));
        runner.setStatus("failed");
      }
      startBtn.disabled = false;
    };

    startBtn.addEventListener("click", () => {
      const body = mod === "trojan" ? { interval: +$("#interval").value, count: +$("#count").value } : {};
      run(app.dataset.start, body);
    });
    if ($("#clearBtn")) $("#clearBtn").addEventListener("click", () => { results.replaceChildren(el("div", { class: "results-empty" }, "No results yet.")); runner.clear(); runner.setStatus("idle"); });
    if ($("#resetBtn")) $("#resetBtn").addEventListener("click", () => run(app.dataset.reset));
    if ($("#stopBtn")) $("#stopBtn").addEventListener("click", async () => {
      try { await api(app.dataset.stop, "POST"); toast("■ Stop requested", "The trojan will stop before its next beacon.", ""); } catch (e) { toast("Error", e.message, "high"); }
    });
    if (mod === "ransomware") {
      api(app.dataset.state).then(renderFiles).catch((e) =>
        results.replaceChildren(el("div", { class: "flash flash-danger" }, "Cannot read sandbox: " + e.message)));
    }
  }

  // ------------------------------------------------ dashboard reset
  const resetAll = $("#resetAll");
  if (resetAll) {
    resetAll.addEventListener("click", async () => {
      if (!window.confirm("Reset the simulation environment? This resolves incidents, restores the sandbox and acknowledges simulation alerts on the store. Real data is not touched.")) return;
      const log = $("#resetLog");
      log.classList.remove("hidden");
      log.replaceChildren();
      resetAll.disabled = true;
      try {
        const { run_id } = await api(resetAll.dataset.url, "POST");
        let after = 0, r;
        do {
          await sleep(500);
          r = await api(resetAll.dataset.runs + run_id + "?after=" + after);
          r.logs.forEach((l) => { after = l.id; log.appendChild(el("div", { class: "line " + l.level }, l.message)); });
        } while (r.status === "running");
        toast("↺ Environment reset", "Store incidents resolved and sandbox restored.", "");
        setTimeout(() => location.reload(), 1500);
      } catch (e) {
        log.appendChild(el("div", { class: "line error" }, e.message));
      }
      resetAll.disabled = false;
    });
  }
})();
