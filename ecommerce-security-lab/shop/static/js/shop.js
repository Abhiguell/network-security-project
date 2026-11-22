/* LabMart front-end: live admin alerts, incident banner, simple canvas charts.
   Server text is always inserted with textContent (never innerHTML) to prevent XSS. */
(function () {
  "use strict";
  const $ = (s) => document.querySelector(s);

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function toast(title, msg, level) {
    const box = $("#toasts");
    if (!box) return;
    const t = el("div", "toast " + (level || ""));
    t.append(el("b", "", title), el("span", "", msg));
    box.appendChild(t);
    setTimeout(() => t.remove(), 8000);
  }

  // ---------------- simulated phishing lure: "Ignore" hides it for this browser tab
  const lure = $("#phishLure");
  if (lure) {
    const key = "lure-dismissed-" + lure.dataset.id;
    let dismissed = false;
    try { dismissed = sessionStorage.getItem(key) === "1"; } catch (e) { /* storage blocked */ }
    if (dismissed) lure.remove();
    else $("#lureClose").addEventListener("click", () => {
      try { sessionStorage.setItem(key, "1"); } catch (e) { /* ignore */ }
      lure.remove();
    });
  }

  // ---------------- live alerts + incident banner (admin pages) ----------------
  const admin = $("#adminApp");
  if (admin) {
    let lastId = parseInt(admin.dataset.lastId || "0", 10);
    const poll = async () => {
      try {
        const r = await fetch(admin.dataset.alerts + "?since=" + lastId, { credentials: "same-origin" });
        if (!r.ok) return;
        const d = await r.json();
        d.alerts.forEach((a) => toast((a.source === "simulation" ? "🧪 " : "⚠ ") + a.category + " · " + a.severity.toUpperCase(), a.message, a.severity));
        lastId = d.last_id;
        $("#navAlerts").textContent = d.open || "";
        $("#navIncidents").textContent = d.incidents.length || "";
        const pill = $("#statusPill");
        pill.className = "status-pill status-" + d.status.level;
        pill.textContent = d.status.label;
        const banner = $("#incidentBanner"), list = $("#incidentList");
        list.replaceChildren(...d.incidents.map((i) => {
          const li = el("li");
          li.append(el("b", "", i.kind.toUpperCase() + ": "), document.createTextNode(i.title + " "), el("span", "", "(" + i.ts.slice(11) + ")"));
          return li;
        }));
        banner.classList.toggle("hidden", d.incidents.length === 0);
      } catch (e) { /* server restarting: try again */ }
    };
    setInterval(poll, 3000);
  }

  // ---------------- charts ----------------
  function bars(canvas, labels, values, colors, fmt) {
    const ratio = window.devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * ratio; canvas.height = h * ratio;
    const ctx = canvas.getContext("2d");
    ctx.scale(ratio, ratio);
    ctx.font = "11px Segoe UI, sans-serif";
    const pad = { l: 10, r: 10, t: 18, b: 22 }, max = Math.max(1, ...values);
    const slot = (w - pad.l - pad.r) / labels.length;
    labels.forEach((lab, i) => {
      const bh = (h - pad.t - pad.b) * (values[i] / max), x = pad.l + i * slot + slot * 0.18;
      ctx.fillStyle = colors[i % colors.length];
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(x, h - pad.b - bh, slot * 0.64, bh, 6); else ctx.rect(x, h - pad.b - bh, slot * 0.64, bh);
      ctx.fill();
      ctx.fillStyle = "#6b7280"; ctx.textAlign = "center";
      ctx.fillText(lab, x + slot * 0.32, h - 6);
      if (values[i]) { ctx.fillStyle = "#111827"; ctx.fillText(fmt ? fmt(values[i]) : values[i], x + slot * 0.32, h - pad.b - bh - 5); }
    });
  }
  const charts = $("#charts");
  if (charts) {
    const draw = async () => {
      const r = await fetch(charts.dataset.api, { credentials: "same-origin" });
      if (!r.ok) return;
      const d = await r.json();
      bars($("#chartSales"), d.days, d.sales, ["#f97316"], (v) => (v >= 1e6 ? (v / 1e6).toFixed(1) + "jt" : Math.round(v / 1e3) + "rb"));
      bars($("#chartSev"), d.severity.labels, d.severity.values, ["#3b82f6", "#6366f1", "#f59e0b", "#ea580c", "#dc2626"]);
    };
    draw();
    setInterval(draw, 10000);
    window.addEventListener("resize", draw);
  }
})();
