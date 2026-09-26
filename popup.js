/* Aegis Lens popup: page introspection, scan control, findings UI. */
"use strict";

const $ = (id) => document.getElementById(id);

/* Runs in the page's isolated world via chrome.scripting. Must be self-contained. */
function extractPage() {
  const forms = [...document.forms].map((f) => ({
    action: f.action || location.href,
    method: (f.method || "get").toLowerCase(),
    inputs: [...f.elements]
      .filter((el) => el.name && !/^(submit|button|image|file|reset)$/i.test(el.type || ""))
      .map((el) => ({ name: el.name, type: (el.type || "text").toLowerCase() })),
  }));
  const qparams = [...new URLSearchParams(location.search).keys()];
  return { url: location.href, title: document.title, forms, qparams };
}

function buildPoints(page) {
  const points = [];
  const seen = new Set();
  const add = (method, url, params) => {
    if (!params.length) return;
    let u;
    try { u = new URL(url, page.url); } catch { return; }
    if (!/^https?:$/.test(u.protocol)) return;
    const key = method + "|" + u.origin + u.pathname + "|" + [...params].sort().join(",");
    if (seen.has(key)) return;
    seen.add(key);
    points.push({ method, url: u.origin + u.pathname, params });
  };
  if (page.qparams.length) add("get", page.url.split(/[?#]/)[0], page.qparams);
  for (const f of page.forms) {
    const names = [...new Set(f.inputs.map((i) => i.name))];
    add(f.method === "post" ? "post" : "get", f.action, names);
  }
  return points;
}

let port = null;
let allFindings = [];
let scanMeta = {};

function setNotice(t) {
  const n = $("notice");
  n.textContent = t;
  n.classList.toggle("hidden", !t);
}

function renderFinding(f) {
  const box = $("findings");
  const empty = box.querySelector(".empty");
  if (empty) empty.remove();
  const d = document.createElement("div");
  d.className = "finding " + f.severity;
  const h3 = document.createElement("h3");
  h3.textContent = f.type;
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = `${f.point} · param: ${f.param} · payload: ${f.payload}`;
  const ev = document.createElement("div");
  ev.className = "ev";
  ev.textContent = f.evidence + (f.detail ? "\n" + f.detail : "");
  const sev = document.createElement("div");
  sev.className = "sev";
  sev.textContent = f.severity;
  d.append(sev, h3, meta, ev);
  box.prepend(d);
  $("find-count").textContent = String(allFindings.length);
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || "";
  $("tab-url").textContent = url;
  if (!/^https?:/.test(url)) {
    setNotice("Open a regular http(s) page to scan — browser and extension pages can't be probed.");
    return;
  }
  let page;
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: extractPage });
    page = res.result;
  } catch (e) {
    setNotice("Couldn't read this page (it may block script injection).");
    return;
  }
  const points = buildPoints(page);
  const nParams = points.reduce((a, p) => a + p.params.length, 0);
  $("stat-forms").textContent = page.forms.length;
  $("stat-params").textContent = page.qparams.length;
  $("stat-points").textContent = nParams;
  $("page-info").classList.remove("hidden");
  scanMeta = { page: { url: page.url, points }, tabId: tab.id };
  if (!points.length) {
    setNotice("No testable inputs found — this page has no forms or URL parameters.");
    return;
  }
  $("scan-btn").disabled = !$("consent").checked;
}

$("consent").addEventListener("change", (e) => {
  if (scanMeta.page) $("scan-btn").disabled = !e.target.checked;
});

$("scan-btn").addEventListener("click", () => {
  allFindings = [];
  $("findings").innerHTML = '<p class="empty">Scanning&hellip;</p>';
  $("find-count").textContent = "0";
  $("results-card").classList.remove("hidden");
  $("progress").classList.remove("hidden");
  $("scan-btn").classList.add("hidden");
  $("stop-btn").classList.remove("hidden");
  setNotice("");
  const opts = { sqli: $("opt-sqli").checked, xss: $("opt-xss").checked, ssti: $("opt-ssti").checked, headers: $("opt-headers").checked, cve: $("opt-cve").checked };
  const level = parseInt($("level").value, 10) || 1;
  port = chrome.runtime.connect({ name: "aegis-scan" });
  port.onMessage.addListener((m) => {
    if (m.type === "progress") {
      const pct = m.total ? Math.min(100, (m.sent / m.total) * 100) : 0;
      $("bar-fill").style.width = pct.toFixed(1) + "%";
      $("progress-text").textContent = `${m.sent} / ${m.total} requests`;
    } else if (m.type === "finding") {
      allFindings.push(m.finding);
      renderFinding(m.finding);
    } else if (m.type === "done") {
      endScan(m);
    }
  });
  port.postMessage({ type: "start", page: scanMeta.page, opts, level });
});

function endScan(m) {
  $("scan-btn").classList.remove("hidden");
  $("stop-btn").classList.add("hidden");
  $("bar-fill").style.width = "100%";
  const secs = (m.ms / 1000).toFixed(1);
  $("progress-text").textContent =
    `${m.requests} requests in ${secs}s · ${allFindings.length} finding(s)` + (m.stopped ? " · stopped" : "");
  if (m.error) setNotice("Scan ended early: " + m.error);
  else if (!allFindings.length) {
    $("findings").innerHTML = '<p class="empty">Clean — no issues detected with these probes.</p>';
  }
  port = null;
}

$("stop-btn").addEventListener("click", () => {
  if (port) port.postMessage({ type: "stop" });
});

$("export-btn").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify({
    tool: "aegis-lens", version: "1.1.0",
    target: scanMeta.page?.url, exported: new Date().toISOString(),
    findings: allFindings,
  }, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "aegis-lens-findings.json";
  a.click();
  URL.revokeObjectURL(a.href);
});

init();
