/* Aegis Lens scan engine (MV3 service worker).
   Techniques ported from the aegis Python scanner + UNION/SSTI/CVE modules.
   All probes are non-destructive detection only. */
importScripts("payloads.js", "cves.js");
"use strict";

const BENIGN = "aegislens0";
const MAX_REQ = 500;
const REQ_DELAY_MS = 120;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rand = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");

let sent = 0;
let stopFlag = false;

async function req(url, { method = "GET", body = null } = {}) {
  if (stopFlag) throw new Error("stopped");
  if (sent >= MAX_REQ) throw new Error("request cap reached");
  sent++;
  await sleep(REQ_DELAY_MS);
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 12000);
  try {
    const r = await fetch(url, {
      method, body, signal: ctl.signal,
      redirect: "follow", credentials: "omit",
      headers: body ? { "Content-Type": "application/x-www-form-urlencoded" } : {},
    });
    const text = await r.text().catch(() => "");
    const headers = {};
    r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: r.status, text, headers, url: r.url };
  } finally {
    clearTimeout(t);
  }
}

/* Manual query building so evasion transforms' %XX sequences survive. */
function buildRequest(point, name, value) {
  const params = {};
  for (const p of point.params) params[p] = p === name ? value : BENIGN;
  const qs = Object.entries(params).map(([k, v]) => enc(k) + "=" + enc(v)).join("&");
  if (point.method === "get") return { url: point.url + "?" + qs, method: "GET", body: null };
  return { url: point.url, method: "POST", body: qs };
}

async function sendProbe(point, name, value) {
  const b = buildRequest(point, name, value);
  return req(b.url, { method: b.method, body: b.body });
}

function lenDiff(a, b) {
  return Math.abs(a.length - b.length) / Math.max(a.length, b.length, 1);
}

function snippet(text, idx, len = 120) {
  const s = Math.max(0, idx - 40);
  return text.slice(s, s + len).replace(/\s+/g, " ").trim().slice(0, 160);
}

function matchError(text) {
  for (const [re, dbms] of ERROR_SIGS) {
    const m = re.exec(text);
    if (m) return { dbms, hit: m[0].slice(0, 90) };
  }
  return null;
}

/* Port of aegis _context: strip the probe's own pre-canary markup first. */
function xssContext(html, idx, pre) {
  let before = html.slice(0, idx);
  if (pre && before.endsWith(pre)) before = before.slice(0, -pre.length);
  const low = before.toLowerCase();
  if (low.lastIndexOf("<script") > low.lastIndexOf("</script>")) return "javascript";
  if (before.lastIndexOf("<") > before.lastIndexOf(">")) return "attribute";
  return "html";
}

/* ---------------- SQLi: error -> evasion -> boolean -> union -------- */

async function scanSqli(point, name, base, level, emit, label) {
  const errFinding = (probe, transform, sig) => ({
    severity: "HIGH", type: "SQL injection (error-based)",
    point: label, param: name, payload: probe,
    evidence: `${sig.dbms} signature: ${sig.hit}` + (transform ? ` (bypass: ${transform})` : ""),
    detail: "A quote probe triggered a DBMS error message — input reaches a SQL query." +
      (transform ? ` The "${transform}" evasion transform bypassed the filter.` : ""),
  });
  let found = false;

  for (const probe of ERROR_PROBES) {                       // pass 1: standard
    if (stopFlag) return true;
    try {
      const r = await sendProbe(point, name, probe);
      emit({ progress: true });
      const sig = matchError(r.text);
      if (sig) { emit({ finding: errFinding(probe, null, sig) }); found = true; break; }
    } catch { emit({ progress: true }); }
  }
  if (!found && level >= 2) {                               // pass 2: WAF bypass
    for (const tname of LEVEL_TRANSFORMS[level]) {
      for (const bp of EVADE_BASE) {
        if (stopFlag) return true;
        let probe;
        try { probe = TRANSFORMS[tname](bp); } catch { continue; }
        if (probe === bp) continue;
        try {
          const r = await sendProbe(point, name, probe);
          emit({ progress: true });
          const sig = matchError(r.text);
          if (sig) { emit({ finding: errFinding(probe, tname, sig) }); found = true; break; }
        } catch { emit({ progress: true }); }
      }
      if (found) break;
    }
  }
  if (!found) {                                             // boolean-blind
    for (const [pT, pF] of BOOLEAN_PAIRS) {
      if (stopFlag) return true;
      try {
        const rT = await sendProbe(point, name, pT); emit({ progress: true });
        const rF = await sendProbe(point, name, pF); emit({ progress: true });
        const trueSame = lenDiff(rT.text, base.text) < 0.05 && rT.status === base.status;
        const falseDiff = lenDiff(rF.text, base.text) > 0.15 || rF.status !== base.status;
        if (trueSame && falseDiff) {
          emit({
            finding: {
              severity: "MEDIUM", type: "SQL injection (boolean-blind, possible)",
              point: label, param: name, payload: `${pT} / ${pF}`,
              evidence: `TRUE-resp ~ baseline, FALSE-resp diverged (len Δ ${(lenDiff(rF.text, base.text) * 100).toFixed(1)}%)`,
              detail: "Differential response to boolean probes suggests the query result influences the page. Verify manually.",
            },
          });
          found = true; break;
        }
      } catch { emit({ progress: true }); }
    }
  }
  if (!found) {                                             // UNION-based
    for (const u of UNION_PROBES) {
      if (stopFlag) return true;
      const canary = "aegisu" + rand(3);
      const probe = u.build(canary);
      try {
        const r = await sendProbe(point, name, probe); emit({ progress: true });
        if (r.text.includes(canary) && !r.text.includes(probe)) {
          emit({
            finding: {
              severity: "HIGH", type: "SQL injection (UNION-based)",
              point: label, param: name, payload: probe,
              evidence: `UNION-selected canary "${canary}" rendered in response (${u.cols} column probe)`,
              detail: "A UNION SELECT injected data into the page — arbitrary SELECTs are likely possible. Verify manually.",
            },
          });
          found = true; break;
        }
      } catch { emit({ progress: true }); }
    }
  }
  return found;
}

/* ---------------- XSS: full 22-probe catalogue --------------------- */

async function scanXss(point, name, level, emit, label) {
  const probes = XSS_PROBES.slice(0, XSS_LEVEL_CUTOFF[Math.min(level, 3)]);
  for (const p of probes) {
    if (stopFlag) return;
    const canary = "aegis" + rand(3);
    const payload = p.t.replace("{C}", canary);
    let r;
    try { r = await sendProbe(point, name, payload); } catch { emit({ progress: true }); continue; }
    emit({ progress: true });
    if (!r.text.includes(payload)) continue;                // encoded, stripped or dropped
    const idx = r.text.indexOf(canary);
    const ctx = xssContext(r.text, idx, p.t.split("{C}")[0]);
    let severity = null;
    if (p.kinds.includes("tag") && (ctx === "html" || ctx === "attribute")) severity = "HIGH";
    else if (p.kinds.includes("tag") && ctx === "javascript") severity = "MEDIUM";
    else if (p.kinds.length === 1 && p.kinds[0] === "js" && ctx === "javascript") severity = "HIGH";
    else continue;                                          // reflected where it can't execute
    emit({
      finding: {
        severity, type: "Reflected XSS",
        point: label, param: name, payload,
        evidence: `probe "${p.name}" reflected verbatim in ${ctx} context: …${snippet(r.text, idx)}…`,
        detail: p.name.startsWith("evade-")
          ? `Filter-evasion variant "${p.name}" bypassed output handling.`
          : "Input reflected without encoding in an executable context.",
      },
    });
    break; // one solid proof per parameter is enough
  }
}

/* ---------------- SSTI ---------------------------------------------- */

async function scanSsti(point, name, base, emit, label) {
  if (base.text.includes(SSTI_EXPECTED)) return;
  for (const probe of SSTI_PROBES) {
    if (stopFlag) return;
    try {
      const r = await sendProbe(point, name, probe); emit({ progress: true });
      if (r.text.includes(SSTI_EXPECTED)) {
        emit({
          finding: {
            severity: "MEDIUM", type: "Server-side template injection (possible)",
            point: label, param: name, payload: probe,
            evidence: `template math evaluated → ${SSTI_EXPECTED} in response`,
            detail: "The template engine evaluated injected math. Verify manually before escalating.",
          },
        });
        break;
      }
    } catch { emit({ progress: true }); }
  }
}

/* ---------------- headers + CVE banners + exposed paths ------------- */

function headerChecks(r, pageUrl, emit) {
  const h = r.headers;
  const host = new URL(pageUrl).host;
  const isHttps = pageUrl.startsWith("https");
  const checks = [
    [!h["content-security-policy"], "MEDIUM", "Missing Content-Security-Policy",
     "No CSP header — XSS and injection mitigations are weaker."],
    [!h["x-frame-options"] && !(h["content-security-policy"] || "").includes("frame-ancestors"), "LOW",
     "Missing clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors is set."],
    [isHttps && !h["strict-transport-security"], "LOW", "Missing Strict-Transport-Security",
     "HSTS not set — first-visit SSL-stripping attacks are possible."],
    [!h["x-content-type-options"], "INFO", "Missing X-Content-Type-Options",
     "Without nosniff, browsers may MIME-sniff responses."],
    [!h["referrer-policy"], "INFO", "Missing Referrer-Policy", "Referrer leakage policy not defined."],
  ];
  for (const [bad, sev, title, detail] of checks) {
    if (bad) emit({ finding: { severity: sev, type: "Security header", point: host, param: "-", payload: "-", evidence: title, detail } });
  }
  const server = h["server"] || h["x-powered-by"];
  if (server && /\d+\.\d+/.test(server)) {
    emit({ finding: { severity: "INFO", type: "Version disclosure", point: host, param: "-", payload: "-", evidence: `Banner: ${server.slice(0, 80)}`, detail: "Version banners help attackers fingerprint the stack." } });
  }
}

async function scanPage(pageUrl, opts, emit) {
  let r;
  try { r = await req(pageUrl, { method: "GET" }); } catch { return; }
  emit({ progress: true });
  const host = new URL(pageUrl).host;
  if (opts.headers) headerChecks(r, pageUrl, emit);
  if (opts.cve) {
    checkCveBanners(r.headers, r.text, emit, host);
    const origin = new URL(pageUrl).origin;
    for (const ep of EXPOSED_PATHS) {
      if (stopFlag) return;
      try {
        const pr = await req(origin + ep.path, { method: "GET" });
        emit({ progress: true });
        if (pr.status === 200 && ep.match.test(pr.text)) {
          emit({
            finding: {
              severity: ep.severity, type: "Exposed sensitive path",
              point: host, param: "-", payload: ep.path,
              evidence: `${ep.title}: ${origin}${ep.path} is reachable`,
              detail: ep.detail,
            },
          });
        }
      } catch { emit({ progress: true }); }
    }
  }
}

async function scanPoint(point, opts, level, emit) {
  const label = `${point.method.toUpperCase()} ${new URL(point.url).pathname} [${point.params.join(",")}]`;
  for (const name of point.params) {
    if (stopFlag) return;
    let base;
    try { base = await sendProbe(point, name, BENIGN); } catch { emit({ progress: true }); continue; }
    emit({ progress: true });
    if (opts.sqli) await scanSqli(point, name, base, level, emit, label);
    if (opts.xss) await scanXss(point, name, level, emit, label);
    if (opts.ssti) await scanSsti(point, name, base, emit, label);
  }
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "aegis-scan") return;
  port.onMessage.addListener(async (msg) => {
    if (msg.type === "stop") { stopFlag = true; return; }
    if (msg.type !== "start") return;
    sent = 0; stopFlag = false;
    const { page, opts, level } = msg;
    const lv = Math.min(Math.max(level || 1, 1), 3);
    const seen = new Set();
    const findings = [];
    const total = planCounts(page.points.reduce((a, p) => a + p.params.length, 0), opts, lv);
    const emit = (m) => {
      if (m.finding) {
        const key = m.finding.type + "|" + m.finding.point + "|" + m.finding.param + "|" + m.finding.evidence;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({ ...m.finding, at: new Date().toISOString() });
        port.postMessage({ type: "finding", finding: findings[findings.length - 1], count: findings.length });
      } else if (m.progress) {
        port.postMessage({ type: "progress", sent, total });
      }
    };
    const t0 = Date.now();
    try {
      if (opts.headers || opts.cve) await scanPage(page.url, opts, emit);
      for (const point of page.points) {
        if (stopFlag) break;
        await scanPoint(point, opts, lv, emit);
      }
      port.postMessage({ type: "done", stopped: stopFlag, requests: sent, ms: Date.now() - t0, findings });
    } catch (e) {
      port.postMessage({ type: "done", stopped: stopFlag, error: String((e && e.message) || e), requests: sent, ms: Date.now() - t0, findings });
    }
  });
});
