/* Aegis Lens — in-browser active scan engine (MV3 service worker).
   Detection ideas ported from the aegis Python scanner: DBMS error
   signatures, boolean-differential probes, canary-based reflection checks.
   All probes are non-destructive detection only. */
"use strict";

const SQLI_PROBES = ["'", '"', "')", "' OR '1'='1"];
const BOOLEAN_PAIRS = [
  ["' AND '1'='1", "' AND '1'='2"],
  ["' AND 1=1-- -", "' AND 1=2-- -"],
];
// [regex, dbms label] — response body is scanned for these after quote probes
const ERROR_SIGS = [
  [/you have an error in your sql syntax/i, "MySQL"],
  [/warning:\s*mysql/i, "MySQL"],
  [/mysqli?_[a-z_]+\(\)/i, "MySQL"],
  [/mysql server version/i, "MySQL"],
  [/mariadb server version/i, "MariaDB"],
  [/pg_query\(\)|pg_exec\(\)/i, "PostgreSQL"],
  [/unterminated quoted string/i, "PostgreSQL"],
  [/unclosed quotation mark/i, "MSSQL"],
  [/microsoft ole db provider for sql server/i, "MSSQL"],
  [/odbc sql server driver/i, "MSSQL"],
  [/ora-01756|ora-00933|quoted string not properly terminated/i, "Oracle"],
  [/sqlite3?::|sqlite error/i, "SQLite"],
  [/sql syntax/i, "Generic"],
  [/database error/i, "Generic"],
];
const BENIGN = "aegislens0";
const MAX_REQ = 250;
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

/* Build one request for a test point with a single param overridden. */
function buildRequest(point, name, value) {
  const params = {};
  for (const p of point.params) params[p] = p === name ? value : BENIGN;
  if (point.method === "get") {
    const u = new URL(point.url);
    u.search = "";
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    return { url: u.toString(), method: "GET", body: null };
  }
  const body = new URLSearchParams(params).toString();
  return { url: point.url, method: "POST", body };
}

function lenDiff(a, b) {
  return Math.abs(a.length - b.length) / Math.max(a.length, b.length, 1);
}

function snippet(text, idx, len = 120) {
  const s = Math.max(0, idx - 40);
  return text.slice(s, s + len).replace(/\s+/g, " ").trim().slice(0, 160);
}

/* Where did the canary land? script / event-handler / html / encoded / none */
function classifyReflection(text, canary) {
  const idx = text.indexOf(canary);
  if (idx === -1) {
    // check HTML-encoded reflection
    const enc = canary.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    if (enc !== canary && text.indexOf(enc) !== -1) return { where: "encoded", idx: text.indexOf(enc) };
    return { where: "none", idx: -1 };
  }
  const win = text.slice(Math.max(0, idx - 400), idx + canary.length + 40).toLowerCase();
  const lastScript = win.lastIndexOf("<script");
  const lastScriptEnd = win.lastIndexOf("</script>");
  if (lastScript > lastScriptEnd) return { where: "script", idx };
  const attr = win.match(/on\w+\s*=\s*["']?[^"'>]*$/);
  if (attr) return { where: "event-handler", idx };
  return { where: "html", idx };
}

async function scanPoint(point, opts, emit) {
  const label = `${point.method.toUpperCase()} ${new URL(point.url).pathname} [${point.params.join(",")}]`;
  for (const name of point.params) {
    if (stopFlag) return;
    const bb = buildRequest(point, name, BENIGN);
    const base = await req(bb.url, { method: bb.method, body: bb.body });
    emit({ progress: true });

    // ---- SQLi: error-based ----
    if (opts.sqli) {
      for (const probe of SQLI_PROBES) {
        if (stopFlag) return;
        let r;
        try {
          const b = buildRequest(point, name, probe);
          r = await req(b.url, { method: b.method, body: b.body });
        } catch (e) { emit({ progress: true }); continue; }
        emit({ progress: true });
        for (const [re, dbms] of ERROR_SIGS) {
          const m = r.text.match(re);
          if (m) {
            emit({
              finding: {
                severity: "HIGH", type: "SQL injection (error-based)",
                point: label, param: name, payload: probe,
                evidence: `${dbms} signature: ${m[0].slice(0, 90)}`,
                detail: `A quote probe triggered a ${dbms} error message in the response — user input reaches a SQL query.`,
              },
            });
            break;
          }
        }
      }
      // ---- SQLi: boolean-differential ----
      for (const [pTrue, pFalse] of BOOLEAN_PAIRS) {
        if (stopFlag) return;
        try {
          const bt = buildRequest(point, name, pTrue);
          const bf = buildRequest(point, name, pFalse);
          const rT = await req(bt.url, { method: bt.method, body: bt.body });
          emit({ progress: true });
          const rF = await req(bf.url, { method: bf.method, body: bf.body });
          emit({ progress: true });
          const trueSame = lenDiff(rT.text, base.text) < 0.05 && rT.status === base.status;
          const falseDiff = lenDiff(rF.text, base.text) > 0.15 || rF.status !== base.status;
          if (trueSame && falseDiff) {
            emit({
              finding: {
                severity: "MEDIUM", type: "SQL injection (boolean-blind, possible)",
                point: label, param: name, payload: `${pTrue} / ${pFalse}`,
                evidence: `TRUE-resp ~ baseline, FALSE-resp diverged (len Δ ${(lenDiff(rF.text, base.text) * 100).toFixed(1)}%)`,
                detail: "Differential response to boolean probes suggests the query result influences the page. Verify manually.",
              },
            });
            break;
          }
        } catch (e) { emit({ progress: true }); }
      }
    }

    // ---- XSS: reflected canary ----
    if (opts.xss) {
      const canary = "aegis" + rand(3);
      try {
        const b = buildRequest(point, name, canary);
        const r = await req(b.url, { method: b.method, body: b.body });
        emit({ progress: true });
        const c = classifyReflection(r.text, canary);
        if (c.where === "script" || c.where === "event-handler") {
          emit({
            finding: {
              severity: "HIGH", type: "Reflected XSS (executable context)",
              point: label, param: name, payload: canary,
              evidence: `canary reflected unencoded inside ${c.where}: …${snippet(r.text, c.idx)}…`,
              detail: "Input is reflected into a JavaScript/event-handler context without encoding — likely exploitable.",
            },
          });
        } else if (c.where === "html") {
          // try a real tag-breakout probe
          const canary2 = "aegis" + rand(3);
          const tag = `"><svg onload=${canary2}>`;
          const b2 = buildRequest(point, name, tag);
          const r2 = await req(b2.url, { method: b2.method, body: b2.body });
          emit({ progress: true });
          if (r2.text.includes("<svg") && r2.text.includes(canary2)) {
            emit({
              finding: {
                severity: "HIGH", type: "Reflected XSS (tag injection)",
                point: label, param: name, payload: tag,
                evidence: `unencoded <svg> + canary reflected: …${snippet(r2.text, r2.text.indexOf(canary2))}…`,
                detail: "HTML tag injection reflected unencoded — exploitable reflected XSS.",
              },
            });
          } else {
            emit({
              finding: {
                severity: "LOW", type: "Unencoded reflection",
                point: label, param: name, payload: canary,
                evidence: `canary reflected raw in HTML body: …${snippet(r.text, c.idx)}…`,
                detail: "Input reflects without encoding but no tag breakout confirmed. Verify exploitability manually.",
              },
            });
          }
        }
      } catch (e) { emit({ progress: true }); }
    }
  }
}

async function scanHeaders(pageUrl, emit) {
  let r;
  try {
    r = await req(pageUrl, { method: "GET" });
  } catch (e) { return; }
  emit({ progress: true });
  const h = r.headers;
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
    [!h["referrer-policy"], "INFO", "Missing Referrer-Policy",
     "Referrer leakage policy not defined."],
  ];
  for (const [bad, sev, title, detail] of checks) {
    if (bad) emit({ finding: { severity: sev, type: "Security header", point: new URL(pageUrl).host, param: "-", payload: "-", evidence: title, detail } });
  }
  const server = h["server"] || h["x-powered-by"];
  if (server && /\d+\.\d+/.test(server)) {
    emit({ finding: { severity: "INFO", type: "Version disclosure", point: new URL(pageUrl).host, param: "-", payload: "-", evidence: `Server banner: ${server.slice(0, 80)}`, detail: "Version banners help attackers fingerprint the stack." } });
  }
}

/* Estimate total requests so the popup can show progress. */
function estimateTotal(points, opts) {
  let n = 0;
  for (const p of points) {
    n += p.params.length; // baseline each
    if (opts.sqli) n += p.params.length * (SQLI_PROBES.length + BOOLEAN_PAIRS.length * 2);
    if (opts.xss) n += p.params.length * 2;
  }
  if (opts.headers) n += 1;
  return n;
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "aegis-scan") return;
  port.onMessage.addListener(async (msg) => {
    if (msg.type === "stop") { stopFlag = true; return; }
    if (msg.type !== "start") return;
    sent = 0; stopFlag = false;
    const { page, opts } = msg;
    const seen = new Set();
    const findings = [];
    const emit = (m) => {
      if (m.finding) {
        const key = m.finding.type + "|" + m.finding.point + "|" + m.finding.param + "|" + m.finding.evidence;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({ ...m.finding, at: new Date().toISOString() });
        port.postMessage({ type: "finding", finding: findings[findings.length - 1], count: findings.length });
      } else if (m.progress) {
        port.postMessage({ type: "progress", sent, total: estimateTotal(page.points, opts) });
      }
    };
    const t0 = Date.now();
    try {
      if (opts.headers) await scanHeaders(page.url, emit);
      for (const point of page.points) {
        if (stopFlag) break;
        await scanPoint(point, opts, emit);
      }
      port.postMessage({ type: "done", stopped: stopFlag, requests: sent, ms: Date.now() - t0, findings });
    } catch (e) {
      port.postMessage({ type: "done", stopped: stopFlag, error: String(e.message || e), requests: sent, ms: Date.now() - t0, findings });
    }
  });
});
