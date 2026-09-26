# Aegis Lens 🔍🛡️

A browser extension (Manifest V3) that turns the page you're on into a security test target — powered by the detection engine ideas from [aegis](https://github.com/sourabhbeni/aegis).

Click the icon on any page and it will:

- **Map attack surface** — extracts every form and URL parameter on the page as test points
- **Probe for SQL injection** — quote-based error detection across 14 DBMS error signatures (MySQL, PostgreSQL, MSSQL, Oracle, SQLite…), plus boolean-differential blind probes
- **Probe for reflected XSS** — canary-based reflection analysis with context classification (script, event-handler, HTML), including tag-breakout confirmation
- **Audit security headers** — missing CSP, clickjacking protection, HSTS, nosniff, referrer policy, version disclosure

All probes are **non-destructive detection only** — no exploitation, no data extraction. Findings are graded HIGH / MEDIUM / LOW / INFO with the exact payload and evidence, and export to JSON.

> ⚠️ **Only scan targets you own or have explicit permission to test.** The popup requires a consent checkbox before every scan.

## Install (Chrome / Edge / Brave)

1. Clone or download this repo
2. Open `chrome://extensions`, enable **Developer mode**
3. **Load unpacked** → select this folder
4. Click the Aegis Lens icon on any `http(s)` page

No build step, no dependencies.

## How it works

- `popup.js` injects a self-contained page extractor via `chrome.scripting` (forms, inputs, query params)
- `background.js` (service worker) fires the probes with `fetch` — host permissions let it bypass page CORS — with a 120 ms delay, 12 s timeout, and a 250-request cap per scan
- Responses are matched against DBMS error signatures and canary reflection, findings stream back over a long-lived port

## Project layout

```
manifest.json      MV3 manifest (activeTab, scripting, host_permissions)
popup.html/css/js  UI: target summary, consent gate, progress, findings, JSON export
background.js      scan engine: SQLi / XSS / header checks
icons/             extension icons
```

## Limits

- GET/POST form-encoded only; no JSON APIs, no auth flows, no JavaScript-rendered multi-step flows
- Boolean-blind detection is heuristic — verify MEDIUM findings manually
- Time-based SQLi probes intentionally omitted (too noisy for in-browser use)

MIT — built for learning and authorized testing.
