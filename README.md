# Aegis Lens 🔍🛡️

A browser extension (Manifest V3) that turns the page you're on into a security test target — powered by the detection engine ideas from [aegis](https://github.com/sourabhbeni/aegis).

Click the icon on any page and it will:

- **Map attack surface** — extracts every form and URL parameter on the page as test points
- **Probe for SQL injection** — error-based detection across 26 DBMS/XPath/LDAP signatures, boolean-blind differentials, and UNION-based canary confirmation
- **Bypass filters** — 3 evasion levels; levels 2–3 retry blocked probes through 9 WAF-evasion transforms (case games, `/**/` smuggling, char/double encoding, versioned comments, keyword splitting…). Findings name the bypass that worked
- **Probe for reflected XSS** — the full 22-vector catalogue (HTML, attribute-breakout, JS-context, and filter-evasion variants) with canary-based context classification
- **Probe for SSTI** — distinctive-math probes (`{{1337*7331}}`) for template injection
- **Match known CVEs** — banner/body fingerprinting against a curated DB (Heartbleed, CVE-2021-41773, CVE-2021-23017, EOL PHP/Apache/IIS/OpenSSL, vulnerable jQuery, outdated WordPress…)
- **Audit security headers** — missing CSP, clickjacking protection, HSTS, nosniff, referrer policy, version disclosure
- **Find exposed paths** — `/.git/HEAD`, `/.env`, `/phpinfo.php`, `/server-status`, `/.DS_Store`

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
popup.html/css/js  UI: target summary, consent gate, evasion level, progress, findings, JSON export
background.js      scan engine: SQLi / XSS / SSTI / headers / CVE / exposures
payloads.js        payload & transform library (ported from aegis)
cves.js            curated known-CVE banner DB + exposed-path probes
icons/             extension icons
```

## Evasion levels

- **1 — Standard**: base payloads only, fastest
- **2 — Filter bypass**: + case/encoding/comment transforms and the first evasion XSS wave
- **3 — Full WAF-evasion**: all 11 transforms and the complete 27-vector XSS catalogue

Transforms run as a second pass only when standard probes are blocked — no wasted requests.

## Limits

- GET/POST form-encoded only; no JSON APIs, no auth flows, no JavaScript-rendered multi-step flows
- Boolean-blind and UNION findings are heuristic — verify MEDIUM/HIGH findings manually
- Time-based SQLi probes intentionally omitted (too noisy for in-browser use)
- The CVE DB is a curated starter set of famous fingerprintable issues, not a full scanner feed

MIT — built for learning and authorized testing.

## Changelog

- **1.2.1** — Community feed update (2026-09-28): 2 new XSS vectors (SVG `<animate>`
  href hijack bypassing event-handler + href filters, `<noscript>` mutation-XSS breakout),
  1 new SSTI `{% if %}` tag probe (Django-family incl. Pongo2/Go templates, Nullcon 2026
  research), 1 new level-3 WAF transform (XML decimal-entity keyword encoding, PortSwigger
  XML-encoding lab), 1 new SQLi boolean-blind pair (strcmp synonym-function oracle).
- **1.2.0** — Community feed update (2026-09-26): 5 new XSS vectors (marquee, video/audio
  onerror, input autofocus, nested math-namespace breakout), 4 new SSTI engine fingerprints
  (ERB/EJS, Mako/Pebble, Thymeleaf, Jinja2-vs-Twig distinguisher), 2 new level-3 WAF transforms
  (JSON-wrap blind from Claroty research, XML hex-entity keyword encoding), auth-bypass
  tautology probe. Request cap math updated automatically via `planCounts`.
- **1.1.0** — Full payload arsenal: 9 evasion transforms, UNION/SSTI probes, curated CVE DB.
