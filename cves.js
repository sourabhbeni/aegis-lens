/* Aegis Lens known-CVE / exposure database.
   Curated starter set of famous, remotely fingerprintable issues.
   All checks are PASSIVE (banner/body matching) or single safe GETs —
   no exploits are ever sent. Loaded via importScripts. */
"use strict";

/* numeric dotted-version compare: -1 / 0 / 1 */
function vercmp(a, b) {
  const pa = String(a).split(".").map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

/* Each entry: test(headers, body) -> null | {evidence} */
const CVE_DB = [
  {
    id: "CVE-2021-41773", severity: "HIGH", title: "Apache httpd path traversal → RCE",
    test: (h) => {
      const m = /apache\/2\.4\.(\d+)/i.exec(h.server || "");
      return m && (m[1] === "49" || m[1] === "50")
        ? { evidence: `Server: Apache/2.4.${m[1]} — vulnerable to CVE-2021-41773/42013 path traversal` } : null;
    },
    detail: "Apache 2.4.49/2.4.50 allow path traversal and, with mod_cgi, RCE. Fixed in 2.4.51.",
  },
  {
    id: "CVE-2014-0160", severity: "CRITICAL", title: "Heartbleed (OpenSSL)",
    test: (h) => {
      const m = /openssl\/1\.0\.1([a-f]?)/i.exec(h.server || "");
      return m && (!m[1] || m[1] <= "f")
        ? { evidence: `Server banner discloses OpenSSL 1.0.1${m[1] || ""} — Heartbleed-vulnerable range` } : null;
    },
    detail: "Heartbleed leaks server memory, including private keys. Upgrade OpenSSL past 1.0.1g.",
  },
  {
    id: "CVE-2021-23017", severity: "MEDIUM", title: "nginx DNS resolver RCE",
    test: (h) => {
      const m = /nginx\/(\d+\.\d+\.\d+)/i.exec(h.server || "");
      return m && vercmp(m[1], "1.20.1") < 0
        ? { evidence: `Server: nginx/${m[1]} — predates the 1.20.1 security fix` } : null;
    },
    detail: "nginx before 1.20.1 has a DNS-resolver heap overflow (1-byte write → RCE potential).",
  },
  {
    id: "EOL-PHP", severity: "HIGH", title: "End-of-life PHP — unpatched",
    test: (h) => {
      const m = /php\/(\d+)\.(\d+)/i.exec(h["x-powered-by"] || "");
      return m && (parseInt(m[1], 10) < 7 || (m[1] === "7" && parseInt(m[2], 10) <= 4) || (m[1] === "8" && parseInt(m[2], 10) === 0))
        ? { evidence: `X-Powered-By: PHP/${m[1]}.${m[2]} — EOL, receives no security fixes` } : null;
    },
    detail: "EOL PHP branches accumulate unpatched CVEs. Move to a supported 8.x branch.",
  },
  {
    id: "EOL-APACHE-2.2", severity: "MEDIUM", title: "End-of-life Apache 2.2",
    test: (h) => /apache\/2\.2\./i.test(h.server || "")
      ? { evidence: "Server: Apache 2.2.x — EOL since 2018, no security fixes" } : null,
    detail: "Apache 2.2 is end-of-life; known CVEs in it will never be patched.",
  },
  {
    id: "EOL-IIS", severity: "MEDIUM", title: "End-of-life IIS",
    test: (h) => {
      const m = /microsoft-iis\/(\d+\.\d+)/i.exec(h.server || "");
      return m && vercmp(m[1], "8.0") < 0
        ? { evidence: `Server: Microsoft-IIS/${m[1]} — EOL, no security fixes` } : null;
    },
    detail: "IIS below 8.0 is end-of-life with the underlying Windows Server release.",
  },
  {
    id: "EOL-OPENSSL", severity: "MEDIUM", title: "End-of-life OpenSSL 1.0.2/1.1.0",
    test: (h) => /openssl\/1\.(0\.2|1\.0)/i.test(h.server || "")
      ? { evidence: "Server banner discloses EOL OpenSSL 1.0.2/1.1.0" } : null,
    detail: "These OpenSSL branches are EOL and miss fixes for post-EOL CVEs.",
  },
  {
    id: "CVE-2020-11022", severity: "MEDIUM", title: "Vulnerable jQuery (< 3.5.0)",
    test: (h, body) => {
      const m = /jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js|jquery\/(\d+\.\d+\.\d+)/i.exec(body || "");
      const v = m && (m[1] || m[2]);
      return v && vercmp(v, "3.5.0") < 0
        ? { evidence: `Page loads jQuery ${v} — vulnerable to CVE-2020-11022/11023 (XSS)` } : null;
    },
    detail: "jQuery before 3.5.0 has known XSS CVEs via HTML parsing. Upgrade to 3.5.0+.",
  },
  {
    id: "OUTDATED-WP", severity: "MEDIUM", title: "Outdated WordPress",
    test: (h, body) => {
      const m = /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress (\d+\.\d+(?:\.\d+)?)/i.exec(body || "");
      return m && vercmp(m[1], "6.0") < 0
        ? { evidence: `Meta generator: WordPress ${m[1]} — predates 6.0, many known CVEs` } : null;
    },
    detail: "Old WordPress cores/plugins are a top initial-access vector. Update core and plugins.",
  },
];

/* Safe single-GET exposure probes: {path, match, severity, title, detail} */
const EXPOSED_PATHS = [
  { path: "/.git/HEAD", match: /ref:\s*refs\//, severity: "HIGH",
    title: "Exposed .git directory",
    detail: "The git repo is downloadable — full source history, secrets in old commits." },
  { path: "/.env", match: /^[\w-]+=.+$/m, severity: "HIGH",
    title: "Exposed .env file",
    detail: "Environment files routinely hold DB passwords, API keys, and app secrets." },
  { path: "/phpinfo.php", match: /phpinfo\(\)/i, severity: "MEDIUM",
    title: "Exposed phpinfo()",
    detail: "Discloses PHP config, paths, and loaded modules to attackers." },
  { path: "/server-status", match: /apache status/i, severity: "MEDIUM",
    title: "Exposed Apache server-status",
    detail: "Leaks request details and internal URLs; restrict to localhost." },
  { path: "/.DS_Store", match: /Bud1/, severity: "LOW",
    title: "Exposed .DS_Store",
    detail: "Leaks internal directory/file names." },
];

function checkCveBanners(headers, body, emit, point) {
  const h = {};
  for (const k of Object.keys(headers)) h[k.toLowerCase()] = headers[k];
  for (const entry of CVE_DB) {
    let r = null;
    try { r = entry.test(h, body); } catch { r = null; }
    if (r) {
      emit({
        finding: {
          severity: entry.severity, type: `Known CVE: ${entry.id}`,
          point, param: "-", payload: "-",
          evidence: `${entry.title} — ${r.evidence}`,
          detail: entry.detail,
        },
      });
    }
  }
}
