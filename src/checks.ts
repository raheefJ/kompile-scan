// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Kompile Scan checks. Read-only: ordinary GET requests a browser could make,
 * about 20 per scan, no payloads, no login attempts, no load. Evidence never
 * quotes the contents of an exposed file, so a report cannot leak a secret.
 */
import { resolve4, resolveCaa, resolveCname, resolveMx, resolveTxt } from "node:dns/promises";
import { safeRequest, type SafeRequestOptions, type SafeResponse } from "./net";

export type Severity = "high" | "medium" | "low" | "info";
export type Status = "pass" | "fail" | "warn" | "info";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  status: Status;
  /** What we observed, in plain words. Never contains secret values. */
  evidence: string;
  why: string;
  fix: string;
}

/** Bump when checks change so training data can tell rule sets apart. */
export const SCANNER_VERSION = "2026.10.13-ai-lab-fixes";

export interface ScanReport {
  hostname: string;
  finalUrl: string;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  findings: Finding[];
  durationMs: number;
  /** Which rule set produced this report (training rows are grouped by it). */
  scannerVersion: string;
  /** Coarse, non-identifying facts about the site (hosting, framework, backends, header strength) for training. */
  signals?: ScanSignals;
}

const WEIGHT: Record<Severity, number> = { high: 25, medium: 12, low: 4, info: 0 };

export function scoreFindings(findings: Finding[]): { score: number; grade: ScanReport["grade"] } {
  let score = 100;
  for (const f of findings) {
    if (f.status === "fail") score -= WEIGHT[f.severity];
    else if (f.status === "warn") score -= Math.ceil(WEIGHT[f.severity] / 2);
  }
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  return { score, grade };
}

const header = (r: SafeResponse, name: string): string | undefined => {
  const v = r.headers[name.toLowerCase()];
  return Array.isArray(v) ? v.join(", ") : v;
};

const isRedirect = (s: number) => [301, 302, 303, 307, 308].includes(s);

/** Follows same-site redirects (host or its www variant), every hop through the SSRF-safe client. */
async function fetchFinal(req: Requester, start: string, hostname: string, net: SafeRequestOptions): Promise<{ res: SafeResponse; hops: string[]; offsite: string | null }> {
  const hops: string[] = [];
  let url = start;
  const bare = hostname.replace(/^www\./, "");
  for (let i = 0; i < 4; i++) {
    const res = await req(url, net);
    if (!isRedirect(res.status)) return { res, hops, offsite: null };
    const loc = header(res, "location");
    if (!loc) return { res, hops, offsite: null };
    const next = new URL(loc, url);
    hops.push(next.toString());
    const nextBare = next.hostname.replace(/^www\./, "");
    if (nextBare !== bare || (next.protocol !== "https:" && next.protocol !== "http:")) return { res, hops, offsite: next.origin };
    url = next.toString();
  }
  return { res: await req(url, net), hops, offsite: null };
}

interface Probe {
  path: string;
  label: string;
  matches(r: SafeResponse): boolean;
}

const looksHtml = (r: SafeResponse) => /<html|<!doctype html/i.test(r.body.slice(0, 512)) || /text\/html/i.test(String(r.headers["content-type"] ?? ""));

export const PROBES: Probe[] = [
  {
    path: "/.env",
    label: "an environment file (often holds API keys and database passwords)",
    matches: (r) => r.status === 200 && !looksHtml(r) && (r.body.match(/^[A-Z][A-Z0-9_]{1,60}=.*$/gm)?.length ?? 0) >= 2,
  },
  { path: "/.git/HEAD", label: "the site's Git repository (the full source code and its history can be downloaded)", matches: (r) => r.status === 200 && /^(ref: refs\/|[0-9a-f]{40}\s*$)/.test(r.body) },
  { path: "/.git/config", label: "the site's Git configuration", matches: (r) => r.status === 200 && !looksHtml(r) && /\[core\]/.test(r.body) },
  { path: "/.svn/entries", label: "a Subversion working copy", matches: (r) => r.status === 200 && !looksHtml(r) && /^\d+\s*$/m.test(r.body.slice(0, 20)) },
  { path: "/.DS_Store", label: "a macOS folder index (lists hidden file names)", matches: (r) => r.status === 200 && r.body.includes("Bud1") },
  { path: "/.aws/credentials", label: "an AWS credentials file", matches: (r) => r.status === 200 && /aws_access_key_id/i.test(r.body) },
  { path: "/wp-config.php.bak", label: "a WordPress configuration backup (database password)", matches: (r) => r.status === 200 && /DB_PASSWORD/.test(r.body) },
  { path: "/config.php.bak", label: "a PHP configuration backup", matches: (r) => r.status === 200 && /<\?php/.test(r.body) },
  { path: "/phpinfo.php", label: "a phpinfo() page (server internals and paths)", matches: (r) => r.status === 200 && /PHP Version/.test(r.body) && /phpinfo/i.test(r.body) },
  { path: "/server-status", label: "the Apache server-status page (live requests and client addresses)", matches: (r) => r.status === 200 && /Apache Server Status/i.test(r.body) },
  { path: "/docker-compose.yml", label: "a Docker Compose file (service layout, often passwords)", matches: (r) => r.status === 200 && !looksHtml(r) && /^services:/m.test(r.body) },
  { path: "/Dockerfile", label: "the Dockerfile (base image, build steps, sometimes secrets)", matches: (r) => r.status === 200 && !looksHtml(r) && /^FROM\s+\S+/m.test(r.body) && /^(RUN|COPY|ENV|WORKDIR|CMD|ENTRYPOINT|LABEL|EXPOSE)\s/m.test(r.body) },
  { path: "/next.config.js", label: "the Next.js config file (build settings, sometimes keys)", matches: (r) => r.status === 200 && !looksHtml(r) && /(module\.exports|export default)[\s\S]{0,400}(reactStrictMode|images|env|experimental|output|rewrites|headers)/.test(r.body) },
  { path: "/vite.config.ts", label: "the Vite config file", matches: (r) => r.status === 200 && !looksHtml(r) && /defineConfig\s*\(/.test(r.body) },
  { path: "/vite.config.js", label: "the Vite config file", matches: (r) => r.status === 200 && !looksHtml(r) && /defineConfig\s*\(/.test(r.body) },
  { path: "/webpack.config.js", label: "the webpack config file", matches: (r) => r.status === 200 && !looksHtml(r) && /module\.exports[\s\S]{0,600}(entry|output|module)\s*:/.test(r.body) },
  { path: "/vercel.json", label: "the Vercel project config", matches: (r) => r.status === 200 && !looksHtml(r) && /"(rewrites|redirects|builds|routes|functions|crons)"\s*:/.test(r.body) },
  { path: "/.vercel/project.json", label: "the Vercel project link file (project and team ids)", matches: (r) => r.status === 200 && /"projectId"\s*:\s*"prj_/.test(r.body) },
  { path: "/netlify.toml", label: "the Netlify config file", matches: (r) => r.status === 200 && !looksHtml(r) && /^\[\[?(build|redirects|headers|functions|context)\b/m.test(r.body) },
  { path: "/backup.zip", label: "a site backup archive", matches: (r) => r.status === 200 && r.body.startsWith("PK\u0003\u0004") },
  { path: "/backup.sql", label: "a database dump (every row of your data)", matches: (r) => r.status === 200 && !looksHtml(r) && /(CREATE TABLE|INSERT INTO|-- (MySQL|PostgreSQL) database dump)/i.test(r.body) },
  { path: "/dump.sql", label: "a database dump (every row of your data)", matches: (r) => r.status === 200 && !looksHtml(r) && /(CREATE TABLE|INSERT INTO|-- (MySQL|PostgreSQL) database dump)/i.test(r.body) },
  { path: "/.npmrc", label: "an npm config file (often holds a registry token)", matches: (r) => r.status === 200 && !looksHtml(r) && /(_authToken|registry=)/.test(r.body) },
  { path: "/firebase-debug.log", label: "a Firebase debug log (project ids, sometimes tokens)", matches: (r) => r.status === 200 && !looksHtml(r) && /\[debug\]/i.test(r.body) },
  { path: "/.env.local", label: "a local environment file (often holds API keys)", matches: (r) => r.status === 200 && !looksHtml(r) && (r.body.match(/^[A-Z][A-Z0-9_]{1,60}=.*$/gm)?.length ?? 0) >= 2 },
  { path: "/.env.production", label: "a production environment file (often holds API keys)", matches: (r) => r.status === 200 && !looksHtml(r) && (r.body.match(/^[A-Z][A-Z0-9_]{1,60}=.*$/gm)?.length ?? 0) >= 2 },
  { path: "/metrics", label: "a Prometheus metrics page (internal counters, routes and versions)", matches: (r) => r.status === 200 && !looksHtml(r) && /^# HELP /m.test(r.body) && /^# TYPE /m.test(r.body) },
  { path: "/actuator/env", label: "the Spring Boot environment endpoint (configuration, sometimes passwords)", matches: (r) => r.status === 200 && /"(propertySources|activeProfiles)"/.test(r.body) },
  { path: "/actuator", label: "the Spring Boot actuator index (links to health, config and environment endpoints)", matches: (r) => r.status === 200 && /"_links"\s*:\s*\{[\s\S]{0,2000}"(env|configprops|heapdump|beans)"/.test(r.body) },
  { path: "/actuator/configprops", label: "the Spring Boot configuration properties endpoint", matches: (r) => r.status === 200 && /"contexts"\s*:[\s\S]{0,400}"beans"/.test(r.body) },
  { path: "/debug/pprof/", label: "the Go profiler (memory and goroutine dumps)", matches: (r) => r.status === 200 && /Types of profiles available/i.test(r.body) },
  { path: "/storage/logs/laravel.log", label: "a Laravel log file (errors, queries, sometimes secrets)", matches: (r) => r.status === 200 && !looksHtml(r) && /^\[\d{4}-\d\d-\d\d [\d:]+\] \w+\.(ERROR|INFO|DEBUG|WARNING)/m.test(r.body) },
  { path: "/elmah.axd", label: "the ELMAH error log (full .NET errors with request data)", matches: (r) => r.status === 200 && /Error Log for/i.test(r.body) },
];

/** Automatic folder listings from Apache, nginx, IIS, Python and Node (serve-index). */
export const LISTING_SIGNATURE = /<title>(Index of \/|Directory listing for \/|listing directory \/)|\[To Parent Directory\]/i;
/** Folders that are often listed by accident; robots.txt Disallow entries are added at scan time. */
const LISTING_PATHS = ["/ftp/", "/backup/", "/backups/", "/uploads/", "/files/", "/logs/", "/tmp/"];

/** Error-page signatures that reveal stack traces, file paths, or debug mode. */
export const DEBUG_SIGNATURES: Array<[string, RegExp]> = [
  ["a Python traceback", /Traceback \(most recent call last\)/],
  ["Django debug mode", /You're seeing this error because you have <code>DEBUG = True<\/code>|Django Version:/],
  ["a Laravel / Ignition debug page", /Whoops! There was an error|Illuminate\\|ignition/i],
  ["a Node.js stack trace", /\n\s+at [\w.<>$]+ \((\/|[A-Z]:\\)[^)]+:\d+:\d+\)/],
  // Tomcat labels real exceptions "Exception Report"; its ordinary 404 page says "Status Report" and is not matched.
  ["a Java / Tomcat exception report", /<b>Type<\/b>\s*Exception Report|\n\s*at (org|com|java|jakarta)\.[\w.$]+\([\w$]+\.java:\d+\)/],
  ["an Express debug error page",/id="stacktrace"|(&nbsp;\s*){2}at [^<]{0,300}(\/|[A-Z]:\\)[^<]*:\d+:\d+/],
  ["an ASP.NET error page", /Server Error in '\/' Application|Exception Details:/],
  ["a Ruby on Rails error page", /Action Controller: Exception caught/],
  ["a Spring Boot error page", /Whitelabel Error Page[\s\S]{0,400}(Exception|trace)/],
  ["a PHP error with file paths", /(Fatal error|Warning|Parse error)<\/b>:.{0,200} in <b>\//],
];

const API_DOC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs"];
/** Interactive API explorers (Swagger UI, ReDoc). */
const API_UI_PATHS = ["/api-docs/", "/swagger-ui.html", "/swagger/", "/swagger-ui/"];
const API_UI_SIGNATURE = /swagger-ui-bundle\.js|id="swagger-ui"|<redoc[\s>]/i;

/** Admin, database and AI tool panels that should never face the internet. Matched by page fingerprint only; we never log in. */
export const PANELS: Array<{ path: string; label: string; re: RegExp }> = [
  { path: "/phpmyadmin/", label: "phpMyAdmin (database admin)", re: /<title>[^<]*phpMyAdmin/i },
  { path: "/adminer.php", label: "Adminer (database admin)", re: /<title>[^<]*Adminer|adminer\.org/i },
  { path: "/pgadmin4/", label: "pgAdmin (database admin)", re: /<title>[^<]*pgAdmin/i },
  { path: "/project/default", label: "Supabase Studio (database dashboard)", re: /<title>[^<]*Supabase|Supabase Studio/i },
  { path: "/_/", label: "the PocketBase admin dashboard", re: /<title>[^<]*PocketBase/i },
  { path: "/tree", label: "a Jupyter notebook server", re: /<title>[^<]*(Jupyter|Home Page - Select or create a notebook)/i },
  { path: "/lab", label: "a JupyterLab server", re: /<title>[^<]*JupyterLab/i },
  { path: "/api/tags", label: "an Ollama model server (anyone can run your models)", re: /^\s*\{\s*"models"\s*:\s*\[/ },
  { path: "/signin", label: "an n8n automation server", re: /<title>[^<]*n8n/i },
  { path: "/", label: "Open WebUI (AI chat front end)", re: /<title>Open WebUI<\/title>/i },
  { path: "/api/v1/ping", label: "a Flowise AI workflow server", re: /^pong$/ },
  { path: "/login", label: "Grafana", re: /<title>Grafana<\/title>/i },
  { path: "/app/kibana", label: "Kibana", re: /<title>[^<]*Kibana/i },
  { path: "/storybook/", label: "a Storybook component library (internal UI and props)", re: /<title>[^<]*Storybook/i },
  { path: "/dashboard/", label: "the Traefik dashboard", re: /<title>Traefik<\/title>/i },
  { path: "/", label: "mongo-express (database admin)", re: /<title>Home - Mongo Express<\/title>/i },
];

/** Front-end libraries with well-known security fixes. Version below `fixed` is flagged. Sources: NVD and GitHub advisories. */
export const VULN_LIBS: Array<{ name: string; re: RegExp; fixed: string; advisory: string }> = [
  { name: "jQuery", re: /jquery[.-](\d+\.\d+\.\d+)(\.min)?\.js|jQuery v(\d+\.\d+\.\d+)|jquery@(\d+\.\d+\.\d+)/i, fixed: "3.5.0", advisory: "CVE-2020-11022 / CVE-2020-11023 (XSS)" },
  { name: "AngularJS", re: /angular[.-](1\.\d+\.\d+)(\.min)?\.js|AngularJS v(1\.\d+\.\d+)|angular\.js@(1\.\d+\.\d+)/i, fixed: "99.0.0", advisory: "AngularJS 1.x is end of life (no security fixes since 2022)" },
  { name: "Lodash", re: /lodash[.-](\d+\.\d+\.\d+)(\.min)?\.js|lodash@(\d+\.\d+\.\d+)|@license Lodash[^\n]{0,40}?(\d+\.\d+\.\d+)/i, fixed: "4.17.21", advisory: "CVE-2021-23337 / CVE-2020-8203" },
  { name: "Bootstrap", re: /bootstrap[.-](\d+\.\d+\.\d+)(\.min)?\.js|bootstrap@(\d+\.\d+\.\d+)\/dist\/js|Bootstrap v(\d+\.\d+\.\d+)/i, fixed: "3.4.1", advisory: "CVE-2019-8331 (XSS in tooltip)" },
  { name: "Moment.js", re: /moment[.-](\d+\.\d+\.\d+)(\.min)?\.js|moment@(\d+\.\d+\.\d+)|\/\/! version : (\d+\.\d+\.\d+)/i, fixed: "2.29.4", advisory: "CVE-2022-31129 (ReDoS)" },
  { name: "Handlebars", re: /handlebars[.-](\d+\.\d+\.\d+)(\.min)?\.js|handlebars@(\d+\.\d+\.\d+)|Handlebars v(\d+\.\d+\.\d+)/i, fixed: "4.7.7", advisory: "CVE-2021-23369 (code execution)" },
  { name: "DOMPurify", re: /purify[.-](\d+\.\d+\.\d+)(\.min)?\.js|dompurify@(\d+\.\d+\.\d+)|DOMPurify (\d+\.\d+\.\d+)/i, fixed: "3.1.3", advisory: "CVE-2024-45801 (sanitizer bypass)" },
];

/** CDNs taken over and used to serve malware (polyfill.io, June 2024, and its sister domains). */
export const HIJACKED_CDNS = /^(.*\.)?(polyfill\.io|polyfill\.com|polyfillcache\.com|bootcdn\.net|bootcss\.com|staticfile\.net|staticfile\.org|unionadjs\.com|xhsbpza\.com|union\.macoms\.la|newcrbpc\.com)$/i;

/**
 * Hosting providers where a dangling CNAME can be claimed by someone else. Fingerprints follow the community list at
 * github.com/EdOverflow/can-i-take-over-xyz; providers that now verify domain ownership (such as Vercel) are left out.
 */
export const TAKEOVER_PROVIDERS: Array<{ name: string; cname: RegExp; body?: RegExp; nxdomainMeansOpen?: boolean }> = [
  { name: "GitHub Pages", cname: /\.github\.io$/, body: /There isn't a GitHub Pages site here/i },
  { name: "Heroku", cname: /\.(herokuapp\.com|herokudns\.com|herokussl\.com)$/, body: /No such app|herokucdn\.com\/error-pages\/no-such-app/i, nxdomainMeansOpen: true },
  { name: "AWS S3", cname: /\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com$|\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/, body: /NoSuchBucket|The specified bucket does not exist/i },
  { name: "Azure", cname: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net|azure-api\.net|azurefd\.net)$/, nxdomainMeansOpen: true },
  { name: "Netlify", cname: /\.netlify\.(app|com)$/, body: /Not Found - Request ID:/i },
  { name: "Surge", cname: /\.surge\.sh$|^na-west1\.surge\.sh$/, body: /project not found/i },
  { name: "Shopify", cname: /\.myshopify\.com$/, body: /Sorry, this shop is currently unavailable/i },
  { name: "Ghost", cname: /\.ghost\.io$/, body: /Domain error|Failed to resolve DNS path for this host/i },
  { name: "Pantheon", cname: /\.pantheonsite\.io$/, body: /The gods are wise, but do not know of the site which you seek/i },
  { name: "Tumblr", cname: /^domains\.tumblr\.com$/, body: /Whatever you were looking for doesn't currently exist at this address/i },
];

/** Subdomains of `hostname` seen in public certificate transparency logs (crt.sh). Wildcards and the host itself are dropped. */
export async function ctSubdomains(req: Requester, hostname: string, net: SafeRequestOptions): Promise<string[]> {
  const r = await req(`https://crt.sh/?q=${encodeURIComponent(`%.${hostname}`)}&output=json`, { ...net, maxBodyBytes: 2_000_000, timeoutMs: 15_000 });
  if (r.status !== 200) return [];
  let rows: Array<{ name_value?: string }> = [];
  try {
    rows = JSON.parse(r.body);
  } catch {
    return [];
  }
  const out = new Set<string>();
  for (const row of rows) {
    for (const n of (row.name_value ?? "").toLowerCase().split(/\s+/)) {
      if (n.endsWith(`.${hostname}`) && !n.includes("*") && /^[a-z0-9.-]+$/.test(n)) out.add(n);
    }
  }
  return [...out].sort();
}

/** Coarse facts about a scanned site, stored with training data. Categories and counts only: no names, URLs or values. */
export interface ScanSignals {
  hosting: string;
  server: string;
  framework: string;
  frameworkMajor: number | null;
  backends: string[];
  scripts: number;
  thirdPartyScripts: number;
  cookies: number;
  csp: "none" | "weak" | "strict";
  hsts: "none" | "short" | "long";
}

const HOSTING: Array<[string, (h: (n: string) => string | undefined) => boolean]> = [
  ["vercel", (h) => Boolean(h("x-vercel-id")) || /vercel/i.test(h("server") ?? "")],
  ["netlify", (h) => Boolean(h("x-nf-request-id")) || /netlify/i.test(h("server") ?? "")],
  ["cloudflare", (h) => Boolean(h("cf-ray"))],
  ["railway", (h) => /railway/i.test(h("server") ?? "") || Boolean(h("x-railway-request-id"))],
  ["fly", (h) => Boolean(h("fly-request-id"))],
  ["render", (h) => Boolean(h("x-render-origin-server")) || Boolean(h("rndr-id"))],
  ["github-pages", (h) => /github\.com/i.test(h("server") ?? "")],
  ["aws-cloudfront", (h) => Boolean(h("x-amz-cf-id"))],
];

const FRAMEWORKS: Array<[string, RegExp]> = [
  ["nextjs", /\/_next\/static\/|window\.next\s*=|__NEXT_DATA__/],
  ["nuxt", /\/_nuxt\/|window\.__NUXT__/],
  ["sveltekit", /\/_app\/immutable\//],
  ["astro", /\/_astro\//],
  ["remix", /__remixContext/],
  ["gatsby", /___gatsby/],
  ["angular", /ng-version=|<app-root/],
  ["wordpress", /\/wp-content\/|\/wp-includes\//],
  ["vite-spa", /<script type="module"[^>]+src="\/assets\/index-[\w-]+\.js"/],
];

const BACKENDS: Array<[string, RegExp]> = [
  ["supabase", /\.supabase\.(co|in)\b/],
  ["firebase", /firebaseio\.com|firebaseapp\.com|firebasestorage\.googleapis\.com/],
  ["clerk", /clerk\.(accounts\.dev|com)|@clerk\//],
  ["stripe-js", /js\.stripe\.com/],
  ["auth0", /\.auth0\.com/],
  ["convex", /\.convex\.cloud/],
  ["openai-in-browser", /api\.openai\.com/],
];

export function collectSignals(page: SafeResponse, bodies: Array<[string, string]>, scriptHosts: string[], origin: string, nextVersion?: string): ScanSignals {
  const h = (n: string) => header(page, n);
  const all = bodies.map(([, t]) => t).join("\n");
  const csp = h("content-security-policy");
  const hstsAge = Number(/max-age=(\d+)/i.exec(h("strict-transport-security") ?? "")?.[1] ?? -1);
  const originHost = new URL(origin).hostname;
  const framework = FRAMEWORKS.find(([, re]) => re.test(all))?.[0] ?? "unknown";
  const server = h("server");
  return {
    hosting: HOSTING.find(([, test]) => test(h))?.[0] ?? "other",
    server: server ? (/^(nginx|apache|caddy|openresty|cloudflare|express|microsoft-iis|gunicorn|uvicorn|envoy|litespeed)/i.exec(server)?.[1]?.toLowerCase() ?? "other") : "hidden",
    framework,
    frameworkMajor: framework === "nextjs" && nextVersion ? Number(nextVersion.split(".")[0]) : null,
    backends: BACKENDS.filter(([, re]) => re.test(all)).map(([n]) => n),
    scripts: scriptHosts.length,
    thirdPartyScripts: scriptHosts.filter((s) => s !== originHost).length,
    cookies: page.setCookies.length,
    csp: !csp ? "none" : /script-src[^;]*'unsafe-inline'/.test(csp) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(csp) ? "weak" : "strict",
    hsts: hstsAge < 0 ? "none" : hstsAge >= 15_552_000 ? "long" : "short",
  };
}

/** Compares dotted versions: true when a < b. */
export function versionBelow(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}

/** Secret key formats that must never reach a browser. Publishable/anon keys are deliberately not listed. */
export const SECRET_KEY_PATTERNS: Array<[string, RegExp]> = [
  ["a Stripe or Clerk secret key", /\b[sr]k_(live|test)_[A-Za-z0-9]{20,}/],
  ["a Groq API key", /\bgsk_[A-Za-z0-9]{52}\b/],
  ["an OpenRouter API key", /\bsk-or-v1-[0-9a-f]{64}\b/],
  ["a Resend API key", /\bre_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}\b/],
  ["a Replicate API token", /\br8_[0-9A-Za-z_-]{37}\b/],
  ["a SendGrid API key", /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/],
  ["a Hugging Face token", /\bhf_[A-Za-z]{34}\b/],
  ["a Perplexity API key", /\bpplx-[A-Za-z0-9]{48}\b/],
  ["a Slack token", /\bxox[bpe]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*/],
  ["a Slack webhook URL", /hooks\.slack\.com\/(services|workflows|triggers)\/[A-Za-z0-9+/]{30,60}/],
  ["a Discord webhook URL", /discord(app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,70}/],
  ["a Telegram bot token", /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/],
  ["a Shopify access token", /\bshpat_[a-fA-F0-9]{32}\b/],
  ["an npm token", /\bnpm_[A-Za-z0-9]{36}\b/],
  ["a DigitalOcean token", /\bdo[op]_v1_[a-f0-9]{64}\b/],
  ["a Linear API key", /\blin_api_[A-Za-z0-9]{40}\b/],
  ["a Notion integration token", /\bntn_[0-9]{11}[A-Za-z0-9]{35}\b/],
  ["a Mapbox secret token", /\bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/],
  ["an OpenAI API key", /\bsk-(proj-)?[A-Za-z0-9_-]{32,}/],
  ["an Anthropic API key", /\bsk-ant-[A-Za-z0-9_-]{32,}/],
  ["an AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["a GitHub token", /\b(ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{30,}/],
  ["a Supabase service_role key", /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*c2VydmljZV9yb2xl[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+/],
  // Built from parts so this source file itself never contains a key header.
  ["a private key", new RegExp(["-----BEGIN", "PRIVATE KEY-----"].join(" "))],
];

/** Shows just enough to recognise the key, never enough to use it. */
export const maskKey = (k: string) => `${k.slice(0, Math.min(8, k.length - 4))}...`;

const SESSIONISH =/(sess|auth|token|login|jwt|sid|remember)/i;

export interface RunScanOptions {
  net?: SafeRequestOptions;
  dns?: { txt?: typeof resolveTxt; mx?: typeof resolveMx; caa?: typeof resolveCaa; cname?: (name: string) => Promise<string[]>; a?: (name: string) => Promise<string[]> };
  /** Subdomain source (defaults to public certificate transparency logs). Tests inject a list. */
  ctNames?: (hostname: string) => Promise<string[]>;
  /** Set false to skip the subdomain takeover check. */
  subdomains?: boolean;
  /** Overall budget for the whole scan. */
  budgetMs?: number;
  /** Where the app starts when it is not at the root, e.g. "/app". Same verified host only. */
  basePath?: string;
}

/** Accepts "/app" or "/app/sub/" style paths only: no dots, queries, or other hosts. */
export function normalizeBasePath(input: string | undefined | null): string | undefined {
  if (!input) return undefined;
  const p = input.trim();
  if (!/^\/[A-Za-z0-9_\-/]{0,100}$/.test(p) || p.includes("//")) return undefined;
  return p === "/" ? undefined : p;
}

export type Requester = typeof safeRequest;

export function runScan(hostname: string, opts: RunScanOptions = {}): Promise<ScanReport> {
  return runScanWith(safeRequest, hostname, opts);
}

/** The checks, with the HTTP client injected (production always passes the SSRF-safe safeRequest). */
export async function runScanWith(req: Requester, hostname: string, opts: RunScanOptions = {}): Promise<ScanReport> {
  const started = Date.now();
  const net = opts.net ?? {};
  const basePath = normalizeBasePath(opts.basePath);
  const findings: Finding[] = [];
  const add = (f: Finding) => findings.push(f);

  // 1. HTTPS and the certificate.
  let https: Awaited<ReturnType<typeof fetchFinal>> | null = null;
  try {
    https = await fetchFinal(req, `https://${hostname}${basePath ?? "/"}`, hostname, net);
  } catch (err) {
    add({
      id: "KS-01", title: "HTTPS works", severity: "high", status: "fail",
      evidence: `We could not open https://${hostname}/ (${(err as Error).message}).`,
      why: "Without HTTPS, anyone on the same network (a cafe, a hotel, an ISP) can read and change what your visitors send and see.",
      fix: "Turn on HTTPS. Most hosts do this in one click with a free certificate from Let's Encrypt, or put the site behind a CDN such as Cloudflare.",
    });
  }
  const page = https?.res;
  let signals: ScanSignals | undefined;
  if (page?.tls) {
    const t = page.tls;
    add(
      t.authorized
        ? { id: "KS-01", title: "HTTPS works with a trusted certificate", severity: "high", status: "pass", evidence: `Certificate issued by ${t.issuer ?? "a trusted authority"}.`, why: "Visitors' connections are encrypted and browsers trust your certificate.", fix: "Nothing to do." }
        : { id: "KS-01", title: "HTTPS certificate is not trusted", severity: "high", status: "fail", evidence: `Browsers reject the certificate: ${t.authorizationError}.`, why: "Visitors see a full-page warning, and people who click through are open to interception.", fix: "Install a valid certificate for this exact name (including www if you use it). Free certificates from Let's Encrypt renew automatically." },
    );
    if (t.validTo) {
      const days = Math.floor((Date.parse(t.validTo) - Date.now()) / 86_400_000);
      add(
        days >= 14
          ? { id: "KS-02", title: "Certificate is not about to expire", severity: "medium", status: "pass", evidence: `Valid for ${days} more days.`, why: "An expired certificate takes the site down for everyone.", fix: "Nothing to do. Keep automatic renewal on." }
          : { id: "KS-02", title: "Certificate expires soon", severity: "medium", status: days < 0 ? "fail" : "warn", evidence: days < 0 ? "The certificate has expired." : `Only ${days} days left.`, why: "When it expires, every visitor gets a security error.", fix: "Renew the certificate now and turn on automatic renewal." },
      );
    }
    const modern = t.protocol === "TLSv1.3" || t.protocol === "TLSv1.2";
    add({
      id: "KS-03", title: "Modern encryption (TLS 1.2 or newer)", severity: "medium", status: modern ? "pass" : "fail",
      evidence: `Negotiated ${t.protocol ?? "an unknown protocol"}.`,
      why: "TLS 1.0 and 1.1 have known weaknesses and are refused by current browsers.",
      fix: modern ? "Nothing to do." : "Disable TLS 1.0 and 1.1 in your web server or CDN settings and allow TLS 1.2 and 1.3.",
    });
  }
  if (page && page.status >= 400) {
    add({
      id: "KS-00", title: "Home page did not load", severity: "info", status: "info",
      evidence: `https://${hostname}/ answered HTTP ${page.status}. The header checks below describe that error page, which may come from your host rather than your site.`,
      why: "If your site is down or misconfigured, visitors see an error and the results below may not reflect your real pages.",
      fix: "Make sure the site is running, then scan again.",
    });
  }
  if (https?.offsite) {
    add({
      id: "KS-00", title: "Site redirects to another domain", severity: "info", status: "info",
      evidence: `https://${hostname}/ redirects to ${https.offsite}. We only checked ${hostname}; verify and scan that domain separately.`,
      why: "Kompile Scan only checks domains you have proven you own.", fix: "Add the destination domain as its own site if it is yours.",
    });
  }

  // 2. Plain HTTP must redirect to HTTPS.
  try {
    const plain = await req(`http://${hostname}/`, { ...net, maxBodyBytes: 4096 });
    const loc = header(plain, "location") ?? "";
    const upgrades = isRedirect(plain.status) && loc.startsWith("https://");
    add({
      id: "KS-04", title: "HTTP redirects to HTTPS", severity: "medium", status: upgrades ? "pass" : "fail",
      evidence: upgrades ? `http:// answers ${plain.status} to ${loc.slice(0, 120)}.` : `http://${hostname}/ answered ${plain.status} without moving visitors to HTTPS.`,
      why: "People who type your address or follow old links land on the unencrypted version, where their traffic can be read or changed.",
      fix: "Make every http:// request permanently redirect (301 or 308) to the same https:// address.",
    });
  } catch {
    add({ id: "KS-04", title: "HTTP redirects to HTTPS", severity: "medium", status: "info", evidence: "Port 80 did not answer. That is fine if HSTS is set (see below).", why: "Visitors who type the address without https need a way to reach the secure site.", fix: "Either redirect port 80 to HTTPS or rely on HSTS preloading." });
  }

  if (page) {
    // 3. Security headers.
    const hsts = header(page, "strict-transport-security");
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts ?? "")?.[1] ?? 0);
    add({
      id: "KS-05", title: "Browsers are told to always use HTTPS (HSTS)", severity: "medium",
      status: !hsts ? "fail" : maxAge >= 15_552_000 ? "pass" : "warn",
      evidence: hsts ? `Strict-Transport-Security: ${hsts.slice(0, 160)}` : "No Strict-Transport-Security header.",
      why: "Without HSTS, an attacker on the network can quietly downgrade a visitor to plain HTTP on their first request.",
      fix: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once every page works over HTTPS.",
    });
    const csp = header(page, "content-security-policy");
    const weakCsp = csp && /script-src[^;]*'unsafe-inline'/.test(csp) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(csp);
    add({
      id: "KS-06", title: "Content Security Policy limits what scripts can run", severity: "medium",
      status: !csp ? "fail" : weakCsp || /'unsafe-eval'/.test(csp) ? "warn" : "pass",
      evidence: csp ? `Content-Security-Policy: ${csp.slice(0, 200)}${csp.length > 200 ? "..." : ""}` : "No Content-Security-Policy header.",
      why: "If an attacker gets a script onto your page (cross-site scripting), a CSP is what stops it from running or sending data away.",
      fix: csp ? "Remove 'unsafe-inline' and 'unsafe-eval' from script-src; use nonces or hashes for the inline scripts you need." : "Start with Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self' and loosen only what your site needs.",
    });
    const xfo = header(page, "x-frame-options");
    const frameAncestors = csp && /frame-ancestors/.test(csp);
    add({
      id: "KS-07", title: "Other sites cannot frame your pages (clickjacking)", severity: "medium", status: xfo || frameAncestors ? "pass" : "fail",
      evidence: xfo ? `X-Frame-Options: ${xfo}` : frameAncestors ? "CSP frame-ancestors is set." : "Neither X-Frame-Options nor CSP frame-ancestors is set.",
      why: "A hostile page can load yours invisibly and trick visitors into clicking buttons they cannot see.",
      fix: "Send X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.",
    });
    const nosniff = (header(page, "x-content-type-options") ?? "").toLowerCase().includes("nosniff");
    add({ id: "KS-08", title: "Browsers will not guess file types", severity: "low", status: nosniff ? "pass" : "fail", evidence: nosniff ? "X-Content-Type-Options: nosniff" : "No X-Content-Type-Options: nosniff header.", why: "Without it, a browser may run an uploaded file as a script.", fix: "Send X-Content-Type-Options: nosniff on every response." });
    const rp = header(page, "referrer-policy");
    add({ id: "KS-09", title: "Referrer policy limits what leaks in links", severity: "low", status: rp ? "pass" : "warn", evidence: rp ? `Referrer-Policy: ${rp}` : "No Referrer-Policy header (browsers use their default).", why: "Full addresses, sometimes with tokens or private paths, can leak to every site you link to.", fix: "Send Referrer-Policy: strict-origin-when-cross-origin." });

    // 4. Cookies.
    const cookieIssues: string[] = [];
    for (const c of page.setCookies) {
      const name = c.split("=")[0].trim();
      const attrs = c.toLowerCase();
      const missing = [!/;\s*secure/.test(attrs) && "Secure", SESSIONISH.test(name) && !/;\s*httponly/.test(attrs) && "HttpOnly", !/;\s*samesite=/.test(attrs) && "SameSite"].filter(Boolean);
      if (missing.length) cookieIssues.push(`${name.slice(0, 40)} is missing ${missing.join(", ")}`);
    }
    if (page.setCookies.length) {
      add({
        id: "KS-10", title: "Cookies are protected", severity: "medium", status: cookieIssues.length ? "fail" : "pass",
        evidence: cookieIssues.length ? cookieIssues.slice(0, 5).join("; ") + "." : `${page.setCookies.length} cookie(s) set with the right flags.`,
        why: "Secure keeps cookies off plain HTTP, HttpOnly keeps login cookies away from injected scripts, and SameSite blocks many cross-site request forgeries.",
        fix: "Set cookies with Secure; HttpOnly (for anything that keeps someone logged in); SameSite=Lax.",
      });
    }

    // 5. Version disclosure.
    const leaks = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
      .map((h) => [h, header(page, h)] as const)
      // Only real version numbers count: "X-Powered-By: Express" names the tool but gives no version to look up.
      .filter(([, v]) => v && /\d/.test(v));
    add({
      id: "KS-11", title: "Server does not advertise software versions", severity: "low", status: leaks.length ? "fail" : "pass",
      evidence: leaks.length ? leaks.map(([h, v]) => `${h}: ${String(v).slice(0, 60)}`).join("; ") : "No version numbers in response headers.",
      why: "Exact versions tell attackers which known bugs to try first.",
      fix: "Hide version headers (for example server_tokens off in nginx, ServerTokens Prod in Apache, remove X-Powered-By in your framework).",
    });

    // 6. Directory listings: the home page, folders robots.txt asks crawlers to skip, and folders often left open.
    {
      const origin = new URL(page.url).origin;
      const listed: string[] = LISTING_SIGNATURE.test(page.body) ? ["/"] : [];
      const robots = await req(`${origin}/robots.txt`, { ...net, maxBodyBytes: 16 * 1024, timeoutMs: 5_000 }).catch(() => null);
      const fromRobots = robots && robots.status === 200 && !looksHtml(robots)
        ? [...robots.body.matchAll(/^\s*Disallow:\s*(\/[^\s*?$#]+)/gim)].map((m) => m[1]).slice(0, 10)
        : [];
      const candidates = [...new Set([...fromRobots, ...LISTING_PATHS].map((p) => (p.endsWith("/") ? p : `${p}/`)))];
      for (let i = 0; i < candidates.length; i += 4) {
        const batch = candidates.slice(i, i + 4);
        const rs = await Promise.all(batch.map((p) => req(`${origin}${p}`, { ...net, maxBodyBytes: 16 * 1024, timeoutMs: 5_000 }).catch(() => null)));
        rs.forEach((r, j) => {
          if (r && r.status === 200 && LISTING_SIGNATURE.test(r.body)) listed.push(batch[j]);
        });
      }
      add({
        id: "KS-16", title: "Folder contents are not listed", severity: "medium", status: listed.length ? "fail" : "pass",
        evidence: listed.length ? `Automatic file listings at ${listed.join(", ")}.` : `No automatic file listings on the home page or ${candidates.length} common and robots.txt folders.`,
        why: "Anyone can browse and download every file in the folder, including backups and logs nobody meant to publish. Listing a folder in robots.txt does not hide it; it points people to it.",
        fix: "Turn off directory listing (Options -Indexes in Apache, autoindex off in nginx, remove serve-index in Express) and move private files out of the public folder.",
      });
    }

    // 7. CORS: does the site hand its responses to any website, with cookies?
    try {
      const probeOrigin = "https://kompile-scan-check.invalid";
      const cors = await req(https!.res.url, { ...net, headers: { origin: probeOrigin }, maxBodyBytes: 2048 });
      const acao = header(cors, "access-control-allow-origin");
      const creds = (header(cors, "access-control-allow-credentials") ?? "").toLowerCase() === "true";
      const reflects = acao === probeOrigin;
      add({
        id: "KS-13", title: "Other websites cannot read your pages as your visitors", severity: "high",
        status: reflects && creds ? "fail" : reflects ? "warn" : "pass",
        evidence: reflects ? `Any origin is echoed back in Access-Control-Allow-Origin${creds ? ", with credentials allowed" : ""}.` : acao ? `Access-Control-Allow-Origin: ${acao.slice(0, 80)}` : "No cross-origin access granted.",
        why: "If any website may read your responses with the visitor's cookies, a malicious page can pull their private data from your site.",
        fix: "Only allow the exact origins you trust, and never combine a reflected origin with Access-Control-Allow-Credentials: true.",
      });
    } catch {
      // Non-fatal; the main page already loaded.
    }
  }

  // 7b. Secret keys shipped to the browser (the most common mistake in AI-built apps).
  if (page) {
    const origin = new URL(page.url).origin;
    const srcs = [...page.body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
      .map((m) => {
        try {
          return new URL(m[1], page.url);
        } catch {
          return null;
        }
      })
      .filter((u): u is URL => Boolean(u) && u!.origin === origin)
      .slice(0, 8);
    const bodies: Array<[string, string]> = [["the page HTML", page.body]];
    for (const u of srcs) {
      if (Date.now() - started > (opts.budgetMs ?? 45_000)) break;
      const r = await req(u.toString(), { ...net, maxBodyBytes: 1_500_000, timeoutMs: 8_000 }).catch(() => null);
      if (r && r.status === 200) bodies.push([u.pathname.slice(0, 80), r.body]);
    }
    const leaks: string[] = [];
    for (const [where, text] of bodies) {
      for (const [label, re] of SECRET_KEY_PATTERNS) {
        const m = re.exec(text);
        if (m) leaks.push(`${label} (${maskKey(m[0])}) in ${where}`);
      }
    }
    add({
      id: "KS-17", title: "No secret keys are exposed in your JavaScript", severity: "high", status: leaks.length ? "fail" : "pass",
      evidence: leaks.length ? `${leaks.slice(0, 6).join("; ")}. Only a masked prefix is shown.` : `Checked the page and ${bodies.length - 1} script file(s) for secret key formats. None found.`,
      why: "Anything in your JavaScript is readable by every visitor. A secret key there lets anyone spend your money on that service or read your data. AI app builders often put keys in front-end code by mistake.",
      fix: leaks.length
        ? "Rotate (replace) every key listed now, in that provider's dashboard. Then move the calls that need it to your server or a serverless function, and keep only public keys (like a Stripe publishable key or Supabase anon key with Row Level Security on) in the browser."
        : "Nothing to do. Keep secret keys on the server only.",
    });

    // 7c. Source maps: the original, readable source code of the front end.
    const mapLeaks: string[] = [];
    for (const [where, text] of bodies.slice(1)) {
      const m = /\/\/[#@] sourceMappingURL=([^\s'"]+\.map)\s*$/m.exec(text);
      if (!m || mapLeaks.length >= 3) continue;
      let mapUrl: URL;
      try {
        mapUrl = new URL(m[1], new URL(where, origin));
      } catch {
        continue;
      }
      if (mapUrl.origin !== origin) continue;
      const r = await req(mapUrl.toString(), { ...net, maxBodyBytes: 64 * 1024, timeoutMs: 6_000 }).catch(() => null);
      if (r && r.status === 200 && /"(sources|mappings)"\s*:/.test(r.body)) mapLeaks.push(mapUrl.pathname.slice(0, 80));
    }
    add({
      id: "KS-18", title: "Your original source code is not downloadable", severity: "medium", status: mapLeaks.length ? "fail" : "pass",
      evidence: mapLeaks.length ? `Source maps are public: ${mapLeaks.join(", ")}.` : `No public source maps found for ${Math.max(bodies.length - 1, 0)} script file(s).`,
      why: "Source maps rebuild your original, commented source code from the minified bundle. Attackers read them to find hidden API routes, admin checks, and keys.",
      fix: "Stop publishing .map files in production (for example productionBrowserSourceMaps: false in Next.js, build.sourcemap: false in Vite), or upload them privately to your error tracker instead.",
    });

    // 7d. Mixed content and unprotected third-party scripts.
    if (new URL(page.url).protocol === "https:") {
      const insecure = [...page.body.matchAll(/<(script|link|iframe|img)[^>]+(src|href)=["'](http:\/\/[^"']+)["']/gi)].map((m) => m[3]).slice(0, 5);
      add({
        id: "KS-19", title: "Everything on the page loads over HTTPS", severity: "medium", status: insecure.length ? "fail" : "pass",
        evidence: insecure.length ? `Loaded over plain HTTP: ${insecure.map((u) => u.slice(0, 80)).join(", ")}.` : "No plain-HTTP resources on the page.",
        why: "A script or stylesheet loaded over HTTP can be swapped by anyone on the network, which defeats HTTPS for the whole page.",
        fix: "Change those URLs to https:// (or protocol-relative to your own domain), and add Content-Security-Policy: upgrade-insecure-requests.",
      });
    }
    const thirdParty = [...page.body.matchAll(/<script\b[^>]*>/gi)]
      .map((m) => m[0])
      .filter((tag) => {
        const src = /src=["']([^"']+)["']/i.exec(tag)?.[1];
        if (!src) return false;
        try {
          return new URL(src, page.url).origin !== origin;
        } catch {
          return false;
        }
      });
    const noSri = thirdParty.filter((tag) => !/\bintegrity=["']sha(256|384|512)-/i.test(tag));
    add({
      id: "KS-20", title: "Third-party scripts are pinned with integrity hashes", severity: "low",
      status: thirdParty.length === 0 ? "pass" : noSri.length ? "warn" : "pass",
      evidence: thirdParty.length === 0 ? "No scripts are loaded from other domains." : `${noSri.length} of ${thirdParty.length} script(s) from other domains have no integrity hash.`,
      why: "If a CDN or analytics provider is compromised, its script runs on your page with full access. An integrity hash makes the browser refuse a modified file.",
      fix: "Add integrity=\"sha384-...\" crossorigin=\"anonymous\" to fixed-version third-party scripts (most CDNs show the hash), or self-host them.",
    });

    // 7f. Scripts from CDNs that were taken over and used to serve malware.
    const scriptHosts = [...page.body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
      .map((m) => {
        try {
          return new URL(m[1], page.url).hostname;
        } catch {
          return "";
        }
      })
      .filter(Boolean);
    const hijacked = [...new Set(scriptHosts.filter((h) => HIJACKED_CDNS.test(h)))];
    add({
      id: "KS-24", title: "No scripts from hijacked CDNs", severity: "high", status: hijacked.length ? "fail" : "pass",
      evidence: hijacked.length ? `Scripts load from ${hijacked.join(", ")}, which were taken over and used to serve malware.` : "No scripts load from known hijacked CDNs (such as polyfill.io).",
      why: "In 2024 the polyfill.io domain was sold and started sending malicious code to more than 100,000 sites. Anything your page loads from such a domain runs with full access.",
      fix: "Remove the script tag. Modern browsers rarely need polyfills; if you do, use cdnjs.cloudflare.com/polyfill or self-host a pinned copy.",
    });

    // 7g. Front-end libraries with known security fixes (version from file names, CDN URLs and license banners).
    const outdated = new Map<string, string>();
    // Library banners sit at the top of each file, so only the first few kilobytes of each script are checked.
    const haystacks = [page.body, ...bodies.slice(1).map(([, t]) => t.slice(0, 4000))];
    for (const text of haystacks) {
      for (const lib of VULN_LIBS) {
        const m = lib.re.exec(text);
        const v = m?.slice(1).find((g) => g && /^\d+\.\d+\.\d+$/.test(g));
        if (v && versionBelow(v, lib.fixed) && !outdated.has(lib.name)) outdated.set(lib.name, `${lib.name} ${v} (${lib.advisory})`);
      }
    }
    add({
      id: "KS-25", title: "Front-end libraries are not known-vulnerable versions", severity: "medium", status: outdated.size ? "fail" : "pass",
      evidence: outdated.size ? `${[...outdated.values()].join("; ")}.` : "No known-vulnerable versions of common libraries (jQuery, Lodash, Bootstrap, Moment, Handlebars, DOMPurify, AngularJS) were found.",
      why: "Old library versions have published bugs, usually cross-site scripting, with public exploit code. AI tools often paste in old CDN links from their training data.",
      fix: "Update each library to its latest version (or at least the fixed version in its advisory), then re-run the scan.",
    });

    // 7h. Next.js versions with critical published advisories (version read from the shipped runtime; no exploit is ever sent).
    let nextVersion: string | undefined;
    for (const [, text] of bodies) {
      const m = /window\.next\s*=\s*\{\s*version\s*:\s*["'](\d+\.\d+\.\d+)/.exec(text) ?? /"next"\s*:\s*\{\s*"version"\s*:\s*"(\d+\.\d+\.\d+)/.exec(text);
      if (m) {
        nextVersion = m[1];
        break;
      }
    }
    if (nextVersion) {
      const issues: string[] = [];
      const [maj, min] = nextVersion.split(".").map(Number);
      const mwFixed: Record<number, string> = { 12: "12.3.5", 13: "13.5.9", 14: "14.2.25", 15: "15.2.3" };
      if (mwFixed[maj] && versionBelow(nextVersion, mwFixed[maj])) issues.push("CVE-2025-29927 (middleware authorization bypass, critical; affects self-hosted apps)");
      const rscFixed: Record<string, string> = { "15.0": "15.0.5", "15.1": "15.1.9", "15.2": "15.2.6", "15.3": "15.3.6", "15.4": "15.4.8", "15.5": "15.5.7", "16.0": "16.0.7" };
      const line = rscFixed[`${maj}.${min}`];
      if (line && versionBelow(nextVersion, line)) issues.push("CVE-2025-55182 (React Server Components remote code execution, critical)");
      // Every release npm marks as having a security vulnerability, as the first safe version per line ("" = whole line is affected).
      // Taken from the npm registry's deprecation flags on 10/13/2026.
      const npmSafe: Record<string, string> = {
        "13.3": "", "13.4": "", "13.5": "13.5.11", "14.0": "", "14.1": "", "14.2": "14.2.35", "15.0": "15.0.7", "15.1": "15.1.11",
        "15.2": "15.2.8", "15.3": "15.3.8", "15.4": "15.4.10", "15.5": "15.5.9", "16.0": "16.0.10",
      };
      const safe = npmSafe[`${maj}.${min}`];
      if (safe !== undefined && (safe === "" || versionBelow(nextVersion, safe)) && issues.length === 0) {
        issues.push(safe ? `npm marks this version as vulnerable (fixed in ${safe}, see the Next.js security update of December 2025)` : "npm marks every release of this version line as vulnerable; move to a supported line");
      }
      add({
        id: "KS-26", title: "Framework version has no critical known vulnerabilities", severity: "high", status: issues.length ? "fail" : "pass",
        evidence: issues.length ? `Next.js ${nextVersion}: ${issues.join("; ")}.` : `Next.js ${nextVersion} has no critical advisories we track.`,
        why: "These advisories let attackers skip your login checks or run code on your server. Exploits are public and automated.",
        fix: "Upgrade Next.js to the latest patch release for your version line (npm i next@latest), redeploy, and re-run the scan.",
      });
    }

    signals = collectSignals(page, bodies, scriptHosts, origin, nextVersion);
  }

  // 7e. Error pages that reveal internals (one ordinary request for a page that does not exist).
  if (page) {
    const base404 = new URL(page.url).origin;
    // One missing page at the root and one under /api/, where back ends usually live behind a single-page app.
    const tag = Date.now().toString(36);
    const probes = await Promise.all(
      // The third is an ordinary request with a "[" in the query, which some servers (Tomcat) answer with a full exception.
      [`/kompile-scan-not-found-${tag}`, `/api/kompile-scan-not-found-${tag}`, `/?kompile-scan=[`].map((p) => req(`${base404}${p}`, { ...net, maxBodyBytes: 64 * 1024, timeoutMs: 6_000 }).catch(() => null)),
    );
    // A single-page app answers every path with its home page; text there (a blog post quoting a
    // traceback, say) is not an error page, so only judge bodies that differ from the home page.
    let probe: SafeResponse | null = null;
    let hit: [string, RegExp] | undefined;
    for (const r of probes) {
      if (!r || r.body === page.body) continue;
      hit = DEBUG_SIGNATURES.find(([, re]) => re.test(r.body));
      if (hit) {
        probe = r;
        break;
      }
    }
    add({
      id: "KS-21", title: "Error pages do not reveal internals", severity: "medium", status: hit ? "fail" : "pass",
      evidence: hit ? `A request for a missing page returned ${hit[0]} (HTTP ${probe!.status}).` : "Error pages show no stack traces, file paths, or debug output.",
      why: "Debug pages and stack traces hand attackers your file layout, framework versions, and sometimes environment variables and database queries.",
      fix: "Turn off debug mode in production (DEBUG=False in Django, APP_DEBUG=false in Laravel, NODE_ENV=production in Node) and show a plain error page.",
    });

    const docs: string[] = [];
    for (const p of API_DOC_PATHS) {
      const r = await req(`${base404}${p}`, { ...net, maxBodyBytes: 32 * 1024, timeoutMs: 5_000 }).catch(() => null);
      if (r && r.status === 200 && /"(openapi|swagger)"\s*:\s*"\d/.test(r.body)) docs.push(p);
    }
    for (const p of API_UI_PATHS) {
      if (docs.length) break;
      const r = await req(`${base404}${p}`, { ...net, maxBodyBytes: 32 * 1024, timeoutMs: 5_000 }).catch(() => null);
      if (r && r.status === 200 && r.body !== page.body && API_UI_SIGNATURE.test(r.body)) docs.push(`${p} (interactive explorer)`);
    }
    add({
      id: "KS-22", title: "API documentation is not public by accident", severity: "low", status: docs.length ? "warn" : "pass",
      evidence: docs.length ? `A machine-readable API description is public at ${docs.join(", ")}.` : "No public OpenAPI or Swagger description found at the usual paths.",
      why: "A public API description lists every endpoint, including ones the user interface never shows. That is fine for public APIs and a map for attackers otherwise.",
      fix: "If the API is not meant to be public, serve its documentation only to signed-in staff or disable it in production.",
    });

    // 7i. Admin, database and AI tool panels reachable from the internet (fingerprint only; never a login attempt).
    const panels: string[] = [];
    const panelPaths = [...new Set(PANELS.map((p) => p.path).filter((p) => p !== "/"))];
    const panelBodies = new Map<string, string>([["/", page.body]]);
    for (let i = 0; i < panelPaths.length; i += 4) {
      if (Date.now() - started > (opts.budgetMs ?? 45_000)) break;
      const batch = panelPaths.slice(i, i + 4);
      const rs = await Promise.all(batch.map((p) => req(`${base404}${p}`, { ...net, maxBodyBytes: 32 * 1024, timeoutMs: 5_000 }).catch(() => null)));
      rs.forEach((r, j) => {
        if (r && r.status === 200 && r.body !== page.body) panelBodies.set(batch[j], r.body);
      });
    }
    for (const p of PANELS) {
      const body = panelBodies.get(p.path);
      if (body && p.re.test(body) && !panels.includes(p.label)) panels.push(`${p.label} at ${p.path}`);
    }
    add({
      id: "KS-27", title: "No admin or developer panels are open to the internet", severity: "high", status: panels.length ? "fail" : "pass",
      evidence: panels.length ? `${panels.join("; ")}. We only looked at the page title; we never try to log in.` : `Checked ${PANELS.length} common database, admin and AI tool panels. None were reachable.`,
      why: "Database admins, notebook servers and AI tool dashboards are built for trusted networks. Bots find them within hours and try default passwords or known exploits; some (Ollama, Jupyter) need no password at all.",
      fix: "Put the tool behind a VPN, an IP allowlist or your hosting provider's access protection, or move it off the public internet entirely.",
    });

    // 7j. GraphQL explorers and schema introspection left on (GET only: one read-only schema question).
    const gql: string[] = [];
    for (const p of ["/graphql", "/api/graphql"]) {
      if (Date.now() - started > (opts.budgetMs ?? 45_000)) break;
      const ide = await req(`${base404}${p}`, { ...net, headers: { accept: "text/html" }, maxBodyBytes: 32 * 1024, timeoutMs: 5_000 }).catch(() => null);
      if (ide && ide.status === 200 && ide.body !== page.body && /<title>[^<]*(GraphiQL|GraphQL Playground|Apollo Sandbox|Altair|Voyager)/i.test(ide.body)) gql.push(`an interactive GraphQL explorer at ${p}`);
      const intro = await req(`${base404}${p}?query=${encodeURIComponent("{__schema{queryType{name}}}")}`, { ...net, headers: { accept: "application/json", "apollo-require-preflight": "true" }, maxBodyBytes: 16 * 1024, timeoutMs: 5_000 }).catch(() => null);
      if (intro && intro.status === 200 && /"__schema"\s*:\s*\{/.test(intro.body)) gql.push(`schema introspection at ${p}`);
    }
    add({
      id: "KS-28", title: "GraphQL schema is not open to everyone", severity: "medium", status: gql.length ? "warn" : "pass",
      evidence: gql.length ? `Found ${gql.join(" and ")}.` : "No GraphQL explorer or open introspection at /graphql or /api/graphql.",
      why: "Introspection hands anyone the full list of your queries, mutations and fields, including admin ones the app never shows. Explorers make trying them effortless.",
      fix: "Turn off introspection and the explorer in production (for example introspection: false in Apollo Server) unless the API is meant to be public.",
    });
  }

  // 8. Files that should never be public.
  const exposed: string[] = [];
  const base = page ? new URL(page.url).origin : `https://${hostname}`;
  // An app mounted under a path (Tomcat contexts, reverse-proxy prefixes) has its own copies of these files.
  const appBase = basePath && basePath !== "/" ? `${base}${basePath.replace(/\/+$/, "")}` : null;
  const jobs = [...PROBES.map((p) => ({ p, url: `${base}${p.path}`, shown: p.path })), ...(appBase ? PROBES.map((p) => ({ p, url: `${appBase}${p.path}`, shown: `${basePath!.replace(/\/+$/, "")}${p.path}` })) : [])];
  for (let i = 0; i < jobs.length; i += 4) {
    if (Date.now() - started > (opts.budgetMs ?? 45_000)) break;
    const batch = jobs.slice(i, i + 4);
    const results = await Promise.all(batch.map((j) => req(j.url, { ...net, maxBodyBytes: 8192, timeoutMs: 6_000 }).catch(() => null)));
    results.forEach((r, k) => {
      if (r && batch[k].p.matches(r)) exposed.push(`${batch[k].shown} looks like ${batch[k].p.label}`);
    });
  }
  add({
    id: "KS-12", title: "No sensitive files are publicly downloadable", severity: "high", status: exposed.length ? "fail" : "pass",
    evidence: exposed.length ? `${exposed.join(". ")}. We did not read or store the contents.` : `Checked ${PROBES.length} common leak locations (.env, .git, backups, server status pages). None were exposed.`,
    why: "These files routinely contain passwords, API keys, or the full source code. Bots scan the whole internet for them every day.",
    fix: exposed.length ? "Remove these files from the public web folder or block them in your server config, then change any password or key they contained, because it must be treated as stolen." : "Nothing to do.",
  });

  // 9. security.txt and email spoofing protection (informational and low).
  try {
    const st = await req(`${base}/.well-known/security.txt`, { ...net, maxBodyBytes: 4096, timeoutMs: 5_000 });
    const has = st.status === 200 && /contact:/i.test(st.body);
    add({ id: "KS-14", title: "Security contact published (security.txt)", severity: "info", status: has ? "pass" : "info", evidence: has ? "Found /.well-known/security.txt with a contact." : "No /.well-known/security.txt.", why: "It tells people who find a problem how to reach you privately.", fix: "Publish /.well-known/security.txt with a Contact: line (see securitytxt.org)." });
  } catch {
    // Optional.
  }
  const txt = opts.dns?.txt ?? resolveTxt;
  const mx = opts.dns?.mx ?? resolveMx;
  const hasMail = await mx(hostname).then((r) => r.length > 0).catch(() => false);
  if (hasMail) {
    const dmarc = await txt(`_dmarc.${hostname}`).then((r) => r.map((c) => c.join("")).find((v) => /^v=DMARC1/i.test(v))).catch(() => undefined);
    const spf = await txt(hostname).then((r) => r.map((c) => c.join("")).find((v) => /^v=spf1/i.test(v))).catch(() => undefined);
    add({
      id: "KS-15", title: "Others cannot easily send email as your domain", severity: "low", status: dmarc && spf ? "pass" : "fail",
      evidence: [spf ? "SPF record found" : "No SPF record", dmarc ? `DMARC policy ${/p=(\w+)/i.exec(dmarc)?.[1] ?? "set"}` : "No DMARC record"].join("; ") + ".",
      why: "Without SPF and DMARC, scammers can send convincing email that appears to come from your domain.",
      fix: "Publish an SPF record listing your mail providers and a DMARC record (start with v=DMARC1; p=none; rua=mailto:you@yourdomain, then move to quarantine).",
    });
  }

  // 10. CAA: which certificate authorities may issue certificates for this domain (checked up the tree).
  const caa = opts.dns?.caa ?? resolveCaa;
  const labels = hostname.split(".");
  let caaAt: string | null = null;
  for (let i = 0; i < labels.length - 1 && !caaAt; i++) {
    const name = labels.slice(i).join(".");
    const recs = await caa(name).catch(() => []);
    if (recs.some((r) => "issue" in r || "issuewild" in r)) caaAt = name;
  }
  add({
    id: "KS-23", title: "Only your chosen certificate authorities can issue certificates", severity: "low", status: caaAt ? "pass" : "warn",
    evidence: caaAt ? `CAA record found on ${caaAt}.` : "No CAA record: any certificate authority may issue a certificate for this domain.",
    why: "A CAA record limits who can issue HTTPS certificates for your domain, which makes a fraudulently issued certificate much harder to obtain.",
    fix: "Add a CAA DNS record for the authority you use, for example: 0 issue \"letsencrypt.org\" (most DNS providers have a CAA record type).",
  });

  // 11. Forgotten subdomains that can be taken over: names from public certificate logs, then DNS, then at most one
  // ordinary page request per subdomain. Only names under the verified hostname are looked at.
  if (opts.subdomains !== false && Date.now() - started < (opts.budgetMs ?? 45_000)) {
    const cname = opts.dns?.cname ?? resolveCname;
    const a4 = opts.dns?.a ?? resolve4;
    const names = await (opts.ctNames ?? ((h: string) => ctSubdomains(req, h, net)))(hostname).catch(() => [] as string[]);
    const risky: string[] = [];
    for (const name of names.slice(0, 25)) {
      if (Date.now() - started > (opts.budgetMs ?? 45_000)) break;
      const target = (await cname(name).catch(() => [] as string[]))[0]?.toLowerCase().replace(/\.$/, "");
      if (!target) continue;
      const provider = TAKEOVER_PROVIDERS.find((p) => p.cname.test(target));
      if (!provider) continue;
      const targetGone = await a4(target).then((r) => r.length === 0).catch((e: NodeJS.ErrnoException) => e.code === "ENOTFOUND" || e.code === "ENODATA");
      let unclaimed = targetGone && provider.nxdomainMeansOpen;
      if (!unclaimed && provider.body) {
        const r = await req(`https://${name}/`, { ...net, maxBodyBytes: 16 * 1024, timeoutMs: 5_000 })
          .catch(() => req(`http://${name}/`, { ...net, maxBodyBytes: 16 * 1024, timeoutMs: 5_000 }))
          .catch(() => null);
        unclaimed = Boolean(r && provider.body.test(r.body));
      }
      if (unclaimed) risky.push(`${name} points to ${provider.name} (${target}), which is unclaimed`);
    }
    add({
      id: "KS-29", title: "No forgotten subdomains can be taken over", severity: "high", status: risky.length ? "fail" : "pass",
      evidence: risky.length ? `${risky.slice(0, 5).join("; ")}.` : names.length ? `Checked ${Math.min(names.length, 25)} subdomain(s) from public certificate logs. None point to an unclaimed service.` : "No subdomains found in public certificate logs.",
      why: "When you delete a project on GitHub Pages, Heroku, Netlify, S3 or Azure but keep its DNS record, anyone can claim that name on the provider and serve their own page, phishing form or cookie stealer on your domain.",
      fix: "Delete the DNS record (CNAME) for each listed subdomain, or re-create the project on the provider so you own the name again.",
    });
  }

  const { score, grade } = scoreFindings(findings);
  return { hostname, finalUrl: page?.url ?? `https://${hostname}/`, score, grade, findings, durationMs: Date.now() - started, scannerVersion: SCANNER_VERSION, signals };
}
