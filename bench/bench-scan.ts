/**
 * Kompile Scan benchmark. Spins up local sites with KNOWN planted problems (and
 * clean sites built to trap false alarms), runs the real checks against each,
 * and scores every check: true/false positives, recall, precision, timing.
 *
 *   npx tsx bench/bench-scan.ts            prints the table, writes bench/out/scan-benchmark.json
 *
 * TLS (KS-01..03) and the HTTP redirect (KS-04) are simulated by the harness and
 * not scored here; they are covered by real scans of live sites.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { runScanWith, type Requester, type ScanReport } from "../src/checks";
import { safeRequest } from "../src/net";

// Fake secrets are assembled at runtime so this file never contains a real-looking key.
const k = (...parts: string[]) => parts.join("");
const FAKE = {
  stripe: k("sk", "_live_", "Zq9X".repeat(7)),
  openai: k("sk-", "proj-", "aB3d".repeat(10)),
  aws: k("AK", "IA", "QWERTYUIOP123456"),
  supabaseService: k("eyJhbGciOiJIUzI1NiJ9.", "eyJyb2xlIjoic2VydmljZV9yb2xlIn0", ".c2ln"),
  supabaseAnon: k("eyJhbGciOiJIUzI1NiJ9.", "eyJyb2xlIjoiYW5vbiJ9", ".c2ln"),
  publishable: k("pk", "_live_", "Ab12".repeat(7)),
  groq: k("gsk", "_", "Ab3d".repeat(13)),
  clerkPublishable: k("pk", "_live_", "Y2xlcmsuZXhhbXBsZS5jb20k"),
};

export interface Site {
  name: string;
  headers?: boolean; // full hardened headers
  env?: boolean;
  git?: boolean;
  sqlDump?: boolean;
  zipBackup?: boolean;
  dsStore?: boolean;
  secret?: keyof typeof FAKE;
  sourceMap?: "public" | "missing";
  mixed?: boolean;
  thirdPartyNoSri?: boolean;
  debug?: "python" | "node" | "django" | "laravel";
  apiDocs?: boolean;
  corsCreds?: boolean;
  versions?: boolean;
  weakCookie?: boolean;
  catchAll?: boolean;
  blogTraceback?: boolean;
  caa?: boolean;
  mail?: "none" | "protected" | "unprotected";
  /** Folder listing in a folder named by robots.txt, or in a commonly open folder. */
  listing?: "robots" | "common";
  /** robots.txt points at a normal sign-in page (must not be flagged). */
  robotsAdmin?: boolean;
  metrics?: "prometheus" | "marketing-page";
  actuator?: boolean;
  /** Only /api/* answers with an Express debug page; the rest is a single-page app. */
  apiExpressDebug?: boolean;
  swaggerUi?: boolean;
  /** Tomcat-style server: "[" in a query gives an exception report; missing pages give its plain status report. */
  tomcat?: "exception-on-bad-char" | "plain-404";
  actuatorIndex?: boolean;
  /** App mounted under /app with nothing at the root; the owner sets basePath. */
  subApp?: "leaky" | "clean";
  /** A real Dockerfile, or a page that merely mentions one. */
  dockerfile?: "public" | "blog-mentions";
  /** Extra HTML inside the home page, extra JS inside /assets/app.js, and extra fixed routes. */
  homeExtra?: string;
  jsExtra?: string;
  routes?: Record<string, { status?: number; type?: string; body: string }>;
  /** Non-security response headers that make a site look like a given host (for example x-vercel-id). */
  extraHeaders?: Record<string, string>;
  /** Subdomains "seen in certificate logs", each with its CNAME and whether the target still exists. */
  subs?: Record<string, { cname?: string; targetLive?: boolean }>;
  basePath?: string;
  /** Check ids that must be flagged (fail or warn). Everything else scored must pass. */
  expect: string[];
}

const HARDENED: Record<string, string> = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
};

const clean = (name: string, extra: Partial<Site> = {}): Site => ({ name, headers: true, caa: true, mail: "none", expect: [], ...extra });

export const CORPUS: Site[] = [
  clean("clean-hardened"),
  clean("clean-with-mail", { mail: "protected" }),
  // One planted problem each.
  clean("env-file", { env: true, expect: ["KS-12"] }),
  clean("git-folder", { git: true, expect: ["KS-12"] }),
  clean("sql-dump", { sqlDump: true, expect: ["KS-12"] }),
  clean("zip-backup", { zipBackup: true, expect: ["KS-12"] }),
  clean("ds-store", { dsStore: true, expect: ["KS-12"] }),
  clean("stripe-secret-in-js", { secret: "stripe", expect: ["KS-17"] }),
  clean("openai-key-in-js", { secret: "openai", expect: ["KS-17"] }),
  clean("aws-key-in-js", { secret: "aws", expect: ["KS-17"] }),
  clean("supabase-service-role-in-js", { secret: "supabaseService", expect: ["KS-17"] }),
  clean("public-source-map", { sourceMap: "public", expect: ["KS-18"] }),
  // The http:// script is also third-party with no integrity hash, so KS-20 is a correct second finding.
  clean("mixed-content", { mixed: true, expect: ["KS-19", "KS-20"] }),
  clean("cdn-without-sri", { thirdPartyNoSri: true, expect: ["KS-20"] }),
  clean("python-traceback", { debug: "python", expect: ["KS-21"] }),
  clean("node-stack-trace", { debug: "node", expect: ["KS-21"] }),
  clean("django-debug", { debug: "django", expect: ["KS-21"] }),
  clean("laravel-debug", { debug: "laravel", expect: ["KS-21"] }),
  clean("public-openapi", { apiDocs: true, expect: ["KS-22"] }),
  clean("cors-reflects-with-credentials", { corsCreds: true, expect: ["KS-13"] }),
  clean("version-banners", { versions: true, expect: ["KS-11"] }),
  clean("weak-session-cookie", { weakCookie: true, expect: ["KS-10"] }),
  clean("no-caa", { caa: false, expect: ["KS-23"] }),
  clean("email-spoofable", { mail: "unprotected", expect: ["KS-15"] }),
  { name: "no-security-headers", headers: false, caa: true, mail: "none", expect: ["KS-05", "KS-06", "KS-07", "KS-08", "KS-09"] },
  // Traps: none of these may be flagged.
  clean("trap-spa-catch-all", { catchAll: true }),
  clean("trap-publishable-key-only", { secret: "publishable" }),
  clean("trap-supabase-anon-key", { secret: "supabaseAnon" }),
  clean("trap-missing-source-map", { sourceMap: "missing" }),
  clean("trap-blog-quotes-traceback", { catchAll: true, blogTraceback: true }),
  // Added after the Juice Shop comparison (10/12): one site per new rule, plus traps for each.
  clean("listing-in-robots-folder", { listing: "robots", expect: ["KS-16"] }),
  clean("listing-in-uploads", { listing: "common", expect: ["KS-16"] }),
  clean("prometheus-metrics", { metrics: "prometheus", expect: ["KS-12"] }),
  clean("spring-actuator-env", { actuator: true, expect: ["KS-12"] }),
  clean("express-debug-under-api", { catchAll: true, apiExpressDebug: true, expect: ["KS-21"] }),
  clean("swagger-ui-public", { swaggerUi: true, expect: ["KS-22"] }),
  clean("trap-robots-points-at-login", { robotsAdmin: true }),
  clean("trap-metrics-marketing-page", { metrics: "marketing-page" }),
  // Added after the blind WebGoat test (10/12), which Nuclei won: one site per new rule, plus a trap.
  clean("tomcat-exception-report", { tomcat: "exception-on-bad-char", expect: ["KS-21"] }),
  clean("spring-actuator-index", { actuatorIndex: true, expect: ["KS-12"] }),
  clean("trap-tomcat-plain-404", { tomcat: "plain-404" }),
  // App under a sub-path (the WebGoat gap), scanned with the owner-set start path.
  clean("app-under-path-actuator", { subApp: "leaky", basePath: "/app", expect: ["KS-12"] }),
  clean("trap-app-under-path-clean", { subApp: "clean", basePath: "/app" }),
  // Added after the blind DVWA test (10/12), a tie with Nuclei: the Dockerfile Kompile missed, plus a trap.
  clean("public-dockerfile", { dockerfile: "public", expect: ["KS-12"] }),
  clean("trap-dockerfile-blog-post", { dockerfile: "blog-mentions" }),
  // Added from the 10/12 research into other tools (ZAP, Nuclei, retire.js, Detectify, AI-app studies): one site per new check, plus traps.
  clean("polyfill-io-script", { homeExtra: `<script src="https://polyfill.io/v3/polyfill.min.js" integrity="sha384-x" crossorigin="anonymous"></script>`, expect: ["KS-24"] }),
  clean("old-jquery", { homeExtra: `<script src="https://code.jquery.com/jquery-3.4.1.min.js" integrity="sha384-x" crossorigin="anonymous"></script>`, expect: ["KS-25"] }),
  clean("vulnerable-nextjs", { jsExtra: `window.next={version:"15.2.2",appDir:true};`, expect: ["KS-26"] }),
  clean("open-ollama", { routes: { "/api/tags": { type: "application/json", body: '{"models":[{"name":"llama3:8b"}]}' } }, expect: ["KS-27"] }),
  clean("open-phpmyadmin", { routes: { "/phpmyadmin/": { body: "<!doctype html><title>localhost / phpMyAdmin</title>" } }, expect: ["KS-27"] }),
  clean("graphql-introspection", { routes: { "/graphql": { type: "application/json", body: '{"data":{"__schema":{"queryType":{"name":"Query"}}}}' } }, expect: ["KS-28"] }),
  clean("groq-key-in-js", { secret: "groq", expect: ["KS-17"] }),
  clean("public-vercel-json", { routes: { "/vercel.json": { type: "application/json", body: '{"rewrites":[{"source":"/(.*)","destination":"/"}]}' } }, expect: ["KS-12"] }),
  clean("trap-cdnjs-polyfill", { homeExtra: `<script src="https://cdnjs.cloudflare.com/polyfill/v3/polyfill.min.js" integrity="sha384-x" crossorigin="anonymous"></script>` }),
  clean("trap-current-jquery", { homeExtra: `<script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha384-x" crossorigin="anonymous"></script>` }),
  clean("trap-patched-nextjs", { jsExtra: `window.next={version:"15.5.9",appDir:true};` }),
  clean("trap-normal-login-page", { routes: { "/login": { body: "<!doctype html><title>Sign in to Acme</title><form></form>" } } }),
  clean("trap-graphql-needs-post", { routes: { "/graphql": { status: 400, type: "application/json", body: '{"errors":[{"message":"GET query missing."}]}' } } }),
  clean("trap-clerk-publishable-key", { secret: "clerkPublishable" }),
  clean("dangling-azure-subdomain", { subs: { old: { cname: "kompile-demo-old.azurewebsites.net", targetLive: false }, www: {} }, expect: ["KS-29"] }),
  clean("trap-live-azure-subdomain", { subs: { api: { cname: "kompile-api.azurewebsites.net", targetLive: true } } }),
  clean("trap-unknown-provider-cname", { subs: { docs: { cname: "docs.example-provider.net", targetLive: false } } }),
  // Everything at once.
  {
    name: "worst-case", headers: false, env: true, git: true, secret: "stripe", sourceMap: "public", mixed: true, thirdPartyNoSri: true,
    debug: "python", apiDocs: true, corsCreds: true, versions: true, weakCookie: true, caa: false, mail: "unprotected",
    expect: ["KS-05", "KS-06", "KS-07", "KS-08", "KS-09", "KS-10", "KS-11", "KS-12", "KS-13", "KS-15", "KS-17", "KS-18", "KS-19", "KS-20", "KS-21", "KS-22", "KS-23"],
  },
];

/** Checks scored by this benchmark (TLS and redirect are simulated by the harness). */
export const SCORED = ["KS-05", "KS-06", "KS-07", "KS-08", "KS-09", "KS-10", "KS-11", "KS-12", "KS-13", "KS-15", "KS-16", "KS-17", "KS-18", "KS-19", "KS-20", "KS-21", "KS-22", "KS-23", "KS-24", "KS-25", "KS-26", "KS-27", "KS-28", "KS-29"];

const DEBUG_BODIES = {
  python: 'Traceback (most recent call last):\n  File "/app/main.py", line 42, in handler\nKeyError: "id"',
  node: "Error: not found\n    at Object.<anonymous> (/srv/app/server.js:12:9)\n    at Module._compile (node:internal/modules/cjs/loader:1256:14)",
  django: "<h1>Page not found (404)</h1><p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>",
  laravel: "<title>Whoops! There was an error.</title>",
};

export function handler(site: Site): http.RequestListener {
  return (req, res) => {
    let p: string;
    try {
      p = new URL(req.url ?? "/", "http://site").pathname;
    } catch {
      return res.writeHead(400).end(); // Malformed request line (other scanners send these on purpose).
    }
    const headers: Record<string, string | string[]> = { "content-type": "text/html", ...(site.headers ? HARDENED : {}), ...(site.extraHeaders ?? {}) };
    if (site.versions) Object.assign(headers, { server: "nginx/1.18.0", "x-powered-by": "Express 4.17.1" });
    if (site.weakCookie) headers["set-cookie"] = ["session=abc; Path=/"];
    else if (site.headers) headers["set-cookie"] = ["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"];
    const origin = req.headers.origin;
    if (site.corsCreds && origin) Object.assign(headers, { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" });

    const home = () => {
      const scripts = [
        `<script src="/assets/app.js"></script>`,
        site.mixed ? `<script src="http://cdn.example.net/legacy.js"></script>` : "",
        site.thirdPartyNoSri ? `<script src="https://cdn.example.net/widget@1.0.0/widget.js"></script>` : `<script src="https://cdn.example.net/pinned.js" integrity="sha384-abc" crossorigin="anonymous"></script>`,
      ].join("");
      const blog = site.blogTraceback ? `<article><p>Today I saw this: Traceback (most recent call last): oops</p></article>` : "";
      return `<!doctype html><title>Home</title>${scripts}${blog}${site.homeExtra ?? ""}`;
    };
    const tomcatPage = (kind: string, msg: string) =>
      `<!doctype html><html><head><title>HTTP Status ${kind === "Exception" ? "400 – Bad Request" : "404 – Not Found"}</title></head><body><h1>HTTP Status</h1><p><b>Type</b> ${kind} Report</p><p><b>Message</b> ${msg}</p>${kind === "Exception" ? "<p><b>Exception</b></p><pre>java.lang.IllegalArgumentException: Invalid character found in the request target\n\torg.apache.coyote.http11.Http11InputBuffer.parseRequestLine(Http11InputBuffer.java:494)\n</pre>" : ""}<h3>Apache Tomcat</h3></body></html>`;
    if (site.tomcat === "exception-on-bad-char" && (req.url ?? "").includes("[")) return res.writeHead(400, headers).end(tomcatPage("Exception", "Invalid character found in the request target"));
    if (site.subApp) {
      if (p === "/app" || p === "/app/") return res.writeHead(200, headers).end(home());
      if (p === "/app/assets/app.js" || p === "/assets/app.js") return res.writeHead(200, { ...headers, "content-type": "text/javascript" }).end('console.log("app");');
      if (p === "/app/actuator/env" && site.subApp === "leaky") return res.writeHead(200, { "content-type": "application/json" }).end('{"activeProfiles":[],"propertySources":[]}');
      return res.writeHead(404, headers).end("<!doctype html><title>Not found</title>");
    }
    if (p === "/" || p === "/index.html") return res.writeHead(200, headers).end(home());
    if (p === "/assets/app.js") {
      const body = `console.log("app");${site.jsExtra ?? ""}${site.secret ? `const key="${FAKE[site.secret]}";` : ""}${site.sourceMap ? "\n//# sourceMappingURL=app.js.map" : ""}`;
      return res.writeHead(200, { ...headers, "content-type": "text/javascript" }).end(body);
    }
    if (p === "/assets/app.js.map" && site.sourceMap === "public") return res.writeHead(200, { "content-type": "application/json" }).end('{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}');
    if (p === "/.env" && site.env) return res.writeHead(200, { "content-type": "text/plain" }).end("DB_PASSWORD=x\nAPI_KEY=y\n");
    if (p === "/.git/HEAD" && site.git) return res.writeHead(200).end("ref: refs/heads/main\n");
    // A real exposed repository serves every file in .git, so other scanners' probes must find it too.
    if (p === "/.git/config" && site.git) return res.writeHead(200, { "content-type": "text/plain" }).end('[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/example/app.git\n');
    if (p === "/backup.sql" && site.sqlDump) return res.writeHead(200, { "content-type": "text/plain" }).end("-- MySQL dump 10.13\nCREATE TABLE users (id int);");
    if (p === "/backup.zip" && site.zipBackup) return res.writeHead(200, { "content-type": "application/zip" }).end("PK\u0003\u0004rest");
    const route = site.routes?.[p];
    if (route) return res.writeHead(route.status ?? 200, { ...headers, "content-type": route.type ?? "text/html" }).end(route.body);
    if (p === "/Dockerfile" && site.dockerfile === "public") return res.writeHead(200, { "content-type": "application/octet-stream" }).end("FROM node:22-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD [\"node\", \"server.js\"]\n");
    if (p === "/Dockerfile" && site.dockerfile === "blog-mentions") return res.writeHead(200, headers).end("<!doctype html><title>Our Dockerfile</title><pre>FROM node:22-alpine\nRUN npm ci</pre>");
    if (p === "/.DS_Store" && site.dsStore) return res.writeHead(200, { "content-type": "application/octet-stream", "accept-ranges": "bytes" }).end("\u0000\u0000\u0000\u0001Bud1");
    if (p === "/openapi.json" && site.apiDocs) return res.writeHead(200, { "content-type": "application/json" }).end('{"openapi":"3.1.0","paths":{}}');
    const listingPage = (dir: string) => `<!doctype html><html><head><title>Index of ${dir}</title></head><body><h1>Index of ${dir}</h1><a href="db-backup.tar.gz">db-backup.tar.gz</a></body></html>`;
    if (p === "/robots.txt" && (site.listing === "robots" || site.robotsAdmin)) {
      return res.writeHead(200, { "content-type": "text/plain" }).end(`User-agent: *\nDisallow: ${site.listing === "robots" ? "/private-files" : "/admin"}\n`);
    }
    if (p === "/private-files/" && site.listing === "robots") return res.writeHead(200, headers).end(listingPage("/private-files/"));
    if (p === "/uploads/" && site.listing === "common") return res.writeHead(200, headers).end(listingPage("/uploads/"));
    if ((p === "/admin" || p === "/admin/") && site.robotsAdmin) return res.writeHead(200, headers).end("<!doctype html><title>Sign in</title><form method=post><input name=email></form>");
    if (p === "/metrics" && site.metrics === "prometheus") return res.writeHead(200, { "content-type": "text/plain; version=0.0.4" }).end("# HELP process_cpu_seconds_total Total user and system CPU time.\n# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 1.5\n# HELP process_start_time_seconds Start time.\n# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds 1760000000\n");
    if (p === "/metrics" && site.metrics === "marketing-page") return res.writeHead(200, headers).end("<!doctype html><title>Metrics that matter</title><p># HELP is on the way. # TYPE your email below.</p>");
    if (p === "/actuator" && site.actuatorIndex) return res.writeHead(200, { "content-type": "application/vnd.spring-boot.actuator.v3+json" }).end('{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"}}}');
    if (p === "/actuator/env" && site.actuator) return res.writeHead(200, { "content-type": "application/json" }).end('{"activeProfiles":["prod"],"propertySources":[]}');
    if (p === "/api-docs" && site.swaggerUi) return res.writeHead(301, { ...headers, location: "/api-docs/" }).end();
    if ((p === "/api-docs/" || p === "/swagger-ui/") && site.swaggerUi) return res.writeHead(200, headers).end('<!doctype html><div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script>');
    if (p.startsWith("/api/") && site.apiExpressDebug) {
      return res.writeHead(500, headers).end(`<html><head><title>Error: Unexpected path: ${p}</title></head><body><h1>Error: Unexpected path</h1><ul id="stacktrace"><li> &nbsp; &nbsp;at /srv/app/routes/api.js:41:13</li></ul></body></html>`);
    }
    if (site.catchAll) return res.writeHead(200, headers).end(home());
    if (site.debug) return res.writeHead(500, headers).end(DEBUG_BODIES[site.debug]);
    if (site.tomcat) return res.writeHead(404, headers).end(tomcatPage("Status", "The requested resource is not available"));
    return res.writeHead(404, headers).end("<!doctype html><title>Not found</title>");
  };
}

export async function scanSite(site: Site): Promise<ScanReport> {
  const server = http.createServer(handler(site));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const shim: Requester = async (u, o) => {
    const x = new URL(u);
    const r = await safeRequest(`http://bench.local.test:${port}${x.pathname}${x.search}`, { ...o, unsafeAllowAddress: (a) => a === "127.0.0.1" });
    return x.protocol === "https:"
      ? { ...r, url: u, tls: { authorized: true, authorizationError: null, protocol: "TLSv1.3", validTo: new Date(Date.now() + 80 * 864e5).toUTCString(), issuer: "(bench)" } }
      : { ...r, status: 301, headers: { ...r.headers, location: u.replace("http://", "https://") } };
  };
  const mailTxt = site.mail === "protected" ? [["v=spf1 include:_spf.example.net ~all"], ["v=DMARC1; p=reject"]] : [];
  try {
    return await runScanWith(shim, `${site.name}.bench.test`, {
      dns: {
        mx: async () => (site.mail === "none" ? [] : [{ exchange: "mx.example.net", priority: 10 }]),
        txt: async (name: string) => (name.startsWith("_dmarc.") ? mailTxt.filter((r) => r[0].startsWith("v=DMARC1")) : mailTxt.filter((r) => r[0].startsWith("v=spf1"))),
        caa: async () => (site.caa ? [{ critical: 0, issue: "letsencrypt.org" }] : []),
        cname: async (n: string) => {
          const c = site.subs?.[n.slice(0, n.indexOf("."))]?.cname;
          return c ? [c] : [];
        },
        a: async (n: string) => {
          const live = Object.values(site.subs ?? {}).find((s) => s.cname === n)?.targetLive;
          if (live === false) throw Object.assign(new Error("gone"), { code: "ENOTFOUND" });
          return ["192.0.2.10"];
        },
      } as never,
      ctNames: async (h: string) => Object.keys(site.subs ?? {}).map((s) => `${s}.${h}`),
      budgetMs: 20_000,
      basePath: site.basePath,
    });
  } finally {
    server.close();
  }
}

async function main() {
  const perCheck: Record<string, { tp: number; fp: number; fn: number; tn: number }> = Object.fromEntries(SCORED.map((c) => [c, { tp: 0, fp: 0, fn: 0, tn: 0 }]));
  const sites: Array<{ name: string; ms: number; missed: string[]; falseAlarms: string[] }> = [];
  for (const site of CORPUS) {
    const t = Date.now();
    const report = await scanSite(site);
    const flagged = new Set(report.findings.filter((f) => f.status === "fail" || f.status === "warn").map((f) => f.id));
    const missed: string[] = [];
    const falseAlarms: string[] = [];
    for (const c of SCORED) {
      const want = site.expect.includes(c);
      const got = flagged.has(c);
      const cell = perCheck[c];
      if (want && got) cell.tp++;
      else if (want && !got) (cell.fn++, missed.push(c));
      else if (!want && got) (cell.fp++, falseAlarms.push(c));
      else cell.tn++;
    }
    sites.push({ name: site.name, ms: Date.now() - t, missed, falseAlarms });
  }
  const tot = Object.values(perCheck).reduce((a, c) => ({ tp: a.tp + c.tp, fp: a.fp + c.fp, fn: a.fn + c.fn, tn: a.tn + c.tn }), { tp: 0, fp: 0, fn: 0, tn: 0 });
  const recall = tot.tp / Math.max(1, tot.tp + tot.fn);
  const precision = tot.tp / Math.max(1, tot.tp + tot.fp);
  const times = sites.map((s) => s.ms).sort((a, b) => a - b);
  const summary = {
    ranAt: new Date().toISOString(),
    sites: CORPUS.length,
    plantedProblems: tot.tp + tot.fn,
    detected: tot.tp,
    missed: tot.fn,
    falseAlarms: tot.fp,
    recall: Number(recall.toFixed(4)),
    precision: Number(precision.toFixed(4)),
    medianScanMs: times[Math.floor(times.length / 2)],
    perCheck,
    sitesDetail: sites,
  };
  mkdirSync(path.join(process.cwd(), "bench", "out"), { recursive: true });
  writeFileSync(path.join(process.cwd(), "bench", "out", "scan-benchmark.json"), JSON.stringify(summary, null, 2));
  for (const s of sites) console.log(`${s.missed.length || s.falseAlarms.length ? "MISS" : "ok  "} ${s.name.padEnd(34)} ${String(s.ms).padStart(5)} ms${s.missed.length ? ` missed ${s.missed.join(",")}` : ""}${s.falseAlarms.length ? ` false alarm ${s.falseAlarms.join(",")}` : ""}`);
  console.log(`\n${CORPUS.length} sites, ${summary.plantedProblems} planted problems: detected ${tot.tp}, missed ${tot.fn}, false alarms ${tot.fp}. Recall ${(recall * 100).toFixed(1)}%, precision ${(precision * 100).toFixed(1)}%, median scan ${summary.medianScanMs} ms.`);
  process.exit(tot.fn || tot.fp ? 1 : 0);
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("bench/bench-scan.ts")) main().catch((e) => {
  console.error(e);
  process.exit(1);
});
