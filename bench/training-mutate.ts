/**
 * Mutation lab: generates hundreds of benchmark sites by mixing known planted problems, traps, and harmless "look"
 * (hosting headers, framework markers, backend references), scans each with the real checks, and labels every check
 * from what was planted. All sites are local and ours; no user data and no outside requests are involved.
 *
 *   npx tsx bench/training-mutate.ts [count] [seed]      (default 400 sites, seed 20261013)
 *   Writes labelled examples and site features as JSONL to bench/out/.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { SCANNER_VERSION } from "../src/checks";
import { SCORED, scanSite, type Site } from "./bench-scan";

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const HOSTING: Array<Record<string, string>> = [
  {},
  { "x-vercel-id": "iad1::abc123" },
  { "x-nf-request-id": "01HXYZ" },
  { "cf-ray": "8a1b2c3d4e5f-IAD", server: "cloudflare" },
  { server: "railway-edge" },
  { "fly-request-id": "01HXYZ-iad" },
  { "rndr-id": "abc-123" },
];
const FRAMEWORK_MARKERS = [
  "",
  `<link rel="preload" as="style" href="/_next/static/css/app.css">`,
  `<link rel="modulepreload" href="/_nuxt/entry.js">`,
  `<link rel="modulepreload" href="/_app/immutable/entry/start.js">`,
  `<link rel="stylesheet" href="/_astro/index.css">`,
  `<app-root ng-version="17.3.0"></app-root>`,
  `<link rel="stylesheet" href="/wp-content/themes/site/style.css">`,
  `<script type="module" crossorigin src="/assets/index-a1b2c3d4.js"></script>`,
];
const BACKEND_JS = ["", `const sb="https://abcdefghijklmnopqrst.supabase.co";`, `const fb="demo-app.firebaseapp.com";`, `const ck="clerk.accounts.dev";`, `const cv="https://happy-cat-123.convex.cloud";`];

type Problem = { p: number; apply: (s: Site, r: () => number) => string[] };
const pick = <T,>(r: () => number, xs: T[]) => xs[Math.floor(r() * xs.length)];
const addRoute = (s: Site, path: string, route: { status?: number; type?: string; body: string }) => (s.routes = { ...(s.routes ?? {}), [path]: route });

const PROBLEMS: Problem[] = [
  { p: 0.12, apply: (s) => ((s.env = true), ["KS-12"]) },
  { p: 0.08, apply: (s) => ((s.git = true), ["KS-12"]) },
  { p: 0.05, apply: (s) => ((s.sqlDump = true), ["KS-12"]) },
  { p: 0.05, apply: (s) => ((s.zipBackup = true), ["KS-12"]) },
  { p: 0.05, apply: (s) => ((s.dsStore = true), ["KS-12"]) },
  { p: 0.05, apply: (s) => ((s.metrics = "prometheus"), ["KS-12"]) },
  { p: 0.04, apply: (s) => ((s.actuator = true), ["KS-12"]) },
  { p: 0.05, apply: (s) => ((s.dockerfile = "public"), ["KS-12"]) },
  { p: 0.04, apply: (s) => (addRoute(s, "/vercel.json", { type: "application/json", body: '{"rewrites":[{"source":"/(.*)","destination":"/"}]}' }), ["KS-12"]) },
  { p: 0.2, apply: (s, r) => ((s.secret = pick(r, ["stripe", "openai", "aws", "supabaseService", "groq"] as const)), ["KS-17"]) },
  { p: 0.1, apply: (s) => ((s.sourceMap = "public"), ["KS-18"]) },
  { p: 0.06, apply: (s) => ((s.mixed = true), ["KS-19", "KS-20"]) },
  { p: 0.1, apply: (s) => ((s.thirdPartyNoSri = true), ["KS-20"]) },
  { p: 0.1, apply: (s, r) => ((s.debug = pick(r, ["python", "node", "django", "laravel"] as const)), ["KS-21"]) },
  { p: 0.05, apply: (s) => ((s.apiDocs = true), ["KS-22"]) },
  { p: 0.04, apply: (s) => ((s.swaggerUi = true), ["KS-22"]) },
  { p: 0.06, apply: (s) => ((s.corsCreds = true), ["KS-13"]) },
  { p: 0.1, apply: (s) => ((s.versions = true), ["KS-11"]) },
  { p: 0.1, apply: (s) => ((s.weakCookie = true), ["KS-10"]) },
  { p: 0.25, apply: (s) => ((s.caa = false), ["KS-23"]) },
  { p: 0.15, apply: (s) => ((s.mail = "unprotected"), ["KS-15"]) },
  { p: 0.15, apply: (s) => ((s.headers = false), ["KS-05", "KS-06", "KS-07", "KS-08", "KS-09"]) },
  { p: 0.03, apply: (s) => ((s.homeExtra = `${s.homeExtra ?? ""}<script src="https://polyfill.io/v3/polyfill.min.js" integrity="sha384-x" crossorigin="anonymous"></script>`), ["KS-24"]) },
  { p: 0.07, apply: (s) => ((s.homeExtra = `${s.homeExtra ?? ""}<script src="https://code.jquery.com/jquery-3.4.1.min.js" integrity="sha384-x" crossorigin="anonymous"></script>`), ["KS-25"]) },
  { p: 0.06, apply: (s) => ((s.jsExtra = `${s.jsExtra ?? ""}window.next={version:"15.2.2",appDir:true};`), ["KS-26"]) },
  { p: 0.04, apply: (s) => (addRoute(s, "/api/tags", { type: "application/json", body: '{"models":[{"name":"llama3:8b"}]}' }), ["KS-27"]) },
  { p: 0.03, apply: (s) => (addRoute(s, "/phpmyadmin/", { body: "<!doctype html><title>localhost / phpMyAdmin</title>" }), ["KS-27"]) },
  { p: 0.04, apply: (s) => (addRoute(s, "/graphql", { type: "application/json", body: '{"data":{"__schema":{"queryType":{"name":"Query"}}}}' }), ["KS-28"]) },
  { p: 0.05, apply: (s, r) => ((s.listing = pick(r, ["robots", "common"] as const)), ["KS-16"]) },
  { p: 0.04, apply: (s) => ((s.subs = { ...(s.subs ?? {}), old: { cname: "kompile-old-demo.azurewebsites.net", targetLive: false } }), ["KS-29"]) },
];

/** Traps: things that look risky but are fine, so the labels teach what must NOT be flagged. */
const TRAPS: Array<{ p: number; apply: (s: Site, r: () => number) => void }> = [
  { p: 0.15, apply: (s, r) => s.secret === undefined && (s.secret = pick(r, ["publishable", "supabaseAnon", "clerkPublishable"] as const)) },
  { p: 0.08, apply: (s) => s.sourceMap === undefined && (s.sourceMap = "missing") },
  { p: 0.08, apply: (s) => (s.homeExtra = `${s.homeExtra ?? ""}<script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha384-x" crossorigin="anonymous"></script>`) },
  { p: 0.06, apply: (s) => !s.jsExtra?.includes("window.next") && (s.jsExtra = `${s.jsExtra ?? ""}window.next={version:"15.5.9",appDir:true};`) },
  { p: 0.05, apply: (s) => !s.metrics && (s.metrics = "marketing-page") },
  { p: 0.05, apply: (s) => !s.routes?.["/graphql"] && addRoute(s, "/graphql", { status: 400, type: "application/json", body: '{"errors":[{"message":"GET query missing."}]}' }) },
  { p: 0.05, apply: (s) => !s.listing && (s.robotsAdmin = true) },
  { p: 0.05, apply: (s) => !s.dockerfile && (s.dockerfile = "blog-mentions") },
  { p: 0.15, apply: (s) => s.mail === "none" && (s.mail = "protected") },
  { p: 0.08, apply: (s) => (s.subs = { ...(s.subs ?? {}), api: { cname: "kompile-api-demo.azurewebsites.net", targetLive: true } }) },
];

export function generate(count: number, seed: number): Site[] {
  const r = rng(seed);
  const sites: Site[] = [];
  for (let i = 0; i < count; i++) {
    const s: Site = { name: `mut-${seed}-${String(i).padStart(4, "0")}`, headers: true, caa: true, mail: "none", expect: [] };
    const expect = new Set<string>();
    for (const prob of PROBLEMS) if (r() < prob.p) for (const c of prob.apply(s, r)) expect.add(c);
    for (const trap of TRAPS) if (r() < trap.p) trap.apply(s, r);
    s.extraHeaders = pick(r, HOSTING);
    s.homeExtra = `${s.homeExtra ?? ""}${pick(r, FRAMEWORK_MARKERS)}${r() < 0.2 ? `<script src="https://js.stripe.com/v3/" integrity="sha384-x" crossorigin="anonymous"></script>` : ""}`;
    s.jsExtra = `${s.jsExtra ?? ""}${pick(r, BACKEND_JS)}`;
    s.expect = [...expect];
    sites.push(s);
  }
  return sites;
}

async function main() {
  const count = Number(process.argv[2] ?? 400);
  const seed = Number(process.argv[3] ?? 20261013);
  const sites = generate(count, seed);
  const examples: unknown[][] = [];
  const features: unknown[][] = [];
  let tp = 0, fp = 0, fn = 0;
  const misses: string[] = [];
  for (const site of sites) {
    const report = await scanSite(site);
    const flagged = new Set(report.findings.filter((f) => f.status === "fail" || f.status === "warn").map((f) => f.id));
    const seen = new Set<string>();
    for (const f of report.findings) {
      if (seen.has(f.id)) continue;
      seen.add(f.id);
      const scored = SCORED.includes(f.id);
      const want = site.expect.includes(f.id);
      const got = flagged.has(f.id);
      const label = !scored ? null : want && got ? "true_positive" : want ? "false_negative" : got ? "false_positive" : "true_negative";
      if (label === "true_positive") tp++;
      if (label === "false_positive") (fp++, misses.push(`${site.name} false alarm ${f.id}`));
      if (label === "false_negative") (fn++, misses.push(`${site.name} missed ${f.id}`));
      examples.push(["corpus", "kompile", SCANNER_VERSION, site.name, f.id, f.status, f.severity, label, scored ? "planted" : null]);
    }
    for (const c of site.expect) if (!seen.has(c)) (fn++, misses.push(`${site.name} missed ${c} (no finding)`), examples.push(["corpus", "kompile", SCANNER_VERSION, site.name, c, "pass", null, "false_negative", "planted"]));
    if (report.signals) features.push(["corpus", SCANNER_VERSION, site.name, report.grade, JSON.stringify(report.signals)]);
  }
  const summary = { sites: sites.length, seed, planted: tp + fn, caught: tp, missed: fn, falseAlarms: fp, examples: examples.length, featureRows: features.length, problems: misses.slice(0, 50) };
  const out = path.join(process.cwd(), "bench", "out");
  mkdirSync(out, { recursive: true });
  writeFileSync(path.join(out, `mutation-lab-${seed}.json`), JSON.stringify(summary, null, 2));
  console.log(JSON.stringify({ ...summary, problems: misses.length }, null, 0));
  for (const m of misses.slice(0, 20)) console.log("  ", m);

  const cols = ["source", "tool", "scanner_version", "subject", "check_id", "status", "severity", "label", "label_source"];
  const jsonl = (rows: unknown[]) => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
  writeFileSync(path.join(out, `examples-${seed}.jsonl`), jsonl(examples.map((e) => Object.fromEntries(cols.map((c, i) => [c, e[i]])))));
  writeFileSync(path.join(out, `features-${seed}.jsonl`), jsonl(features.map((f) => ({ source: f[0], scanner_version: f[1], subject: f[2], grade: f[3], features: JSON.parse(String(f[4])) }))));
  console.log(`wrote bench/out/examples-${seed}.jsonl and features-${seed}.jsonl`);
  // Any miss or false alarm fails CI.
  if (fn || fp) process.exit(1);
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("bench/training-mutate.ts")) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
