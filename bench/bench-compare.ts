/**
 * Head-to-head: Kompile Scan vs Nuclei (ProjectDiscovery, default community templates) on the same benchmark corpus.
 *
 *   1. npx tsx bench/bench-serve.ts                         (serves the corpus, writes bench/out/bench-targets.*)
 *   2. nuclei -l bench/out/bench-targets.txt -jsonl -o bench/out/nuclei-corpus.jsonl -duc -ni
 *   3. npx tsx bench/bench-compare.ts                       (writes bench/out/scan-vs-nuclei.json)
 *
 * Nuclei findings are mapped to Kompile check categories by template id, matcher name and tags (rules below, fixed
 * before results were read). Findings that fit no category (technology detection, informational banners) are listed
 * but never counted as false alarms, which favours Nuclei. DNS checks (KS-15, KS-23) are left out because Nuclei is
 * pointed at an IP address with no domain.
 */
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { CORPUS, SCORED, scanSite } from "./bench-scan";

// KS-19 (mixed content) is also left out: Nuclei only checks it on https:// targets and the corpus is served over plain HTTP.
const HEAD2HEAD = SCORED.filter((c) => c !== "KS-15" && c !== "KS-23" && c !== "KS-19");

interface NucleiFinding {
  "template-id": string;
  "matcher-name"?: string;
  host?: string;
  url?: string;
  "matched-at"?: string;
  "extracted-results"?: string[];
  port?: string;
  info?: { name?: string; tags?: string[] | string; severity?: string };
}

const HEADER_MAP: Record<string, string> = {
  "strict-transport-security": "KS-05",
  "content-security-policy": "KS-06",
  "x-frame-options": "KS-07",
  "x-content-type-options": "KS-08",
  "referrer-policy": "KS-09",
};

export function mapNuclei(f: NucleiFinding): string | null {
  const id = f["template-id"].toLowerCase();
  const m = (f["matcher-name"] ?? "").toLowerCase();
  const rawTags = f.info?.tags ?? [];
  const tags = (Array.isArray(rawTags) ? rawTags : rawTags.split(",")).map((t) => t.trim().toLowerCase());
  const has = (...t: string[]) => t.some((x) => tags.includes(x));
  if (id === "http-missing-security-headers") return HEADER_MAP[m] ?? null;
  if (/cookie/.test(id)) return "KS-10";
  if (/cors/.test(id) || has("cors")) return "KS-13";
  if (/source-?map|js-?map/.test(id)) return "KS-18";
  if (/mixed-(active|passive)?-?content|mixed-content/.test(id)) return "KS-19";
  if (/subresource|(^|-)sri(-|$)/.test(id)) return "KS-20";
  if (/swagger|openapi|api-docs|redoc/.test(id) || has("swagger", "openapi")) return "KS-22";
  if (/directory-listing|dir-listing|index-of|open-directory|dir-list/.test(id) || has("listing")) return "KS-16";
  if (/stack-?trace|traceback|debug-(mode|page)|whoops|error-page|django-debug|laravel-debug|werkzeug-debug|express-debug|verbose-error/.test(id)) return "KS-21";
  if (has("token", "keys", "secret") || /stripe|aws-access|openai|secret-key|private-key|supabase|service-role|api-key/.test(id)) return "KS-17";
  if (/version|banner|x-powered-by|server-header/.test(id) && (f["extracted-results"] ?? []).some((v) => /\d+\.\d+/.test(v))) return "KS-11";
  if (has("exposure", "config", "backup", "logs", "files", "git", "env", "dump", "metrics", "actuator", "pprof", "disclosure") || /\.env|git-|backup|sql|ds-store|metrics|actuator|pprof|elmah|phpinfo|server-status/.test(id)) return "KS-12";
  return null;
}

function hostKey(f: NucleiFinding): string {
  if (f.port) return String(f.port);
  const u = f.url ?? f["matched-at"] ?? f.host ?? "";
  try {
    return new URL(u.includes("://") ? u : `http://${u}`).port;
  } catch {
    return "";
  }
}

type Cell = { tp: number; fp: number; fn: number };

function score(flaggedBySite: Map<string, Set<string>>) {
  const perCheck: Record<string, Cell> = Object.fromEntries(HEAD2HEAD.map((c) => [c, { tp: 0, fp: 0, fn: 0 }]));
  const sites: Array<{ name: string; missed: string[]; falseAlarms: string[] }> = [];
  for (const site of CORPUS) {
    const flagged = flaggedBySite.get(site.name) ?? new Set();
    const missed: string[] = [];
    const falseAlarms: string[] = [];
    for (const c of HEAD2HEAD) {
      const want = site.expect.includes(c);
      const got = flagged.has(c);
      if (want && got) perCheck[c].tp++;
      else if (want) (perCheck[c].fn++, missed.push(c));
      else if (got) (perCheck[c].fp++, falseAlarms.push(c));
    }
    sites.push({ name: site.name, missed, falseAlarms });
  }
  const t = Object.values(perCheck).reduce((a, c) => ({ tp: a.tp + c.tp, fp: a.fp + c.fp, fn: a.fn + c.fn }), { tp: 0, fp: 0, fn: 0 });
  return {
    planted: t.tp + t.fn,
    detected: t.tp,
    missed: t.fn,
    falseAlarms: t.fp,
    recall: Number((t.tp / Math.max(1, t.tp + t.fn)).toFixed(4)),
    precision: Number((t.tp / Math.max(1, t.tp + t.fp)).toFixed(4)),
    perCheck,
    sites,
  };
}

async function main() {
  const ev = path.join(process.cwd(), "bench", "out");
  const targets: Array<{ name: string; url: string }> = JSON.parse(readFileSync(path.join(ev, "bench-targets.json"), "utf8"));
  const nameByPort = new Map(targets.map((t) => [new URL(t.url).port, t.name]));
  const raw = readFileSync(path.join(ev, "nuclei-corpus.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as NucleiFinding);

  // "Lenient" drops two Nuclei rules that are opinions rather than defects: demanding SameSite=Strict (Lax is the
  // browser default and OWASP-accepted) and demanding X-Frame-Options when CSP frame-ancestors already blocks framing.
  const lenientSkip = (f: NucleiFinding) =>
    f["template-id"] === "missing-cookie-samesite-strict" || (f["template-id"] === "http-missing-security-headers" && f["matcher-name"] === "x-frame-options");
  const lenientFlags = new Map<string, Set<string>>();
  for (const f of raw) {
    const site = nameByPort.get(hostKey(f));
    const c = mapNuclei(f);
    if (!site || !c || !HEAD2HEAD.includes(c) || lenientSkip(f)) continue;
    if (!lenientFlags.has(site)) lenientFlags.set(site, new Set());
    lenientFlags.get(site)!.add(c);
  }

  const nucleiFlags = new Map<string, Set<string>>();
  const unmapped = new Map<string, number>();
  for (const f of raw) {
    const site = nameByPort.get(hostKey(f));
    if (!site) continue;
    const c = mapNuclei(f);
    if (c && HEAD2HEAD.includes(c)) {
      if (!nucleiFlags.has(site)) nucleiFlags.set(site, new Set());
      nucleiFlags.get(site)!.add(c);
    } else {
      const k = `${f["template-id"]}${f["matcher-name"] ? `:${f["matcher-name"]}` : ""}`;
      unmapped.set(k, (unmapped.get(k) ?? 0) + 1);
    }
  }

  const kompileFlags = new Map<string, Set<string>>();
  const t0 = Date.now();
  for (const site of CORPUS) {
    const r = await scanSite(site);
    kompileFlags.set(site.name, new Set(r.findings.filter((f) => f.status === "fail" || f.status === "warn").map((f) => f.id)));
  }
  const kompileMs = Date.now() - t0;

  const timing = (() => {
    try {
      return readFileSync(path.join(ev, "nuclei-timing.txt"), "utf8").trim();
    } catch {
      return "";
    }
  })();
  const out = {
    ranAt: new Date().toISOString(),
    corpusSites: CORPUS.length,
    checksCompared: HEAD2HEAD,
    nuclei: { version: "3.11.1, default community templates", findingsRaw: raw.length, timing, ...score(nucleiFlags), unmappedFindings: Object.fromEntries([...unmapped].sort((a, b) => b[1] - a[1])) },
    nucleiLenient: score(lenientFlags),
    kompile: { totalMs: kompileMs, ...score(kompileFlags) },
  };
  writeFileSync(path.join(ev, "scan-vs-nuclei.json"), JSON.stringify(out, null, 2));

  const line = (n: string, s: ReturnType<typeof score>) =>
    `${n.padEnd(8)} caught ${s.detected}/${s.planted}  missed ${s.missed}  false alarms ${s.falseAlarms}  recall ${(s.recall * 100).toFixed(1)}%  precision ${(s.precision * 100).toFixed(1)}%`;
  console.log(line("Kompile", out.kompile));
  console.log(line("Nuclei", out.nuclei));
  console.log(`${line("Nuclei~", out.nucleiLenient)}   (lenient: SameSite=Strict and X-Frame-Options rules ignored)`);
  console.log(`\nPer check (Kompile tp/fp/fn | Nuclei tp/fp/fn | Nuclei lenient):`);
  for (const c of HEAD2HEAD) {
    const k = out.kompile.perCheck[c];
    const n = out.nuclei.perCheck[c];
    const nl = out.nucleiLenient.perCheck[c];
    console.log(`${c}  ${k.tp}/${k.fp}/${k.fn}  |  ${n.tp}/${n.fp}/${n.fn}  |  ${nl.tp}/${nl.fp}/${nl.fn}`);
  }
  for (const s of out.nucleiLenient.sites) if (s.missed.length || s.falseAlarms.length) console.log(`  nuclei~ ${s.name}: missed ${s.missed.join(",") || "-"}; false ${s.falseAlarms.join(",") || "-"}`);
  console.log(`\nNuclei findings outside the compared categories (not counted):`, out.nuclei.unmappedFindings);
  if (timing) console.log(`Nuclei timing: ${timing}; Kompile corpus total ${kompileMs} ms`);
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("bench/bench-compare.ts")) main().catch((e) => {
  console.error(e);
  process.exit(1);
});
