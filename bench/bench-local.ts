/**
 * Runs the real Kompile Scan checks against a local app (for example OWASP Juice Shop on :3300).
 * TLS is simulated as valid and DNS checks are stubbed, exactly as in bench-scan.ts.
 *
 *   npx tsx bench/bench-local.ts http://127.0.0.1:3300 [out.json]
 */
import { writeFileSync } from "node:fs";
import { runScanWith, type Requester } from "../src/checks";
import { safeRequest } from "../src/net";

async function main() {
  const base = new URL(process.argv[2] ?? "http://127.0.0.1:3300");
  const shim: Requester = async (u, o) => {
    const x = new URL(u);
    const r = await safeRequest(`http://bench.local.test:${base.port}${x.pathname}${x.search}`, { ...o, unsafeAllowAddress: (a) => a === "127.0.0.1" });
    return x.protocol === "https:"
      ? { ...r, url: u, tls: { authorized: true, authorizationError: null, protocol: "TLSv1.3", validTo: new Date(Date.now() + 80 * 864e5).toUTCString(), issuer: "(bench)" } }
      : { ...r, status: 301, headers: { ...r.headers, location: u.replace("http://", "https://") } };
  };
  const t = Date.now();
  const report = await runScanWith(shim, "local-app.bench.test", {
    dns: { mx: async () => [], txt: async () => [], caa: async () => [{ critical: 0, issue: "letsencrypt.org" }] } as never,
    budgetMs: 30_000,
    basePath: base.pathname !== "/" ? base.pathname : undefined,
  });
  const ms = Date.now() - t;
  for (const f of report.findings) if (f.status === "fail" || f.status === "warn") console.log(`${f.status.toUpperCase().padEnd(4)} ${f.id} ${f.title} | ${f.evidence}`);
  console.log(`grade ${report.grade}, ${ms} ms`);
  if (process.argv[3]) writeFileSync(process.argv[3], JSON.stringify({ ms, report }, null, 2));
}

main();
