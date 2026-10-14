/**
 * Serves every benchmark site on a real local port so other scanners (Nuclei, ZAP, ...) can be run against the
 * exact same corpus. Writes bench/out/bench-targets.json ({ url, name }) and keeps running until killed.
 *
 *   npx tsx bench/bench-serve.ts
 */
import { mkdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { CORPUS, handler } from "./bench-scan";

async function main() {
  const targets: Array<{ name: string; url: string }> = [];
  for (const site of CORPUS) {
    const server = http.createServer(handler(site));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    targets.push({ name: site.name, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` });
  }
  mkdirSync(path.join(process.cwd(), "bench", "out"), { recursive: true });
  writeFileSync(path.join(process.cwd(), "bench", "out", "bench-targets.json"), JSON.stringify(targets, null, 2));
  writeFileSync(path.join(process.cwd(), "bench", "out", "bench-targets.txt"), targets.map((t) => t.url).join("\n") + "\n");
  console.log(`serving ${targets.length} sites`);
}

main();
