#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * kompile-scan: read-only, outside-in security checks for a website you own.
 *
 *   kompile-scan example.com --i-own-this
 *   kompile-scan example.com --i-own-this --json > report.json
 *   kompile-scan example.com --i-own-this --path /app --fail-on high
 */
import { normalizeHostname } from "./hostname";
import { runScan, type Finding, type Severity } from "./checks";

const HELP = `kompile-scan <hostname> --i-own-this [options]

Read-only security checks for a site you own: ordinary page requests, no logins, no attack payloads.

Options
  --i-own-this        Required. Confirms you own the site or have the owner's permission to check it.
  --path <path>       Where the app starts if it is not at the root, for example /app.
  --json              Print the full report as JSON.
  --fail-on <level>   Exit with code 1 when a problem at this level or worse is found: high, medium, low (default: medium).
  --no-subdomains     Skip the certificate-log subdomain takeover check.
  -h, --help          Show this help.
`;

const RANK: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0 };

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
    process.stdout.write(HELP);
    return;
  }
  const host = normalizeHostname(args[0]);
  if (!host.ok) {
    process.stderr.write(`${host.message}\n`);
    process.exit(2);
  }
  if (!args.includes("--i-own-this")) {
    process.stderr.write("Only check sites you own or have permission to test. Re-run with --i-own-this to confirm.\n");
    process.exit(2);
  }
  const failOn = (arg("--fail-on") ?? "medium") as Severity;
  if (!(failOn in RANK) || failOn === "info") {
    process.stderr.write("--fail-on must be high, medium or low.\n");
    process.exit(2);
  }

  const report = await runScan(host.hostname, { basePath: arg("--path"), subdomains: !args.includes("--no-subdomains") });
  const problems = report.findings.filter((f) => f.status === "fail" || f.status === "warn");
  const blocking = problems.filter((f) => f.status === "fail" && RANK[f.severity] >= RANK[failOn]);

  if (args.includes("--json")) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    const line = (f: Finding) => `  ${f.status === "fail" ? "FIX " : "IMPROVE"} ${f.id} [${f.severity}] ${f.title}\n      ${f.evidence}\n      Fix: ${f.fix}\n`;
    process.stdout.write(`\nKompile Scan ${report.scannerVersion}: ${report.hostname}\nGrade ${report.grade} (${report.score}/100) in ${report.durationMs} ms\n\n`);
    process.stdout.write(problems.length ? problems.map(line).join("\n") : "  No problems found in these checks.\n");
    process.stdout.write("\nA good grade is not a guarantee that a site cannot be attacked; this is not a full penetration test.\n");
  }
  process.exit(blocking.length ? 1 : 0);
}

main().catch((e) => {
  process.stderr.write(`kompile-scan failed: ${(e as Error).message}\n`);
  process.exit(2);
});
