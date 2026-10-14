#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * kompile-scan: read-only, outside-in security checks for a website you own.
 *
 *   kompile-scan example.com --i-own-this
 *   kompile-scan example.com --i-own-this --json > report.json
 *   kompile-scan example.com --i-own-this --path /app --fail-on high
 */
import { appendFileSync, writeFileSync } from "node:fs";
import { normalizeHostname } from "./hostname";
import { runScan, type Severity } from "./checks";
import { toFixPrompt, toMarkdown, toSarif, toText } from "./format";

const HELP = `kompile-scan <hostname> --i-own-this [options]

Read-only security checks for a site you own: ordinary page requests, no logins, no attack payloads.

Options
  --i-own-this        Required. Confirms you own the site or have the owner's permission to check it.
  --path <path>       Where the app starts if it is not at the root, for example /app.
  --format <f>        text (default), json, markdown (PR comments), sarif (GitHub code scanning) or prompt (paste into your AI tool).
  --json              Same as --format json.
  --fail-on <level>   Exit with code 1 when a problem at this level or worse is found: high, medium, low (default: medium).
  --no-subdomains     Skip the certificate-log subdomain takeover check.
  --sarif-file <p>    Also write a SARIF report to this file.
  --markdown-file <p> Also append a Markdown summary to this file (for example $GITHUB_STEP_SUMMARY).
  --json-file <p>     Also write the full JSON report to this file.
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

  // Extra report files from the same scan (used by the GitHub Action).
  const sarifFile = arg("--sarif-file");
  const markdownFile = arg("--markdown-file");
  const jsonFile = arg("--json-file");
  if (sarifFile) writeFileSync(sarifFile, `${JSON.stringify(toSarif(report), null, 2)}\n`);
  if (markdownFile) appendFileSync(markdownFile, toMarkdown(report));
  if (jsonFile) writeFileSync(jsonFile, `${JSON.stringify(report, null, 2)}\n`);

  const format = args.includes("--json") ? "json" : (arg("--format") ?? "text");
  if (format === "json") process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else if (format === "markdown") process.stdout.write(toMarkdown(report));
  else if (format === "sarif") process.stdout.write(`${JSON.stringify(toSarif(report), null, 2)}\n`);
  else if (format === "prompt") process.stdout.write(toFixPrompt(report));
  else process.stdout.write(toText(report));
  process.exit(blocking.length ? 1 : 0);
}

main().catch((e) => {
  process.stderr.write(`kompile-scan failed: ${(e as Error).message}\n`);
  process.exit(2);
});
