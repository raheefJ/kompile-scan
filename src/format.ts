// SPDX-License-Identifier: AGPL-3.0-or-later
/** Report formats: plain text for terminals, Markdown for pull-request comments, SARIF for GitHub code scanning. */
import type { Finding, ScanReport } from "./checks";

const problemsOf = (r: ScanReport) => r.findings.filter((f) => f.status === "fail" || f.status === "warn");

export function toText(r: ScanReport): string {
  const line = (f: Finding) => `  ${f.status === "fail" ? "FIX    " : "IMPROVE"} ${f.id} [${f.severity}] ${f.title}\n      ${f.evidence}\n      Fix: ${f.fix}\n`;
  const problems = problemsOf(r);
  return [
    `\nKompile Scan ${r.scannerVersion}: ${r.hostname}\nGrade ${r.grade} (${r.score}/100) in ${r.durationMs} ms\n\n`,
    problems.length ? problems.map(line).join("\n") : "  No problems found in these checks.\n",
    "\nA good grade is not a guarantee that a site cannot be attacked; this is not a full penetration test.\n",
  ].join("");
}

export function toMarkdown(r: ScanReport): string {
  const problems = problemsOf(r);
  const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
  const rows = problems.map((f) => `| ${f.status === "fail" ? "Fix" : "Improve"} | \`${f.id}\` | ${f.severity} | ${esc(f.title)} | ${esc(f.evidence)} |`);
  const fixes = problems.map((f) => `- **${f.id} ${esc(f.title)}**: ${esc(f.fix)}`);
  return [
    `### Kompile Scan: ${r.hostname} graded **${r.grade}** (${r.score}/100)`,
    "",
    problems.length ? ["| | Check | Risk | Title | Evidence |", "| --- | --- | --- | --- | --- |", ...rows, "", "<details><summary>How to fix</summary>", "", ...fixes, "", "</details>"].join("\n") : "No problems found in these checks.",
    "",
    `<sub>Kompile Scan ${r.scannerVersion} · read-only checks · not a full penetration test</sub>`,
    "",
  ].join("\n");
}

/** A prompt to paste into an AI coding tool (Cursor, Claude, Lovable, Bolt) so it fixes what the scan found. */
export function toFixPrompt(r: ScanReport): string {
  const problems = problemsOf(r);
  if (!problems.length) return `Kompile Scan found no problems on ${r.hostname}. Nothing to fix.\n`;
  const leaked = problems.some((f) => f.id === "KS-17" || f.id === "KS-12");
  return [
    `A security scan of my live site ${r.hostname} (grade ${r.grade}) found the problems below. Fix them in this codebase.`,
    "",
    "Rules:",
    "- Make the smallest change that fixes each problem, and explain each change in one line.",
    "- Never put secret keys in front-end code or in files served to the public. Read them from server-side environment variables.",
    leaked ? "- A secret may already be exposed: list every key that must be rotated (replaced) in the provider's dashboard. Do not print key values." : "",
    "- If a fix is a hosting setting (headers, DNS, a dashboard toggle) rather than code, tell me exactly where to change it.",
    "",
    ...problems.map((f, i) => `${i + 1}. [${f.id}] ${f.title}\n   Found: ${f.evidence}\n   Why it matters: ${f.why}\n   Fix: ${f.fix}`),
    "",
    "When you are done, list what you changed, then I will re-run the scan to confirm.",
    "",
  ]
    .filter((l) => l !== "")
    .join("\n")
    .concat("\n");
}

const SARIF_LEVEL ={ high: "error", medium: "warning", low: "note", info: "note" } as const;

/** SARIF 2.1.0, so findings show up in GitHub's Security tab via github/codeql-action/upload-sarif. */
export function toSarif(r: ScanReport): object {
  const problems = problemsOf(r);
  const rules = [...new Map(problems.map((f) => [f.id, f])).values()].map((f) => ({
    id: f.id,
    name: f.id.replace("-", ""),
    shortDescription: { text: f.title },
    fullDescription: { text: f.why },
    help: { text: f.fix },
    properties: { tags: ["security", "kompile-scan"], "security-severity": { high: "8.0", medium: "5.0", low: "2.0", info: "0.0" }[f.severity] },
  }));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Kompile Scan", version: r.scannerVersion, informationUri: "https://github.com/kompile/kompile-scan", rules } },
        results: problems.map((f) => ({
          ruleId: f.id,
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.title}: ${f.evidence}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: r.finalUrl } } }],
        })),
      },
    ],
  };
}
