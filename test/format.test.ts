import { describe, expect, it } from "vitest";
import type { ScanReport } from "../src/checks";
import { toFixPrompt, toMarkdown, toSarif } from "../src/format";

const report: ScanReport = {
  hostname: "example.com",
  finalUrl: "https://example.com/",
  score: 62,
  grade: "C",
  durationMs: 1200,
  scannerVersion: "test",
  findings: [
    { id: "KS-17", title: "No secret keys are exposed in your JavaScript", severity: "high", status: "fail", evidence: "a Stripe secret key (sk_live_ab...) in /assets/app.js", why: "w|hy", fix: "Rotate the key." },
    { id: "KS-09", title: "Referrer policy", severity: "low", status: "warn", evidence: "No Referrer-Policy header.", why: "w", fix: "Send Referrer-Policy." },
    { id: "KS-05", title: "HSTS", severity: "medium", status: "pass", evidence: "ok", why: "w", fix: "Nothing to do." },
  ],
};

describe("report formats", () => {
  it("markdown lists only problems and escapes table pipes", () => {
    const md = toMarkdown(report);
    expect(md).toContain("graded **C**");
    expect(md).toContain("`KS-17`");
    expect(md).not.toContain("`KS-05`");
    expect(md).not.toMatch(/w\|hy/);
  });

  it("SARIF has one rule per check and maps severity to levels", () => {
    const s = toSarif(report) as { version: string; runs: Array<{ tool: { driver: { rules: Array<{ id: string }> } }; results: Array<{ ruleId: string; level: string }> }> };
    expect(s.version).toBe("2.1.0");
    expect(s.runs[0].tool.driver.rules.map((r) => r.id)).toEqual(["KS-17", "KS-09"]);
    expect(s.runs[0].results.map((r) => [r.ruleId, r.level])).toEqual([["KS-17", "error"], ["KS-09", "note"]]);
  });

  it("fix prompt asks for key rotation without printing keys, and is empty-safe", () => {
    const p = toFixPrompt(report);
    expect(p).toContain("rotated");
    expect(p).toContain("[KS-17]");
    expect(p).not.toContain("[KS-05]");
    expect(toFixPrompt({ ...report, findings: [] })).toContain("no problems");
  });
});
