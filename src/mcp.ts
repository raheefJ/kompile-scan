#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Kompile Scan as an MCP server (stdio), so AI agents such as Claude, Cursor or Windsurf can scan a site, apply the
 * fixes, and scan again to confirm. Add to your client as: { "command": "npx", "args": ["-y", "kompile-scan-mcp"] }
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod/v4";
import { runScan, SCANNER_VERSION } from "./checks";
import { toFixPrompt, toMarkdown } from "./format";
import { normalizeHostname } from "./hostname";

const server = new McpServer({ name: "kompile-scan", version: SCANNER_VERSION });

server.registerTool(
  "scan_site",
  {
    title: "Scan a website you own",
    description:
      "Runs Kompile Scan's read-only security checks (ordinary page requests, no logins, no attack payloads) against a live website the user owns. Returns a grade, every problem found with evidence, and a ready-to-use fix prompt. Only call this for sites the user has said they own or have permission to test.",
    inputSchema: {
      hostname: z.string().min(3).max(300).describe("The site to check, for example yourapp.com"),
      path: z.string().max(101).optional().describe("Where the app starts if it is not at the root, for example /app"),
      i_own_this: z.boolean().describe("Must be true: the user confirmed they own this site or have the owner's permission"),
      subdomains: z.boolean().optional().describe("Also check subdomains from certificate logs for takeover (default true)"),
    },
    annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true },
  },
  async ({ hostname, path, i_own_this, subdomains }) => {
    if (!i_own_this) {
      return { isError: true, content: [{ type: "text", text: "Only scan sites the user owns or has permission to test. Ask the user to confirm, then call again with i_own_this: true." }] };
    }
    const host = normalizeHostname(hostname);
    if (!host.ok) return { isError: true, content: [{ type: "text", text: host.message }] };
    const report = await runScan(host.hostname, { basePath: path, subdomains: subdomains !== false });
    const problems = report.findings.filter((f) => f.status === "fail" || f.status === "warn");
    return {
      content: [
        { type: "text", text: toMarkdown(report) },
        { type: "text", text: `Fix prompt (apply these changes, then call scan_site again to confirm):\n\n${toFixPrompt(report)}` },
        {
          type: "text",
          text: JSON.stringify({ grade: report.grade, score: report.score, scannerVersion: report.scannerVersion, problems: problems.map(({ id, severity, status, title, evidence, fix }) => ({ id, severity, status, title, evidence, fix })) }),
        },
      ],
    };
  },
);

server.connect(new StdioServerTransport()).catch((e) => {
  process.stderr.write(`kompile-scan-mcp failed to start: ${(e as Error).message}\n`);
  process.exit(1);
});
