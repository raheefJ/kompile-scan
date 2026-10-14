# Changelog

## 0.1.0 (2026-10-13)

First open-source release.

**Checks**
- About 30 read-only checks: TLS, HTTP headers, cookies, secrets in JavaScript (about 25 formats), exposed files and build configs, directory listings, source maps, verbose errors, API docs, GraphQL introspection, admin and AI panels, hijacked CDNs, vulnerable libraries, Next.js advisories (from npm security deprecations), SPF and DMARC, CAA, and subdomain takeover.

**Command line and report formats**
- The `kompile-scan` command line, with text, JSON, Markdown, SARIF and AI-fix-prompt output.
- Exit codes for CI.
- A GitHub Action.

**MCP server**
- `kompile-scan-mcp`, an MCP server for AI agents.

**Benchmark**
- 63 hand-built test sites with planted problems and traps.
- A 400-site mutation lab.
- Head-to-head scripts against Nuclei.
- Published blind tests: WebGoat (a loss) and DVWA (a tie).
