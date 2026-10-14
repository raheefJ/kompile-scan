# Kompile Scan

**Read-only security checks for apps built with AI.** Point it at a site you own. In a few seconds you get a grade, every problem it found, and a plain-English fix for each.

```bash
npx kompile-scan yourapp.com --i-own-this
```

It is built for the mistakes that Lovable, Bolt, v0, Cursor and Replit apps actually ship with:

- secret API keys in the browser bundle
- `.env` files and backups served to anyone
- source maps that publish your source code
- open admin and AI tool panels
- vulnerable Next.js versions
- forgotten subdomains that someone else can take over

## What it checks

| Area | Checks |
| --- | --- |
| HTTPS | Certificate validity and expiry, TLS version, HTTP to HTTPS redirect, HSTS strength, CAA record |
| Headers | Content-Security-Policy quality, clickjacking protection, nosniff, Referrer-Policy, cookie flags, version banners |
| Leaked secrets | About 25 secret key formats in the page and its scripts: Stripe, OpenAI, Anthropic, AWS, Supabase service_role, Groq, OpenRouter, Resend, SendGrid, Slack, GitHub and more. Publishable keys are ignored on purpose. |
| Exposed files | `.env` variants, `.git`, backups and SQL dumps, Dockerfile, build configs (`next.config.js`, `vite.config`, `vercel.json`), Prometheus `/metrics`, Spring actuator, Go pprof, logs |
| Exposure | Directory listings (including folders named in robots.txt), public source maps, verbose error pages (Python, Django, Laravel, Node, Express, Java, ASP.NET, Rails), public OpenAPI and Swagger UI, GraphQL introspection, admin, database and AI panels (phpMyAdmin, Adminer, Supabase Studio, Jupyter, Ollama, n8n and others) |
| Supply chain | Scripts from hijacked CDNs (polyfill.io), front-end libraries with known CVEs, Next.js versions npm marks as vulnerable, missing subresource integrity, mixed content |
| DNS and email | SPF and DMARC, subdomain takeover via certificate-transparency logs and dangling CNAMEs |

## What it never does

- **Never attacks.** It sends ordinary GET and HEAD requests, the same kind a browser sends. It never logs in, never tries passwords and never sends attack payloads.
- **Never echoes secrets.** Reports show a masked prefix of any key and never the contents of an exposed file.
- **Never scans private networks.** Private, loopback and cloud metadata addresses are refused, every connection is pinned to the vetted address, only ports 80 and 443 are allowed, and redirects are never followed blindly.
- **Only scans sites you own.** The CLI requires `--i-own-this`. The hosted version at [kompile.tv](https://kompile.tv) verifies ownership with DNS or a file before every scan.

## Use it in CI

The exit code is `1` when a problem at or above `--fail-on` is found (the default is `medium`), so a deploy that leaks a key can fail the build. The Action also puts the report in the job summary and the findings in your repository's **Security** tab.

```yaml
# .github/workflows/kompile-scan.yml
name: Kompile Scan
on: [deployment_status]
permissions:
  security-events: write
jobs:
  scan:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: OWNER/kompile-scan@v0
        with:
          hostname: ${{ vars.SITE_HOSTNAME }}
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: kompile-scan.sarif
```

## Let your AI agent fix it (MCP)

Kompile Scan ships an MCP server. Your agent (Claude, Cursor, Windsurf and others) can scan your live site, apply the fixes in your code, and scan again until you get an A.

```json
{ "mcpServers": { "kompile-scan": { "command": "npx", "args": ["-y", "-p", "kompile-scan", "kompile-scan-mcp"] } } }
```

The `scan_site` tool needs `i_own_this: true`, so the agent has to confirm ownership with you first. It never logs in or changes anything on the site.

## Report formats

| `--format` | Use it for |
| --- | --- |
| `text` | your terminal (the default) |
| `json` | scripts and dashboards |
| `markdown` | pull-request comments and job summaries |
| `sarif` | GitHub code scanning (the Security tab) |
| `prompt` | pasting into Cursor, Claude, Lovable or Bolt so it fixes everything at once |

## Use it as a library

```ts
import { runScan } from "kompile-scan";

const report = await runScan("yourapp.com", { basePath: "/app" });
console.log(report.grade, report.findings.filter((f) => f.status === "fail"));
```

## Benchmark: every claim is reproducible

```bash
npm run bench          # the corpus of local test sites with planted problems and traps
npm run bench:mutate   # 400 generated sites mixing problems, traps, hosts and frameworks
```

- **Current results:** the corpus finds 64 of 64 planted problems with 0 false alarms, and the mutation lab finds 1,170 of 1,170 with 0 false alarms.
- **Head-to-head and blind tests:** comparisons with Nuclei and the blind tests on OWASP WebGoat and DVWA are in [docs/BENCHMARK.md](docs/BENCHMARK.md). Kompile lost the first blind test, and that result is published as it happened.
- **The rule for changes:** a new check only lands with a test site that it must catch and a trap that it must ignore.

## Contributing

New checks, fingerprints and test sites are very welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (C) 2026 Kompile contributors.

Licensed under the GNU Affero General Public License v3.0 or later. You may use, change and share it. If you run a modified version as a network service, you must share your changes under the same license. See [LICENSE](LICENSE).
