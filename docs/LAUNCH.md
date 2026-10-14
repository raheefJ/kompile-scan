# Launch kit

Every number here is reproducible from the repo. Do not round up and do not claim "unbeatable": the blind-test loss is
part of the story and builds trust.

## The one-liner

> Kompile Scan: open-source security checks for apps built with AI. It finds the leaked keys, open `.env` files and
> vulnerable Next.js versions that Lovable, Bolt and Cursor apps ship with, then hands your AI the fix.

## Launch day order

1. Make the repo public, then publish to npm (`kompile-scan`) and list the Action on the GitHub Marketplace.
2. **Show HN** in the morning, US Eastern time. Answer every comment for the first 6 hours.
3. **Reddit**, spaced a few hours apart: r/webdev, r/nextjs, r/SideProject, r/vibecoding. Read each subreddit's self-promotion rules first.
4. **X/Bluesky thread** and **dev.to article** the same day.
5. **MCP directories**: the modelcontextprotocol/servers community list (PR), mcp.so, Glama, Smithery.
6. **Awesome lists**, through pull requests that follow each list's rules: awesome-security, awesome-static-analysis (DAST section), awesome-nextjs (security), awesome-mcp-servers.
7. **Kompile YouTube channel**: "I built 5 apps the way AI builders do, then scanned them" (the AI-app lab results).

## Show HN

**Title:** Show HN: Kompile Scan – open-source security checks for apps built with AI

**Text:**

I kept seeing apps built with Lovable, Bolt and Cursor go live with an OpenAI key in the JavaScript bundle, a public `.env`, or a Next.js version that npm marks as vulnerable. Existing scanners are either header graders or huge template engines that are noisy for small apps. So I built a focused one.

- **Read-only:** GET and HEAD requests only. No logins, no payloads, and private IPs are refused.
- **About 30 checks** aimed at AI-built apps: about 25 secret key formats in the bundle, exposed build configs, source maps, open admin and AI panels (Ollama, Jupyter, Supabase Studio), polyfill.io, vulnerable Next.js versions, and subdomain takeover from certificate logs.
- **Every finding comes with a plain-English fix**, plus `--format prompt` to paste into your AI tool, SARIF for GitHub code scanning, a GitHub Action, and an MCP server so your agent can scan, fix and re-scan.

**Benchmark (reproducible with `npm run bench` and `npm run bench:mutate`):**

- **Our corpus:** 64 of 64 planted problems on 63 test sites and 1,170 of 1,170 on 400 generated sites, with 0 false alarms on both.
- **Against Nuclei's defaults on the same sites:** 29 of 45 with 73 false alarms.
- **Blind tests on apps we hadn't seen,** with rules frozen first: we lost WebGoat (5 vs 7) and tied DVWA (7 vs 7). Both results are published, and the misses became new rules.

AGPL-3.0. I'd love new checks. Every check needs a test site it must catch and a trap it must ignore.

## X/Bluesky thread

1. AI app builders make the same security mistakes over and over. I built an open-source scanner for exactly those. 🧵
2. The top 3 we see: an OpenAI or Stripe secret key inside the JS bundle, a public `.env`, and Next.js versions npm flags as vulnerable.
3. Kompile Scan checks your live site read-only (no attacks, no logins) and gives you a fix prompt to paste into Cursor or Lovable.
4. We built 5 apps the way AI builders do and scanned them. Kompile caught 33 of 33 problems; Nuclei's defaults caught 25.
5. We also publish our losses. A blind test on WebGoat: Nuclei 7, Kompile 5. Those misses are now rules.
6. It comes as a CLI, a GitHub Action and an MCP server. AGPL. `npx kompile-scan yourapp.com --i-own-this`. Link.

## dev.to article

**Title:** I built 5 apps the way AI builders do. Here is what a security scan found.

Sections:

1. **The five apps** and the exact mistakes in each, with the code.
2. **What an attacker sees from outside,** with screenshots of the reports.
3. **Kompile Scan versus Nuclei:** a table of what each tool caught.
4. **The fix prompt,** and the AI-applied fixes taking the app from grade F to A.
5. **How to add it to your CI** in 10 lines.

## What success looks like (track weekly)

- GitHub stars, forks and unique contributors
- npm weekly downloads of `kompile-scan`
- Action uses (GitHub dependency graph) and MCP directory installs
- Outside pull requests that add checks, and the time to the first review
- Benchmark size (sites and planted problems) and the false-alarm count, which must stay 0
