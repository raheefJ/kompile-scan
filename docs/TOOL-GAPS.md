# What other scanners have that Kompile did not (research 10/12/2026)

## Sources

Three research passes, using public docs and template repositories only:

- **Free and open-source tools:** MDN HTTP Observatory, securityheaders.com, Nuclei templates (14,056), OWASP ZAP passive rules, Nikto, Wapiti, testssl.sh / SSL Labs, internet.nl, Hardenize, Sucuri SiteCheck, Lighthouse, retire.js.
- **Commercial tools:** Detectify, Intruder, HostedScan, Snyk API & Web (Probely), Aikido, UpGuard, SecurityScorecard, Pentest-Tools, Astra, Sucuri, Oh Dear, Red Sift, Attaxion, Escape.
- **Scanners and studies on AI-built apps:** CVE-2025-48757 (Lovable / Supabase), Symbiotic's scan of 1,072 apps, Escape.tech's study of 5,600 apps, FireWreck, the Tea breach, and the Next.js and React advisories.

The full AI-app findings, with source links, are in `ai-app-checks.md`.

## Built now

| Gap | Kompile check | Who had it before |
| --- | --- | --- |
| About 20 more secret key formats (Groq, OpenRouter, Resend, Replicate, SendGrid, Hugging Face, Perplexity, Slack, Discord, Telegram, Shopify, npm, DigitalOcean, Linear, Notion, Mapbox secret, Clerk secret). Publishable keys are deliberately ignored. | KS-17 | Nuclei tokens, gitleaks, trufflehog |
| Exposed build and host config (next.config.js, vite.config, webpack.config, vercel.json, .vercel/project.json, netlify.toml) | KS-12 | Nuclei |
| Scripts from hijacked CDNs (polyfill.io and its sister domains) | KS-24 | ZAP |
| Known-vulnerable front-end libraries (jQuery, AngularJS, Lodash, Bootstrap, Moment, Handlebars, DOMPurify) | KS-25 | retire.js, ZAP, Pentest-Tools |
| Next.js versions with critical advisories (CVE-2025-29927, CVE-2025-55182). Kompile reads the version only and never sends an exploit. | KS-26 | none found as a version check |
| Exposed admin, database and AI tool panels (phpMyAdmin, Adminer, pgAdmin, Supabase Studio, PocketBase, Jupyter, Ollama, n8n, Open WebUI, Flowise, Grafana, Kibana, Storybook, Traefik, mongo-express). Matched by fingerprint; Kompile never logs in. | KS-27 | Nuclei exposed-panels, Pentest-Tools |
| GraphQL explorers and introspection (GET only) | KS-28 | Escape, Nuclei, Pentest-Tools |
| Subdomain takeover, using certificate-log discovery and dangling CNAMEs for GitHub Pages, Heroku, S3, Azure, Netlify, Surge, Shopify, Ghost, Pantheon and Tumblr | KS-29 | Detectify, Nuclei takeovers, Wapiti |
| Slack and Discord alerts for weekly monitoring | product | Detectify, Oh Dear, Intruder |
| App path for apps under a sub-path (built earlier the same night) | product | Nuclei targets |

Each new check has at least one test site and one trap in the benchmark corpus. The corpus now has 63 sites and 64 planted problems: all caught, 0 false alarms. Each check also has a Learn guide.

## Deliberately not built yet, and why

- **Live Supabase table, Firebase database and storage checks.** These are the top AI-app risk. Testing them means querying the owner's backend with the anon key the app itself publishes. Kompile currently sends only GET and HEAD requests to the verified site, and this needs a separate owner opt-in and careful legal wording first. Meanwhile, KS-17 already catches the leaked Supabase service_role key.
- **TLS depth:** every protocol version, weak ciphers, chain and OCSP. This needs a raw TLS client; testssl.sh-style probes that send malformed handshakes are excluded on purpose.
- **Email depth (DKIM selectors, MTA-STS, TLS-RPT, DANE) and DNSSEC.** These are DNS-only and good next candidates. They matter less for small apps.
- **Blocklist and malware reputation.** This needs a Google Safe Browsing API key. It could be added once the owner creates one.
- **Domain expiry (RDAP) and certificate expiry alerts 14 days out.** Good next candidates for monitoring.
- **CI gate (GitHub Action) and a public API.** The highest-value product features left. They need API tokens per user.
- **PDF and compliance reports, agency multi-site dashboards and open-port scans.** These are later, paid-tier items. Port scans also need clear disclosure.
