# Roadmap

Kompile Scan aims to be the scanner people reach for first when they ship an app built with AI. Every item follows the
project rule: a test site that must be caught, a trap that must stay quiet, and 0 false alarms on the benchmark.

## Good first issues

These are small and self-contained, and come with a clear test.

- **More secret formats:** Postmark, Mailgun, Twilio account SID and secret pairs, Cloudflare API tokens, Sentry auth tokens, Supabase secret keys (`sb_secret_`), xAI and Mistral keys. Each one needs a fake key built at runtime in the corpus.
- **More admin panels:** pgweb, Directus, Payload CMS, Strapi admin, Appwrite console, Coolify, Dify, Flowise UI, LangFlow and AnythingLLM. Detection is by page title only.
- **More takeover fingerprints:** Fly.io, Render, Webflow, Readme.io and Help Scout, from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).
- **More vulnerable libraries:** Vue 2 (end of life), Axios, Underscore and Chart.js advisories.
- **CSP depth:** wildcard sources, `data:` in script-src, and missing `base-uri` or `object-src`.

## Next

- **Version advisories from data:** generate the Next.js, Nuxt and SvelteKit tables automatically from the npm registry's security deprecations, instead of keeping them by hand.
- **Email depth:** DKIM at common selectors (resend, sendgrid, google), MTA-STS and TLS-RPT.
- **Certificate depth:** incomplete chains, weak keys and expiring-soon alerts.
- **Monthly blind test:** a new open-source vulnerable app every month, with rules frozen first and results published whether we win or lose.
- **Packaging:** a `kompile-scan` Docker image and a Homebrew formula.

## Later

- **Browser extension:** "scan this tab" for sites you own.
- **Translations** of the fix text.
- **An independent security audit** of the request layer (SSRF protections).

## Never

- **Attacks:** logging in, guessing passwords, sending exploit payloads, or fuzzing.
- **Backend data:** reading or reporting a site's data (table rows, bucket contents).
- **Uninvited scanning:** scanning sites the user does not own.
