# Contributing to Kompile Scan

Thank you for helping. The project has one rule that keeps it trustworthy: **no check lands without proof that it works and proof that it stays quiet.**

## Adding or changing a check

1. **Write the check** in `src/checks.ts`. Use only GET or HEAD requests through the injected `req`, give every request a timeout and a body limit, and never put file contents or full secrets in `evidence`.
2. **Add a test site** to `CORPUS` in `bench/bench-scan.ts` that has the problem. Use `routes`, `homeExtra` or `jsExtra` if the existing options do not cover it, and list the check id in `expect`.
3. **Add a trap**: a site that looks similar but is fine (a publishable key, a blog post quoting an error, a single-page app answering every path). It must not be flagged.
4. **Add it to the mutation lab** in `bench/training-mutate.ts` if the problem can be combined with others.
5. **Run everything**: `npm run typecheck && npm test && npm run bench && npm run bench:mutate`. All of them must stay at 0 missed and 0 false alarms.
6. **Explain the fix.** Every finding needs `why` and `fix` text a non-expert can act on.

If the check is based on an advisory or incident, link it in the pull request.

## What we will not merge

- anything that logs in, guesses passwords or sends exploit payloads, even "harmless" ones
- requests to private, loopback or link-local addresses, or ports other than 80 and 443
- checks that read and report data from a site's backend, such as table contents or bucket listings
- evidence that includes secrets, file contents or personal data

## Reporting a security problem in the scanner itself

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Be kind and assume good faith. We follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
