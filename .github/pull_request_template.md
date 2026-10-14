## What this changes

## Proof
- [ ] Test site that must be flagged added to `bench/bench-scan.ts`
- [ ] Trap that must stay quiet added
- [ ] `npm run typecheck && npm test && npm run bench && npm run bench:mutate` all pass with 0 missed and 0 false alarms
- [ ] Only GET/HEAD requests, no payloads, no logins, no secrets in evidence
