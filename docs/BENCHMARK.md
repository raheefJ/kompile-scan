# Kompile Scan benchmark

Three runs on 10/12/2026, all on one Windows PC with local targets only (nothing outside was scanned):

1. **Kompile's own corpus.** 39 local sites with known planted problems, plus traps built to cause false alarms.
2. **Head-to-head with Nuclei 3.11.1.** ProjectDiscovery's open-source scanner, run with its default 14,000+ community templates on the same 39 sites.
3. **OWASP Juice Shop 20.3.0.** A deliberately vulnerable app written by a third party, scanned by both tools.

Reproduce:

- `npm run bench`
- `npx tsx bench/bench-serve.ts` with Nuclei pointed at `bench/out/bench-targets.txt`, then `npx tsx bench/bench-compare.ts`
- `npx tsx bench/bench-local.ts http://127.0.0.1:3300`

Raw output is in `bench/out/`.

## 1. Kompile's own corpus

| Sites | Planted problems | Caught | Missed | False alarms | Median scan |
| --- | --- | --- | --- | --- | --- |
| 63 | 64 | 64 | 0 | 0 | 31 ms (local) |

The traps that must not fire:

- a single-page app that answers every path with its home page
- a page with a Stripe publishable key, which is safe to expose
- a Supabase anon key, which is also safe
- a broken source-map link
- a blog post quoting a Python traceback
- robots.txt pointing at a normal sign-in page
- a marketing page at /metrics
- a fully hardened site

## 2. Kompile vs Nuclei, same 39 sites

Nuclei findings are mapped to the matching Kompile check by template name and tags. The rules are in `bench/bench-compare.ts` and were fixed before results were read.

Nuclei findings outside the compared checks are listed in the evidence and never counted against it. These include technology detection and the newer cross-origin headers.

Three checks are left out because the setup cannot test them fairly:

- the DNS checks (KS-15, KS-23), because Nuclei was pointed at an IP address
- mixed content (KS-19), because Nuclei only checks it on https:// pages

| | Caught | Missed | False alarms | Recall | Precision | Time for 39 sites |
| --- | --- | --- | --- | --- | --- | --- |
| **Kompile Scan** | **45 / 45** | **0** | **0** | **100%** | **100%** | **4.5 s** |
| Nuclei, as shipped | 29 / 45 | 16 | 73 | 64% | 28% | 461 s |
| Nuclei, lenient | 27 / 45 | 18 | 0 | 60% | 100% | 461 s |

The lenient row ignores two Nuclei rules that are judgement calls rather than defects:

- **It asks for `SameSite=Strict` on every cookie.** `Lax` is the browser default and OWASP accepts it.
- **It asks for `X-Frame-Options` even when CSP `frame-ancestors` already blocks framing.**

Those two rules cause all 73 of the as-shipped false alarms.

**Nuclei did not catch these, and Kompile did:**

- Secret keys inside JavaScript bundles. Nuclei's key templates mostly run on local files, not on live sites.
- Public source maps.
- Python, Node, Django and Express debug pages. Nuclei only caught a Laravel debug page.
- File listings that the home page doesn't link to.
- A Spring Boot environment endpoint.
- A Swagger UI page.

**Fairness fixes made before the final run.** Each fix made Nuclei's score better:

- The fake `.git` folder now also serves `/.git/config`, as a real one does.
- The fake `.DS_Store` is sent as a binary file.
- The fake Prometheus page has the standard counters every real one has.
- `/api-docs` redirects to `/api-docs/`, as real servers do.

Nuclei went from 26 to 29 catches. The first run is kept in `bench/out/nuclei-corpus-run1.jsonl`.

## 3. OWASP Juice Shop (third-party target)

Juice Shop has many problems that can only be found by attacking it, such as SQL injection and XSS. Kompile never attacks a site, by design. The comparison below covers only problems that can be seen from outside without breaking anything.

| Problem visible from outside | Kompile (before) | Kompile (now) | Nuclei |
| --- | --- | --- | --- |
| No HSTS | Yes | Yes | Yes |
| No Content-Security-Policy | Yes | Yes | Yes |
| No Referrer-Policy | Yes | Yes | Yes |
| Public Prometheus metrics at /metrics | No | Yes | Yes |
| Public API explorer at /api-docs | No | Yes | Yes |
| File listing at /ftp (named in robots.txt) | No | Yes | No |
| Express stack traces under /api/ and /rest/ | No | Yes | No |
| File listings at /encryptionkeys and /support/logs | No | No | No |
| **Total of 8** | **3** | **7** | **5** |
| Time | 0.4 s | 0.3 s | 314 s* |

\* Nuclei was rate-limited to 150 requests per second here, because the first run at full speed crashed Juice Shop by running it out of memory.

**Disclosure:** the "now" column includes four rules written after looking at Juice Shop. Those rules are general, not Juice-Shop-specific:

- folders named in robots.txt
- Express and serve-index file listings
- Prometheus, Actuator and pprof endpoints
- Swagger UI pages

Each one was also added to the corpus with a matching trap. Kompile before those rules found 3 of the 8 problems, behind Nuclei's 5. Kompile now finds 7.

## 4. Blind test: OWASP WebGoat 2026.4 (unseen target, rules frozen)

To remove the "tuned after looking" problem, Kompile's rules were frozen before WebGoat was downloaded. The fingerprint is in `bench/out/blind-test-checks-sha256.txt`, sha256 `b6657e50...`, and it was re-checked just before the scan.

Kompile scanned the site root, which is what a customer registers. Nuclei scanned both the root and `/WebGoat`, the path the app actually runs under, which gave it an advantage.

| Problem visible from outside (all confirmed by hand) | Kompile (frozen) | Nuclei |
| --- | --- | --- |
| No HSTS | Yes | Yes |
| No Content-Security-Policy | Yes | Yes |
| No X-Frame-Options or frame-ancestors | Yes | Yes |
| No X-Content-Type-Options | Yes | Yes |
| No Referrer-Policy | Yes | Yes |
| Tomcat exception report when the URL contains "[" | No | Yes |
| Spring Boot actuator `/env` and `/configprops` public under `/WebGoat` | No | Yes |
| **Total of 7** | **5** | **7** |
| Time | 0.06 s | 243 s |

**Nuclei won the blind test.** Nuclei also raised two findings that were wrong or opinion-based:

- It reported an "IBM DB2 database server", which isn't there.
- It flagged the `SameSite=Strict` cookie rule again.

**Fixed after the blind test.** Each fix was added to the corpus with a test site and a trap:

- **Java and Tomcat exception reports.** Tomcat's ordinary 404 "Status Report" is a trap and must not be flagged.
- **A third error probe,** an ordinary GET request with "[" in the query.
- **Spring Boot actuator** at `/actuator` and `/actuator/configprops`.

Kompile now catches the Tomcat exception on WebGoat from the root alone, so it finds 6 of 7.

**Sub-path apps, added after the test:** owners can now set an app path (for example `/WebGoat`) on their verified site. It is the same host, so ownership still covers it, and Kompile then also checks the sensitive files under that path. With the path set, Kompile finds **7 of 7** on WebGoat in 0.25 s, with no false alarms. Nuclei found 7 of 7 in 243 s, plus one false alarm. The blind result above still stands: it was 5 of 7, and Nuclei won it.

## 5. Second blind test: DVWA (unseen target, rules frozen)

DVWA was pinned to commit `068d974`. It ran on portable PHP 8.3.35 using the standard development settings, with MariaDB 11.4.13. Kompile's rules were frozen before the download: sha256 `f2d271d7...`, recorded in `bench/out/blind-test-2-checks-sha256.txt` and re-checked before the scan. Both tools scanned the site root.

| Problem visible from outside without logging in (all confirmed by hand) | Kompile (frozen) | Nuclei |
| --- | --- | --- |
| HSTS, CSP, framing, nosniff, Referrer-Policy missing (5) | 5 | 5 |
| Session cookies without Secure | Yes | Yes |
| Exact PHP version in X-Powered-By | Yes | No (it only detected that the site uses PHP) |
| Public `/Dockerfile` | No | Yes |
| **Total of 8** | **7** | **7** |
| Time | 0.18 s | 328 s |

**The blind result is a tie.**

**What Kompile cannot find by design:** Nuclei logged in with DVWA's default admin password and rated it critical. Kompile never tries passwords. That is an attack, not a read-only check, and it is not allowed without a pentest contract.

**Not counted for either tool:** Nuclei's "PHP stack trace" finding. It was the normal not-found page of PHP's built-in test server, which was used to run DVWA here, and it reveals nothing internal.

**Fixed after the test:** a `/Dockerfile` rule, with a test site and a trap (a blog page quoting a Dockerfile). Kompile now finds 8 of 8 on DVWA.

## Blind tests so far

| Target | Kompile (rules frozen) | Nuclei | Result |
| --- | --- | --- | --- |
| WebGoat 2026.4 | 5 of 7 | 7 of 7 | Nuclei won |
| DVWA (commit 068d974) | 7 of 8 | 7 of 8 | Tie |

After each test, the misses became general rules. Kompile now finds 7 of 7 on WebGoat (with the app path set) and 8 of 8 on DVWA.

## What this does and does not show

- **Read-only, outside-in checks for small web apps:**
  - On known targets, Kompile caught more and raised fewer false alarms than Nuclei's default setup, and it was about 100 to 1,000 times faster.
  - On unseen targets it has lost once and tied once.
- **Nuclei covers far more ground overall.** It has thousands of CVE checks, default-password logins and technology fingerprinting. Kompile does not try to match that, and Nuclei is the better tool for that job.
- **The corpus and the mapping are ours.** An independent claim needs a third party running the scripts, or consenting real sites.

## Coverage compared with other free scanners

Based on each tool's **public documentation**, not side-by-side tests. Check again before quoting publicly.

| Check | Kompile Scan | Mozilla HTTP Observatory | securityheaders.com |
| --- | --- | --- | --- |
| Security headers (HSTS, CSP, framing, nosniff, referrer) | Yes | Yes | Yes |
| Cookie flags | Yes | Yes | Partial |
| CORS misconfiguration | Yes | Yes | No |
| Subresource integrity | Yes | Yes | No |
| Mixed content | Yes | Partial (via CSP) | No |
| Exposed `.env`, `.git`, SQL dumps, ZIP backups, metrics, actuator | Yes | No | No |
| Directory listings (including folders named in robots.txt) | Yes | No | No |
| Secret keys inside the site's JavaScript | Yes | No | No |
| Public source maps | Yes | No | No |
| Verbose error and debug pages | Yes | No | No |
| Public API docs and explorers (OpenAPI / Swagger UI) | Yes | No | No |
| Email spoofing (SPF / DMARC) | Yes | No | No |
| CAA record | Yes | No | No |
| Plain-English fix for each finding | Yes | Partial | Partial |
| Proof of site ownership before scanning | Yes | No (public) | No (public) |
| Weekly re-check with alerts | Yes (Pro) | No | No |
| Hijacked CDNs (polyfill.io), vulnerable JS libraries, critical Next.js versions | Yes | No | No |
| Exposed admin, database and AI tool panels; GraphQL introspection | Yes | No | No |
| Forgotten subdomains that can be taken over | Yes | No | No |
| Slack and Discord alerts | Yes (Pro) | No | No |

Checks KS-24 to KS-29 and the alerts come from the 10/12 tool research in [TOOL-GAPS.md](TOOL-GAPS.md).
