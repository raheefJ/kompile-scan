# Security policy

Kompile Scan makes outbound requests on behalf of its users, so bugs that weaken its safety rules matter most. Please report privately:

- reaching private, loopback, link-local or cloud metadata addresses (SSRF)
- DNS rebinding or redirect tricks that bypass the address pinning
- a report that leaks a secret, file contents or personal data
- anything that makes a check send more than ordinary read-only requests

Use GitHub's "Report a vulnerability" button on this repository (private security advisories). We aim to reply within 3 working days and to credit reporters who want credit.

Please only test against sites you own, or against the local benchmark (`npm run bench:serve`).
