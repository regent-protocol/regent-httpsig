# Security Policy

## Reporting a vulnerability

Email **security@regentprotocol.org**. We aim to acknowledge within 72 hours and follow
coordinated disclosure: please give us up to 90 days before publishing details.

Please include a minimal reproduction. PGP is available on request.

## Scope notes

- The verifier is designed to be safe against untrusted input by construction: it never
  raises on malformed signatures, fetches attacker-nameable URLs only through an SSRF
  guard (https-only, public-IP-only, no redirects, size caps), and bounds its caches.
- A **valid signature proves key possession, not trustworthiness** — reports along the
  lines of "any agent can sign up" describe the protocol's design, not a vulnerability.
- Vulnerabilities in the underlying `http-message-signatures` library should be reported
  upstream; we will ship mitigations where feasible.

## Supported versions

The latest minor release receives security fixes.
