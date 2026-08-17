# Changelog

## 0.1.1

- AAuth: tolerate absent `keyid` (RFC 9421 makes it optional; the key comes from
  the token's `cnf.jwk`). Exposed by cross-library interop with
  christian-posta/aauth-signing, whose signers correctly omit it; that signer's
  exact keyid-less shape is now pinned in CI.

## 0.1.0

Initial release, extracted from Regent Protocol's production marketplace
(get4agent.com), where it authenticates self-onboarding AI agents.

- `HttpsigVerifier` — RFC 9421 verification for both agent dialects:
  - Web Bot Auth (draft -05): sf-dictionary `Signature-Agent` with `;key=`
    member selection AND the legacy sf-string form OpenAI ships in production;
    key discovery via `/.well-known/http-message-signatures-directory`.
  - AAuth (identity-based mode, `[aauth]` extra): `aa-agent+jwt` in
    `Signature-Key`, issuer JWKS discovery, `cnf.jwk` proof of possession.
  - SSRF-guarded directory fetching (https-only, public-IP-only, no redirects,
    size-capped) with bounded per-instance caching.
- `EgressSigner` + `regent-httpsig keygen` — sign outbound agent traffic
  (Web Bot Auth), generate keys and ready-to-publish well-known files.
- FastAPI integration (`[fastapi]` extra): `SignatureDep` (enrichment) and
  `RequiredSignatureDep` (authentication with a self-explaining 401).
- Test suite pinned to the official RFC 9421 B.2.6 vector, both Web Bot Auth
  appendix vectors (A.2.2 re-signed — the draft's printed signature does not
  verify over its own base; reported), and full sign→verify roundtrips for
  both dialects.
