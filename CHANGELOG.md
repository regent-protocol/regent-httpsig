# Changelog

## 0.2.0

AAuth draft **-11** support (per the editor's copy, ahead of datatracker publication):

- **Fully-specified algorithms (RFC 9864):** `Ed25519` accepted everywhere
  (registered with PyJWT, including JWKS entries PyJWK cannot parse).
  New `HttpsigConfig.require_fully_specified_algs` enforces the -11 MUST NOT on
  the polymorphic `EdDSA`; the default keeps accepting it while the -10
  ecosystem migrates, and will flip when -11 posts.
- **Person tokens** (`typ: aa-person+jwt`): PS-issued, per-resource `aud`,
  `cnf`-bound, ≤1h lifetime — verified via `{iss}/.well-known/aauth-person.json`.
  Opt-in: set `HttpsigConfig.resource_url` (the token's `aud` must name it).
  Result scheme: `"aauth-person"`, `sub` = the PS's directed user identifier.
- Strict mode also enforces the -11 requirement that `cnf.jwk` carries a
  fully-specified `alg` member.

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
