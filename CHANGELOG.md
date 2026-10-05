# Changelog

## 0.7.0

**AAuth -11 cut-over** (draft-hardt-oauth-aauth-protocol-11, published
25 September 2026; Signature-Key -09; budgets editor's copy of 6 October). One
dialect, as the editor asked: the -10 forms are gone, not kept behind a flag.
Breaking for every AAuth signer and resource; Web Bot Auth is untouched.

*Resource side (§11.3.4 — a typed answer for every refusal):*

- **`HttpsigVerifier.verify_detailed()`** returns a `VerifiedSignature` or a
  **`VerificationError`** carrying the Signature-Error code -11 assigns:
  `invalid_signature`, `invalid_input` (+ `required_input`),
  `unsupported_scheme` (+ `Accept-Signature-Scheme`), `unsupported_algorithm`
  (+ `Accept-Signature-Alg`), `invalid_key`, `unknown_key`, `issuer_missing`,
  `issuer_mismatch`, `invalid_jwt`, `expired_jwt`, `revoked_jwt`, `clock_skew`.
  `error.headers()` is the 401's header set, `error.problem()` the
  `application/problem+json` body (`type: urn:ietf:params:sig-error:<code>`).
  `verify()` keeps its `None`-on-failure contract.
- **Covered components are enforced** (§11.3.3.1): `@method @authority @path
  signature-key`, plus `content-digest content-type` when the request has a
  body — and the digest is checked against the body you pass. Missing
  components are `invalid_input` with the full `required_input` list.
- **`created` window** (§11.3.4 step 3): `HttpsigConfig.signature_window_seconds`
  (default 60). Older than the window is `invalid_signature`; further ahead of
  our clock is `clock_skew`; a past `expires` is `invalid_signature`. The
  upstream library's 5-second skew rule no longer pre-empts these.
- **RS-51 token time**: `exp` has no tolerance; `iat` is not a validity check
  (only an `iat` beyond the window ahead is refused, as `clock_skew`); person
  and auth tokens live at most **3600 s exactly** (the 90 s grace is gone);
  `typ` is read first; an auth token's `dwk` must be `aauth-person.json` or
  `aauth-access.json`.
- **Fully-specified algorithms by default** (§11.3.1, RFC 9864):
  `require_fully_specified_algs` is now `True`. The polymorphic `EdDSA` and a
  `cnf.jwk` without `alg` are `unsupported_algorithm` with
  `Accept-Signature-Alg: Ed25519, ES256, RS256`. A P-256 possession key
  (ES256) now verifies. The flag stays only for private test rigs.
- **The `jwks_uri` server scheme** (§11.3.2, Signature-Key §3.6):
  `sig=jwks_uri;id="…";dwk="aauth-person.json";kid="…"` — the metadata
  document at `{id}/.well-known/{dwk}` must name `issuer == id`
  (`issuer_mismatch`), its `jwks_uri` is followed, the `kid` found (one
  refetch on rotation, then `unknown_key`). `verify_server()` is the
  entry point for usage and revocation endpoints; `trusted_ps` may pin a
  JWKS URL or `""` to discover it.
- **Revocation hook**: `HttpsigVerifier(is_revoked=meter.is_revoked)` — a
  token the application has on record as revoked is answered `revoked_jwt`
  (RS-43, §11.12.5), never "invalid" or "expired".
- **RS-52**: agent identifiers compare exactly; no case folding (test pinned).

*FastAPI layer:*

- `RequiredSignatureDep` answers a failed signature with `401` +
  `Signature-Error` (+ `Accept-Signature-*`, + `AAuth-Requirement:
  requirement=person-token` for a revoked/expired person or auth token) and a
  problem+json body; an unsigned request gets `AAuth-Requirement:
  requirement=agent-token` (§6.1). New `SignatureErrorDep`,
  `RequiredServerSignatureDep`, `signature_error_response()`.
- `BudgetMiddleware`: a **revoked** auth token is `revoked_jwt` +
  `requirement=person-token`, with **no resource token** (the PS would reject
  one naming a revoked token) and no `AAuth-Budget`; an **expired** auth token
  is `expired_jwt` + `requirement=person-token` the same way (budgets editor's
  copy, 6 October). The 0.5.1 final-record challenge and
  `allow_expired_auth_token` are removed — the final figure reaches the
  issuer through the usage endpoint. Any other signed-but-failing request on
  a priced route is refused with `Signature-Error` instead of being treated
  as unsigned.

*Revocation endpoint (RS-60, §11.12):*

- `make_revocation_endpoint`: the body is **`{"jti", "exp"}`**; the issuer
  comes from the caller's verified server signature, never from the body.
  The pair is recorded whether or not the token was ever seen here; the
  answer is always an empty `200` — **no 404**. Errors are problem+json:
  `invalid_request` 400 (incl. `exp` beyond `max_token_lifetime` + skew),
  `unsupported_iss` 403 (`accepted_issuers=` predicate), a failed signature
  401 + `Signature-Error`.
- `InMemoryMeter.record_revocation(iss, jti, exp)` and `is_revoked(iss, jti)`;
  entries live until `exp` + 60 s. `revoke()` remains for tokens the meter
  holds.
- `make_usage_endpoint` / `make_revocation_endpoint` accept an
  `authenticate_ps` that returns a `VerifiedSignature`, an issuer string, a
  `VerificationError` or `None`; refusals are 401 + `Signature-Error`.

*Signers:*

- **`EgressSigner.sign_aauth(method, url, headers, token=…, body=…)`**: the
  -11 agent signature — `Signature-Key: sig=jwt;jwt="…"`, the required
  components (+ body components with a computed `Content-Digest`), `created`
  only, no `keyid`. `EgressSigner.public_jwk` now carries `alg: Ed25519`
  (RFC 9864) for `cnf.jwk`; the Web Bot Auth directory is unchanged.
- **`ServerSigner(seed, server_id, dwk)`**: the jwks_uri scheme for a PS/AS
  (or a resource) calling another server; `.jwks()` is what to publish.
- **`ResponseSigner(seed, server_id, dwk="aauth-resource.json")`** emits the
  -11 `Signature-Key` form; the `jwks_url` form is gone. Golden vectors
  regenerated.
- `sign_request()`, `content_digest()`, `parse_signature_key()`,
  `parse_signature_input()`, `build_person_token_requirement()` exported.

Dropped: `allow_expired_auth_token`, `VerifiedSignature.expired`,
`EXPIRED_AUTH_TOKEN_GRACE`, `ResponseSigner(jwks_url=)`, the `{iss, jti}`
revocation body, the 90 s lifetime grace, `EdDSA` by default.

## 0.6.0

**Budgets — revocation reaches the meter** (base protocol §Token Revocation,
budgets §Token Scope; drain rule per AAuth issue #151, raised from our
production and not yet in the editor's copy):

- **`InMemoryMeter.revoke(iss, jti)`**: withdraws the grant so no new request
  can reserve against the token; requests already in flight complete and are
  committed as usual. Idempotent; `False` for an unknown `(iss, jti)`.
- **`TokenRevoked(drained)`**: what `reserve()` returns for a revoked token.
  `drained` is true once nothing is in flight on it.
- **Final record only after the drain**: `consumed_record()` withholds a
  revoked token's record while requests are in flight, so a record the
  resource issues after the revocation is the token's final figure and the
  issuer can settle on it (the ordering is checkable by `iat`).
- **`make_revocation_endpoint(meter, authenticate_ps=…)`**: the base
  protocol's endpoint — signed `POST {"iss","jti"}`, `200` empty on success or
  already-invalid, `404` unknown, `403` when the caller is not the issuer.
- **`BudgetMiddleware`** answers a revoked token with the plain
  `requirement=auth-token` challenge (`code: AUTH_TOKEN_REVOKED`, no
  `AAuth-Budget`), the resource token carrying the final record once drained.
- `revocation_state(key, jti)` for resources that learn of revocation out of
  band (e.g. from their own registry) and want the same challenge.

## 0.5.1

**Budgets — the final-record challenge for expired auth tokens** (draft
§Budget Exhaustion "auth token expired" + §Settlement). The final/snapshot
settlement rule needs a moment at which the resource *states* a token's final
figure — and that moment is the challenge to an expired token. A verifier that
refuses to look at an expired token can never build it, so the issuer never
sees a final record and accounts every allocation as fully consumed forever.

- `BudgetMiddleware` answers a genuine-but-expired `aa-auth+jwt` (issuer
  signature and proof of possession verified, request signature fresh) with
  `401` + plain `AAuth-Requirement: requirement=auth-token;resource-token=…`
  (no `reason` — the budget didn't run out, the token did) and `code:
  AUTH_TOKEN_EXPIRED`. The resource token carries the presented token's
  `{jti, consumed}`; no `AAuth-Budget` header. Nothing is served or metered.
- `HttpsigVerifier.verify(..., allow_expired_auth_token=True)` — **opt-in,
  default False**: returns the token with `VerifiedSignature.expired=True`
  for up to `EXPIRED_AUTH_TOKEN_GRACE` (2h, the meter's retention) after
  `exp`. Access decisions through `verify()`/`require_signature` are
  unchanged: an expired token is still `None` there, and the middleware never
  caches an expired result for downstream dependencies.
- `build_aauth_requirement(reason=None, …)` emits the reason-less challenge.

## 0.5.0

**AAuth Budgets — per-token cap, one consumption record** (draft-hardt-aauth-budgets
editor's copy, September 2026; issue #120):

- **No more pooling.** `InMemoryMeter` caps each auth token at its own `budget`
  (§Aggregation): committed consumption plus outstanding reservations against
  the presented `jti` never exceed *its* grant, and a token never draws on a
  sibling's allocation. The `(iss, sub, aud)` key survives as the per-person
  **ledger** for records and usage counters — it is not a second ceiling.
  0.4 pooled a person's live grants into one purse, which let a jti spend past
  its own grant; the overflow, spent from a sibling's allocation, was never
  attributed and the sibling's remainder later released as unspent. The
  `required` member makes a fragmented agent's re-authorization a calculation,
  so the purse bought nothing worth that.
- **One record on the wire.** Budget refusals carry a single
  `budget_consumed` object — `{"jti", "consumed"}` for the PRESENTED token —
  per §The Consumption Record. New `InMemoryMeter.consumed_record(key, jti)`;
  `consumed_records(key, jkt=…)` stays as the audit view.
- **Breaking:** `InMemoryMeter.remaining(key)` → `remaining(key, jti)`;
  `resource_token_provider(key, records: list)` → `(key, record: dict | None)`.
  `InsufficientBudget.remaining` is now the presented token's balance.
- Test vectors regenerated (`consumption_records` is one object).

## 0.4.0

**AAuth Budgets — the August 20 editor's-copy additions** (allocation model,
omitted cost, `required`, usage counters):

- **`required` member**: an `insufficient-budget` refusal now carries the
  refused request's maximum cost in `AAuth-Budget`, so the agent's retry is a
  calculation (fit the bound to `remaining`) rather than a search.
- **Streaming / cost-omitted** (§cost-omitted): a streamed response states
  `reserved` (REQUIRED when `cost` is omitted) with `remaining` already net of
  the hold, commits when the stream ends (`request.state.budget_cost` may be
  set mid-stream), and the agent recovers the exact figure from the next
  response's `remaining`. SSE is recognized automatically; other streams opt
  in with `request.state.budget_streaming = True`.
- **Usage endpoint** (§Usage Counters): `make_usage_endpoint(meter, …)` —
  scope queries (`sub` calendar counters: day/week/month/year/all_time on UTC
  boundaries) and per-key `jkts` queries; unrecognized scope values omit
  `usage` (never zero — a query must not reveal whether an account exists);
  unrecognized/pruned thumbprints are omitted from `jkts` (never zero — a
  false zero misleads an allocation decision); per-key figures pruned on 24h
  IDLE, so a key in continuous use is never pruned; figures keyed by the
  issuing PS, so the endpoint structurally answers only the party whose
  tokens were accepted. PS authentication is pluggable (`authenticate_ps`).
- **Signed usage responses** (§The Signed Response): `ResponseSigner` — an
  Ed25519 HTTP Sig over `@status`, `content-type`, `content-digest`, bound to
  the request via `@authority`/`@path` with the `req` parameter.
- **`validate_budget_grant`**: the §Resource Metadata MUSTs (only declared
  units; declared decimals) as a pre-mint guard against the draft's
  "thousandfold error".

## 0.3.0

**AAuth Budgets** (draft-hardt-aauth-budgets, editor's copy) — the resource
side, first known implementation (running in production on get4agent.com):

- **Auth tokens** (`typ: aa-auth+jwt`): PS-issued budget carriers verified
  against a configuration-pinned PS (`HttpsigConfig.trusted_ps`: issuer →
  JWKS URL), `aud`-checked against `resource_url`, `cnf`-bound, ≤1h lifetime.
- **`BudgetClaim` + `InMemoryMeter`**: atomic reserve → commit → release
  pooled per the draft's `(iss, sub, aud)` aggregation key; conservative
  crash-safety (an unresolved reservation counts as consumed); consumption
  records **scoped to the presenting agent's `jkt`** so one agent never
  learns about a sibling's spending.
- **`BudgetMiddleware`** (FastAPI): `price_fn` hook, metering cycle,
  refusals (401 + `AAuth-Requirement` with `reason=insufficient-budget` /
  `budget-exhausted` and an optional resource token via
  `resource_token_provider`), per-response `AAuth-Budget` header; error
  responses release the reservation.
- `build_aauth_budget_header` / `build_aauth_requirement` — RFC 9651
  serialization (note: the field is a Dictionary, so members are
  comma-separated; the draft's §11 example shows parameter separators).

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
