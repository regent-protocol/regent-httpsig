# Changelog

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
