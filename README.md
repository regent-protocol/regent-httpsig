# regent-httpsig

**Verify and sign AI agent HTTP traffic in Python — the way OpenAI signs and Cloudflare verifies.**
RFC 9421 · Web Bot Auth · AAuth

OpenAI's agents cryptographically sign every HTTP request they make. Cloudflare, AWS WAF and
Google verify those signatures. This library brings both sides of that handshake to Python:
**verify** signed agents hitting your API, and **sign** your own agent's traffic so bot walls
recognize it.

```bash
pip install regent-httpsig
```

## Verify: know which AI agent is calling — in 5 lines

```python
from fastapi import FastAPI
from regent_httpsig import HttpsigVerifier
from regent_httpsig.fastapi import attach, SignatureDep, VerifiedSignature

app = FastAPI()
attach(app, HttpsigVerifier())

@app.post("/v1/orders")
async def create_order(sig: VerifiedSignature | None = SignatureDep):
    if sig:
        print(sig.agent)    # "https://chatgpt.com"
        print(sig.keyid)    # RFC 7638 key thumbprint
    ...
```

No FastAPI? The core has no framework dependencies:

```python
verifier = HttpsigVerifier()
sig = await verifier.verify(method, url, headers)            # VerifiedSignature | None
out = await verifier.verify_detailed(method, url, headers, body)
# VerifiedSignature | VerificationError(code="expired_jwt", …) | None
```

Verification is **enrichment by default**: no `Signature` header costs nothing, a bad
signature yields `None`, and nothing ever raises on untrusted input. `verify_detailed()`
says *why* with the `Signature-Error` code of draft-hardt-httpbis-signature-key exactly
as AAuth -11 §11.3.4 assigns it (`invalid_signature`, `invalid_input`, `unsupported_scheme`,
`unsupported_algorithm`, `invalid_key`, `unknown_key`, `issuer_missing`, `issuer_mismatch`,
`invalid_jwt`, `expired_jwt`, `revoked_jwt`, `clock_skew`); `error.headers()` is the 401's
header set and `error.problem()` its problem+json body. Use
`regent_httpsig.fastapi.RequiredSignatureDep` when a signature must be present — the 401
carries that header, or `AAuth-Requirement: requirement=agent-token` when nothing was signed.

> **Behind a reverse proxy?** The agent signed the *public* URL
> (`https://api.example/…`), but your ASGI server sees `http://container/…`. The FastAPI
> dependency rebuilds the signed URL from `X-Forwarded-Proto` + `Host`, so make sure your
> proxy forwards the scheme — nginx: `proxy_set_header X-Forwarded-Proto $scheme;`.
> If signatures mysteriously fail to verify in production, check this first.

## Sign: get your agent past bot walls

```python
from regent_httpsig import EgressSigner

signer = EgressSigner(seed=os.environ["AGENT_KEY_SEED"],
                      signature_agent="https://myagent.example")
headers = signer.sign("POST", url, {"content-type": "application/json"})
resp = httpx.post(url, json=body, headers=headers)
```

Generate a key and the ready-to-publish `/.well-known/` files in one command:

```bash
regent-httpsig keygen --agent https://myagent.example --out ./well-known/
```

Publish the directory at `https://myagent.example/.well-known/http-message-signatures-directory`
and every Web Bot Auth verifier on the internet can now identify your agent.

The same key signs as an **AAuth agent** (-11 §11.3.3) — the token in `Signature-Key`,
the required components covered, `Content-Digest` computed when there is a body:

```python
headers = signer.sign_aauth("POST", url, {"content-type": "application/json"},
                            token=agent_token, body=raw_body)
```

and a **server** (a PS or AS calling a resource's usage or revocation endpoint, §11.3.2)
signs under the `jwks_uri` scheme with `ServerSigner(seed=…, server_id="https://ps.example",
dwk="aauth-person.json")` — publish `.jwks()` at your metadata document's `jwks_uri`.

## What exactly is verified

| Check | Status |
|---|---|
| RFC 9421 Appendix B.2.6 Ed25519 vector (byte-exact) | ✅ in CI |
| Web Bot Auth draft -05 A.2.2 — sf-dictionary `Signature-Agent` covered with `;key=` | ✅ in CI¹ |
| Web Bot Auth A.2.3 — legacy sf-string form (**what OpenAI ships in production**) | ✅ in CI |
| Sign → verify roundtrip (fresh keys, full pipeline) | ✅ in CI |
| AAuth -11 agent / person / auth tokens (`cnf.jwk` proof of possession, required components, body digest, 60 s `created` window, RS-51 token time, fully-specified algs, Ed25519 + ES256 possession keys) | ✅ in CI |
| AAuth -11 server scheme (`jwks_uri` with `id`/`dwk`/`kid`, `issuer_mismatch`, key rotation refetch) | ✅ in CI |
| Every -11 §11.3.4 Signature-Error code, `revoked_jwt` via the revocation record, RS-52 case-exact ids | ✅ in CI |
| Signed by [`aauth-signing`](https://github.com/christian-posta/aauth-python-library) (jwt scheme, keyid-less) → verified | ✅² |
| Tampered request / expired signature / wrong directory key rejected | ✅ in CI |

¹ The signature bytes printed in the draft's own A.2.2 example do **not** verify over the
draft's own signature base (the legacy A.2.3 vector and RFC 9421 B.2.6 both do, so the defect
is in the example, not the canonicalization). Ed25519 is deterministic, so our test pins the
vector re-signed with the same RFC test key over the same byte-exact base — reported upstream.

² Cross-library interop with `aauth-signing`'s jwt scheme: token layer, `cnf.jwk` proof of
possession and canonicalization all verify. Its signers correctly omit the optional `keyid`
parameter — which exposed an unconditional `keyid` read in the underlying RFC 9421 library
that we now handle. One deviation reported upstream to `aauth-signing`: it emits the
`Signature` byte sequence as base64url, while RFC 8941 requires standard base64. The
keyid-less shape is pinned in CI.

## Both dialects, one verifier

- **Web Bot Auth** (`draft-meunier-web-bot-auth-architecture`): key discovery via
  `{Signature-Agent}/.well-known/http-message-signatures-directory`. Both wire forms of
  `Signature-Agent` are accepted — the current sf-dictionary and the legacy bare sf-string
  OpenAI actually sends.
- **AAuth** (`draft-hardt-oauth-aauth-protocol-11`): the agent carries its token in
  `Signature-Key` under the `jwt` scheme — an agent token (`aa-agent+jwt`), a person token
  (`aa-person+jwt`, opt-in via `HttpsigConfig.resource_url`) or an auth token
  (`aa-auth+jwt`, pinned via `trusted_ps`); the issuer's JWKS, discovered through
  `{iss}/.well-known/{dwk}`, verifies the token, the token's `cnf.jwk` verifies the request
  signature. Servers sign under `jwks_uri` (`id`/`dwk`/`kid`). Install with
  `pip install 'regent-httpsig[aauth]'`. 0.7.0 is the **-11 cut-over** — one dialect, as
  published: fully-specified algorithms only (RFC 9864; `EdDSA` is refused), the required
  covered components, the 60-second `created` window, no tolerance on `exp`, revoked tokens
  named as revoked. `require_fully_specified_algs=False` survives for private test rigs only.
  For a full-protocol AAuth implementation (both roles, all token types) see
  [christian-posta/aauth-python-library](https://github.com/christian-posta/aauth-python-library) —
  this library is the thin relying-party verifier that handles both dialects.

## Budgets: meter a spending envelope (draft-hardt-aauth-budgets)

An agent can carry a PS-issued **auth token** (`typ: aa-auth+jwt`) with a
`budget` claim — a spending envelope it uses offline, no per-call round trip
to the control plane. The middleware does the whole resource-side checklist:
verify the token against your pinned PS, atomically reserve → commit →
release per request, answer with `AAuth-Budget`, and refuse exhausted
envelopes with a `401` + `AAuth-Requirement` (optionally carrying your signed
resource token with **one** consumption record — the presented token's
`{jti, consumed}` — so one agent never learns about a sibling's spending).
The cap is **per token**: a jti never draws on a sibling's grant; the
`(iss, sub, aud)` key is only the per-person ledger behind records and usage:

```python
from regent_httpsig import HttpsigConfig, HttpsigVerifier, InMemoryMeter
from regent_httpsig.fastapi import BudgetMiddleware

app.add_middleware(
    BudgetMiddleware,
    verifier=HttpsigVerifier(HttpsigConfig(
        resource_url="https://api.example",
        trusted_ps={"my-ps": "https://ps.example/jwks.json"},
    )),
    meter=InMemoryMeter(),
    price_fn=lambda request: PRICES.get(request.url.path),  # max cost, minor units
)
```

The only thing the library cannot do for you is pricing (`price_fn`) — that
is your domain. First known implementation of the draft; running in
production on [get4agent.com](https://get4agent.com).

**The August 20 additions** are covered too:

- `insufficient-budget` refusals carry **`required`** — the refused request's
  maximum cost — so the agent lowers its bound and retries instead of guessing.
- **Revocation** (-11 §11.12): `make_revocation_endpoint(meter, authenticate_ps=…)`
  takes the signed `POST {"jti", "exp"}`, keys the record by the caller's
  verified identity, answers an empty `200` always (no 404) and problem+json
  `invalid_request` / `unsupported_iss`. A revoked token stops spending at
  once, in-flight requests complete, and a later presentation is answered
  `401` + `Signature-Error: error=revoked_jwt` + `AAuth-Requirement:
  requirement=person-token` — no resource token (§11.12.5). Wire
  `HttpsigVerifier(is_revoked=meter.is_revoked)` so the verifier names it first.
- An **expired** auth token is answered the same way with `expired_jwt`
  (budgets editor's copy, 6 October): nothing is served or metered, and the
  token's final consumption record reaches its issuer through the usage
  endpoint, not on the challenge.
- **Streaming** responses run in the draft's cost-omitted mode: `reserved` in
  the header, commit when the stream ends (set `request.state.budget_cost`
  mid-stream if you learn the actual), and the agent recovers the exact cost
  from the next response's `remaining`.
- The **usage endpoint** (§Usage Counters) lets your PS query consumption
  without the agent in the loop — scope counters (`sub`, UTC calendar buckets)
  and per-key `jkts` totals, optionally signed:

```python
from regent_httpsig import InMemoryMeter, ResponseSigner, make_usage_endpoint

async def authenticate_ps(request):          # the PS signs as a server, §11.3.2
    return await verifier.verify_server(request.method, str(request.url),
                                        dict(request.headers), await request.body())

handler = make_usage_endpoint(
    meter,
    authenticate_ps=authenticate_ps,
    unit="USD", decimals=6,
    signer=ResponseSigner(seed=SEED, server_id="https://api.example"),  # dwk aauth-resource.json
)

@app.post("/usage")
async def usage(request: Request):
    return await handler(request)
```

- `validate_budget_grant(unit, decimals, budget_units)` enforces the resource
  metadata MUSTs before you mint a resource token — the "thousandfold error"
  guard.

**Test vectors**: [`vectors/aauth-budgets-vectors.json`](vectors/aauth-budgets-vectors.json) —
header serializations (including `required` and the cost-omitted streaming
case), the budget object, consumption records, and a fully worked signed
usage response with a fixed key, ready for cross-implementation checks.

## Security model (what a naive implementation gets wrong)

The verifier fetches key directories from **attacker-nameable origins** — whoever signs a
request chooses its `Signature-Agent`. regent-httpsig ships with the guard rails on:

- **SSRF protection by default**: https-only, every resolved IP must be public (catches
  `169.254.169.254`, loopback, private ranges, DNS names mapping to internal services),
  redirects never followed, responses size-capped.
- **Bounded caching**: per-instance TTL cache with eviction — a keyid-spam attack can't
  grow memory; failures are negative-cached so a dead origin can't be used to slow you down.
- **A valid signature proves key possession — not trustworthiness.** `VerifiedSignature.trusted`
  reflects only your configured allow-list; deciding *whether to trust* a key is your policy
  layer's job.

Known sharp edges of the underlying ecosystem, already handled: the upstream
`http-message-signatures` library cannot resolve RFC 9421 `;key=` dictionary members (we
provide the component resolver), it looks up header names case-sensitively while ASGI
frameworks lowercase them (we wrap), and it forgets to declare `typing_extensions` (we
declare it).

## Configuration

```python
from regent_httpsig import HttpsigConfig, HttpsigVerifier

verifier = HttpsigVerifier(HttpsigConfig(
    trusted_agents=frozenset({"https://chatgpt.com", "https://operator.openai.com"}),
    max_age_hours=25,              # Web Bot Auth: reject signatures created earlier than this
    signature_window_seconds=60,   # AAuth -11: the `created` window (advertise as signature_window)
    resource_url="https://api.example",                    # accept person / auth tokens for us
    trusted_ps={"https://ps.example": ""},                 # pinned issuers ("" = discover the JWKS)
    cache_ttl=600,                 # key-directory cache seconds
), is_revoked=meter.is_revoked)    # optional: name revoked tokens as revoked
```

Pass your app's shared client to reuse its pool: `HttpsigVerifier(http_client=my_async_client)`.

## Honest limitations

- Web Bot Auth and AAuth are **IETF drafts** (RFC 9421 itself is a final standard). We track
  the drafts; breaking draft changes land as minor releases while we're 0.x.
- Web Bot Auth is **Ed25519 only** — it's what the agent ecosystem ships. AAuth
  possession keys may be Ed25519 or P-256 (ES256); RS256 is accepted for issuer keys.
- On the AAuth path a request with a body **must** cover `content-digest` and
  `content-type` (-11 §11.3.3.1) and the digest is checked against the body you pass;
  the FastAPI layer reads the body for you. Web Bot Auth keeps its per-route choice.
- Not in 0.7.0: issuing person/resource tokens, missions, the `202` deferred
  `requirement=auth-token`, federated mode — the PS half of the protocol.

## Related projects

[cloudflare/web-bot-auth](https://github.com/cloudflare/web-bot-auth) (TypeScript/Rust) ·
[christian-posta/aauth-python-library](https://github.com/christian-posta/aauth-python-library)
(full AAuth protocol) · [pyauth/http-message-signatures](https://github.com/pyauth/http-message-signatures)
(the RFC 9421 primitive this builds on)

---

Built and battle-tested in production by [Regent Protocol](https://regentprotocol.org) —
runtime control and identity for AI agents. Apache-2.0.
