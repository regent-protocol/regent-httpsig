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
sig = await verifier.verify(method, url, headers)   # VerifiedSignature | None
```

Verification is **enrichment by default**: no `Signature` header costs nothing, a bad
signature yields `None`, and nothing ever raises on untrusted input. Use
`regent_httpsig.fastapi.RequiredSignatureDep` when a signature must be present — the 401
tells the agent exactly how to sign.

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

## What exactly is verified

| Check | Status |
|---|---|
| RFC 9421 Appendix B.2.6 Ed25519 vector (byte-exact) | ✅ in CI |
| Web Bot Auth draft -05 A.2.2 — sf-dictionary `Signature-Agent` covered with `;key=` | ✅ in CI¹ |
| Web Bot Auth A.2.3 — legacy sf-string form (**what OpenAI ships in production**) | ✅ in CI |
| Sign → verify roundtrip (fresh keys, full pipeline) | ✅ in CI |
| AAuth identity-mode roundtrip (`aa-agent+jwt` + `cnf.jwk` proof of possession) | ✅ in CI |
| Tampered request / expired signature / wrong directory key rejected | ✅ in CI |

¹ The signature bytes printed in the draft's own A.2.2 example do **not** verify over the
draft's own signature base (the legacy A.2.3 vector and RFC 9421 B.2.6 both do, so the defect
is in the example, not the canonicalization). Ed25519 is deterministic, so our test pins the
vector re-signed with the same RFC test key over the same byte-exact base — reported upstream.

## Both dialects, one verifier

- **Web Bot Auth** (`draft-meunier-web-bot-auth-architecture`): key discovery via
  `{Signature-Agent}/.well-known/http-message-signatures-directory`. Both wire forms of
  `Signature-Agent` are accepted — the current sf-dictionary and the legacy bare sf-string
  OpenAI actually sends.
- **AAuth** (`draft-hardt-oauth-aauth-protocol`, identity-based mode): the agent carries a
  JWT `agent_token` in `Signature-Key`; the issuer's JWKS verifies the token, the token's
  `cnf.jwk` verifies the request signature. Install with `pip install 'regent-httpsig[aauth]'`.
  For a full-protocol AAuth implementation (both roles, all token types) see
  [christian-posta/aauth-python-library](https://github.com/christian-posta/aauth-python-library) —
  this library is the thin relying-party verifier that handles both dialects.

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
    max_age_hours=25,       # reject signatures created earlier than this
    cache_ttl=600,          # key-directory cache seconds
))
```

Pass your app's shared client to reuse its pool: `HttpsigVerifier(http_client=my_async_client)`.

## Honest limitations

- Web Bot Auth and AAuth are **IETF drafts** (RFC 9421 itself is a final standard). We track
  the drafts; breaking draft changes land as minor releases while we're 0.x.
- **Ed25519 only** for now — it's what the agent ecosystem ships.
- Body coverage (`content-digest`) is verified when covered by the signature, but this
  library does not require it; decide per-route whether you need it.

## Related projects

[cloudflare/web-bot-auth](https://github.com/cloudflare/web-bot-auth) (TypeScript/Rust) ·
[christian-posta/aauth-python-library](https://github.com/christian-posta/aauth-python-library)
(full AAuth protocol) · [pyauth/http-message-signatures](https://github.com/pyauth/http-message-signatures)
(the RFC 9421 primitive this builds on)

---

Built and battle-tested in production by [Regent Protocol](https://regentprotocol.org) —
runtime control and identity for AI agents. Apache-2.0.
