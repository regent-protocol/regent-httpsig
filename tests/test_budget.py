"""AAuth Budgets (draft-hardt-aauth-budgets): claim parsing, header wire format,
meter semantics (pooling, races, conservative failure) and the FastAPI
middleware end to end over a PS-issued auth token."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request

from regent_httpsig import (
    BudgetClaim,
    EgressSigner,
    HttpsigConfig,
    HttpsigVerifier,
    InMemoryMeter,
    InsufficientBudget,
    InvalidBudgetClaim,
    UnitMismatch,
    b64url,
    build_aauth_budget_header,
    build_aauth_requirement,
    generate_seed,
)
from regent_httpsig.budget import Reservation, TokenRevoked
from regent_httpsig.fastapi import BudgetMiddleware
from regent_httpsig.sfv import SFDictionary

KEY = ("https://ps.example", "owner-1", "https://api.example")


# ── BudgetClaim ──────────────────────────────────────────────────────────────


def test_claim_absent_is_none() -> None:
    assert BudgetClaim.parse({"iss": "x"}) is None


def test_claim_valid() -> None:
    claim = BudgetClaim.parse({"budget": {"amount": 5000000, "unit": "USD", "decimals": 6}})
    assert claim == BudgetClaim(amount=5000000, unit="USD", decimals=6)


@pytest.mark.parametrize(
    "raw",
    [
        "not-an-object",
        {},  # all three members are REQUIRED
        {"amount": -1, "unit": "USD", "decimals": 6},
        {"amount": 1.5, "unit": "USD", "decimals": 6},  # floats are not integers
        {"amount": True, "unit": "USD", "decimals": 6},  # bools are not integers
        {"amount": 1, "unit": "", "decimals": 6},
        {"amount": 1, "unit": "USD", "decimals": -1},
        {"amount": 1, "unit": "USD"},  # decimals missing
    ],
)
def test_claim_malformed_raises(raw: Any) -> None:
    with pytest.raises(InvalidBudgetClaim):
        BudgetClaim.parse({"budget": raw})


# ── wire format ──────────────────────────────────────────────────────────────


def test_budget_header_golden_and_roundtrip() -> None:
    line = build_aauth_budget_header(
        remaining=1568800, cost=221200, unit="USD", decimals=6
    )
    assert line == 'cost=221200, remaining=1568800, unit="USD", decimals=6'
    parsed = SFDictionary()
    parsed.parse(line.encode())  # a real RFC 9651 parser accepts what we emit
    assert int(str(parsed["remaining"].value)) == 1568800
    assert str(parsed["unit"].value) == "USD"


def test_budget_header_requires_unit_decimals_together() -> None:
    with pytest.raises(ValueError):
        build_aauth_budget_header(remaining=1, unit="USD", decimals=None)


def test_requirement_header_roundtrip() -> None:
    line = build_aauth_requirement(reason="insufficient-budget", resource_token="eyJx.y.z")
    assert line == 'requirement=auth-token;resource-token="eyJx.y.z";reason=insufficient-budget'
    parsed = SFDictionary()
    parsed.parse(line.encode())
    member = parsed["requirement"]
    assert str(member.params["resource-token"]) == "eyJx.y.z"


# ── meter semantics ──────────────────────────────────────────────────────────


def _claim(amount: int = 1000) -> BudgetClaim:
    return BudgetClaim(amount=amount, unit="KZT", decimals=2)


async def test_meter_reserve_commit_release_math() -> None:
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "jti-1", _claim(1000), time.time() + 60)
    res = await meter.reserve(KEY, "jti-1", 300)
    assert isinstance(res, Reservation)
    assert await meter.remaining(KEY, "jti-1") == 700  # 300 held
    assert await meter.commit(res, 120) == 880  # difference released
    assert await meter.consumed_records(KEY) == [{"jti": "jti-1", "consumed": 120}]


async def test_meter_caps_each_token_at_its_own_budget() -> None:
    """§Aggregation: the cap is per auth token. Two live envelopes of one
    person do NOT pool — a jti never draws on a sibling's grant, so the
    figure recorded against it can never exceed what its issuer granted."""
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "a", _claim(300), time.time() + 60)
    await meter.observe_grant(KEY, "b", _claim(300), time.time() + 60)
    refusal = await meter.reserve(KEY, "a", 500)  # would have fit a pooled purse
    assert isinstance(refusal, InsufficientBudget)
    assert refusal.remaining == 300 and not refusal.exhausted
    res = await meter.reserve(KEY, "a", 300)
    assert isinstance(res, Reservation)
    assert await meter.commit(res, 300) == 0          # a is spent…
    assert await meter.remaining(KEY, "b") == 300      # …b is untouched
    assert await meter.consumed_record(KEY, "a") == {"jti": "a", "consumed": 300}
    assert await meter.consumed_record(KEY, "b") is None
    # The ledger still aggregates per person for records/usage.
    assert await meter.consumed_records(KEY) == [{"jti": "a", "consumed": 300}]


async def test_meter_insufficient_vs_exhausted() -> None:
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "jti-1", _claim(200), time.time() + 60)
    refusal = await meter.reserve(KEY, "jti-1", 300)
    assert isinstance(refusal, InsufficientBudget)
    assert refusal.remaining == 200 and not refusal.exhausted
    res = await meter.reserve(KEY, "jti-1", 200)
    assert isinstance(res, Reservation)
    await meter.commit(res, 200)
    refusal = await meter.reserve(KEY, "jti-1", 1)
    assert isinstance(refusal, InsufficientBudget)
    assert refusal.exhausted


async def test_meter_unknown_jti_refused() -> None:
    meter = InMemoryMeter()
    refusal = await meter.reserve(KEY, "never-granted", 1)
    assert isinstance(refusal, InsufficientBudget)


async def test_meter_expired_grant_leaves_pool() -> None:
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "jti-1", _claim(1000), time.time() - 1)
    refusal = await meter.reserve(KEY, "jti-1", 1)
    assert isinstance(refusal, InsufficientBudget)


async def test_meter_unit_mismatch() -> None:
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "a", _claim(100), time.time() + 60)
    with pytest.raises(UnitMismatch):
        await meter.observe_grant(
            KEY, "b", BudgetClaim(amount=100, unit="USD", decimals=6), time.time() + 60
        )


async def test_meter_expired_reservation_counts_as_consumed() -> None:
    """Crash-safety is conservative: an unresolved hold becomes consumption."""
    meter = InMemoryMeter(reservation_ttl=0.0)
    await meter.observe_grant(KEY, "jti-1", _claim(1000), time.time() + 60)
    res = await meter.reserve(KEY, "jti-1", 400)
    assert isinstance(res, Reservation)
    # Handler "crashed": never commits. The next touch resolves it as consumed.
    assert await meter.remaining(KEY, "jti-1") == 600
    assert await meter.consumed_records(KEY) == [{"jti": "jti-1", "consumed": 400}]


async def test_meter_commit_clamps_to_reservation() -> None:
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "jti-1", _claim(1000), time.time() + 60)
    res = await meter.reserve(KEY, "jti-1", 300)
    assert isinstance(res, Reservation)
    assert await meter.commit(res, 999999) == 700  # clamped to the 300 hold


async def test_consumed_records_scoped_to_presenting_jkt() -> None:
    """Two agents of one person post to the same (iss, sub, aud) ledger, but
    each sees only ITS OWN consumption records — never its siblings' (privacy
    + no extra figures to infer the ceiling from)."""
    meter = InMemoryMeter()
    now = time.time()
    await meter.observe_grant(KEY, "jti-a", _claim(500), now + 60, jkt="jkt-agent-A")
    await meter.observe_grant(KEY, "jti-b", _claim(500), now + 60, jkt="jkt-agent-B")
    for jti, cost in (("jti-a", 100), ("jti-b", 250)):
        res = await meter.reserve(KEY, jti, cost)
        assert isinstance(res, Reservation)
        await meter.commit(res, cost)

    assert await meter.consumed_records(KEY, jkt="jkt-agent-A") == [
        {"jti": "jti-a", "consumed": 100}
    ]
    assert await meter.consumed_records(KEY, jkt="jkt-agent-B") == [
        {"jti": "jti-b", "consumed": 250}
    ]
    # Unscoped (PS-side / audit view) still returns the whole ledger.
    assert len(await meter.consumed_records(KEY)) == 2


async def test_refusal_records_scoped_to_presenter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The resource token embedded in a refusal carries ONE record — the
    presented token's (§The Consumption Record): sibling A's spend must not
    ride home with agent B, and B's other tokens don't either."""
    ps_priv, ps_jwk = _ps_pair()
    agent_a = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    agent_b = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    token_a = _auth_token(ps_priv, agent_a, amount=400, jti="at-A")
    token_b = _auth_token(ps_priv, agent_b, amount=400, jti="at-B")
    provider_records: list[Any] = []

    def provider(key: Any, records: Any) -> str:
        provider_records.append(records)
        return "resource.token"

    app = _app(_verifier(ps_jwk, monkeypatch), resource_token_provider=provider)

    # A spends 300 (price of /v1/search) of its 400; B spends 300 of its 400.
    assert (await _post(app, "/v1/search",
                        _signed_headers(agent_a, token_a, "/v1/search"))).status_code == 200
    assert (await _post(app, "/v1/search",
                        _signed_headers(agent_b, token_b, "/v1/search"))).status_code == 200
    # B asks again: 300 > 100 remaining on at-B → refusal carrying at-B's record only.
    r = await _post(app, "/v1/search", _signed_headers(agent_b, token_b, "/v1/search"))
    assert r.status_code == 401
    assert provider_records == [{"jti": "at-B", "consumed": 300}]
    assert r.headers["AAuth-Budget"] == 'remaining=100, required=300, unit="KZT", decimals=2'


async def test_meter_concurrent_reserves_never_oversell() -> None:
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "jti-1", _claim(1000), time.time() + 60)
    outcomes = await asyncio.gather(
        *(meter.reserve(KEY, "jti-1", 300) for _ in range(10))
    )
    granted = [o for o in outcomes if isinstance(o, Reservation)]
    assert len(granted) == 3  # 3×300 fits in 1000, a 4th would oversell
    assert sum(r.amount for r in granted) <= 1000


# ── FastAPI middleware end to end ────────────────────────────────────────────

PS_ISS = "https://ps.example"
RESOURCE = "https://api.example"


def _ps_pair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    priv = Ed25519PrivateKey.generate()
    jwk = {
        "kty": "OKP", "crv": "Ed25519", "kid": "ps-1", "alg": "Ed25519",
        "x": b64url(priv.public_key().public_bytes_raw()),
    }
    return priv, jwk


def _auth_token(ps_priv: Ed25519PrivateKey, agent: EgressSigner, *,
                amount: int, jti: str = "at-1", age: int = 0) -> str:
    """``age`` > 600 mints a token that has ALREADY expired (iat/exp shifted
    into the past) — genuine, possession-bound, not valid for access."""
    from regent_httpsig.verify import _register_fully_specified_algs

    _register_fully_specified_algs()  # PyJWT knows "Ed25519" only after this
    now = int(time.time()) - age
    return pyjwt.encode(
        {
            "iss": PS_ISS, "sub": "owner-1", "aud": RESOURCE, "jti": jti,
            "iat": now, "exp": now + 600, "dwk": "aauth-person.json",
            "budget": {"amount": amount, "unit": "KZT", "decimals": 2},
            "cnf": {"jwk": agent.public_jwk},
        },
        ps_priv, algorithm="Ed25519",
        headers={"typ": "aa-auth+jwt", "kid": "ps-1"},
    )


def _app(verifier: HttpsigVerifier, **mw_kwargs: Any) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        BudgetMiddleware,
        verifier=verifier,
        price_fn=lambda request: (
            300 if request.url.path in ("/v1/search", "/v1/stream") else None),
        **mw_kwargs,
    )

    @app.post("/v1/search")
    async def search(request: Request) -> dict[str, bool]:
        return {"ok": True}

    @app.post("/v1/cheap")
    async def cheap(request: Request) -> dict[str, bool]:
        request.state.budget_cost = 50  # handler knows the actual cost
        return {"ok": True}

    @app.post("/free")
    async def free() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/v1/stream")
    async def stream(request: Request):  # type: ignore[no-untyped-def]
        from starlette.responses import StreamingResponse

        async def gen():  # type: ignore[no-untyped-def]
            yield b"data: one\n\n"
            request.state.budget_cost = 120  # actual, learned mid-stream
            yield b"data: two\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    return app


def _mock_fetch(mapping: dict[str, dict[str, Any]]):  # type: ignore[no-untyped-def]
    async def fetch(url: str) -> dict[str, Any] | None:
        return mapping.get(url)
    return fetch


def _verifier(ps_jwk: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
              meter: InMemoryMeter | None = None) -> HttpsigVerifier:
    verifier = HttpsigVerifier(HttpsigConfig(
        resource_url=RESOURCE,
        trusted_ps={PS_ISS: f"{PS_ISS}/jwks.json"},
    ), is_revoked=meter.is_revoked if meter is not None else None)
    monkeypatch.setattr(
        verifier, "_fetch_json",
        _mock_fetch({f"{PS_ISS}/jwks.json": {"keys": [ps_jwk]}}),
    )
    return verifier


def _signed_headers(agent: EgressSigner, token: str, path: str) -> dict[str, str]:
    return agent.sign_aauth("POST", f"{RESOURCE}{path}", {"Host": "api.example"}, token=token)


async def _post(app: FastAPI, path: str, headers: dict[str, str]) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=RESOURCE) as client:
        return await client.post(path, headers=headers)


async def test_middleware_meters_and_answers_with_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    token = _auth_token(ps_priv, agent, amount=1000)
    app = _app(_verifier(ps_jwk, monkeypatch))

    r1 = await _post(app, "/v1/search", _signed_headers(agent, token, "/v1/search"))
    assert r1.status_code == 200
    assert r1.headers["AAuth-Budget"] == 'cost=300, remaining=700, unit="KZT", decimals=2'

    r2 = await _post(app, "/v1/search", _signed_headers(agent, token, "/v1/search"))
    assert r2.headers["AAuth-Budget"] == 'cost=300, remaining=400, unit="KZT", decimals=2'


async def test_middleware_refuses_when_insufficient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    token = _auth_token(ps_priv, agent, amount=500)
    provider_calls: list[Any] = []

    def provider(key: Any, records: Any) -> str:
        provider_calls.append((key, records))
        return "resource.token.here"

    app = _app(_verifier(ps_jwk, monkeypatch), resource_token_provider=provider)

    r1 = await _post(app, "/v1/search", _signed_headers(agent, token, "/v1/search"))
    assert r1.status_code == 200  # 500 - 300 = 200 left

    r2 = await _post(app, "/v1/search", _signed_headers(agent, token, "/v1/search"))
    assert r2.status_code == 401
    assert r2.json()["code"] == "INSUFFICIENT_BUDGET"
    assert (r2.headers["AAuth-Requirement"] ==
            'requirement=auth-token;resource-token="resource.token.here"'
            ";reason=insufficient-budget")
    assert (r2.headers["AAuth-Budget"] ==
            'remaining=200, required=300, unit="KZT", decimals=2')
    assert provider_calls and provider_calls[0][0] == (PS_ISS, "owner-1", RESOURCE)
    assert provider_calls[0][1] == {"jti": "at-1", "consumed": 300}  # one record (#120)


async def test_middleware_actual_cost_from_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    token = _auth_token(ps_priv, agent, amount=1000)
    app = FastAPI()
    app.add_middleware(
        BudgetMiddleware,
        verifier=_verifier(ps_jwk, monkeypatch),
        price_fn=lambda request: 300 if request.url.path == "/v1/cheap" else None,
    )

    @app.post("/v1/cheap")
    async def cheap(request: Request) -> dict[str, bool]:
        request.state.budget_cost = 50
        return {"ok": True}

    r = await _post(app, "/v1/cheap", _signed_headers(agent, token, "/v1/cheap"))
    assert r.headers["AAuth-Budget"] == 'cost=50, remaining=950, unit="KZT", decimals=2'


async def test_middleware_passthrough_without_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """require=False: unsigned / non-budget traffic falls through to the
    application's own (per-decision) authorization path untouched."""
    _, ps_jwk = _ps_pair()
    app = _app(_verifier(ps_jwk, monkeypatch))
    r = await _post(app, "/v1/search", {})
    assert r.status_code == 200
    assert "AAuth-Budget" not in r.headers


async def test_middleware_require_refuses_without_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, ps_jwk = _ps_pair()
    app = _app(_verifier(ps_jwk, monkeypatch), require=True)
    r = await _post(app, "/v1/search", {})
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_TOKEN_REQUIRED"
    assert r.headers["AAuth-Requirement"] == "requirement=auth-token;reason=insufficient-budget"


async def test_middleware_ignores_unpriced_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, ps_jwk = _ps_pair()
    app = _app(_verifier(ps_jwk, monkeypatch))
    r = await _post(app, "/free", {})
    assert r.status_code == 200
    assert "AAuth-Budget" not in r.headers


async def test_middleware_releases_on_error_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    token = _auth_token(ps_priv, agent, amount=1000)
    app = FastAPI()
    app.add_middleware(
        BudgetMiddleware,
        verifier=_verifier(ps_jwk, monkeypatch),
        price_fn=lambda request: 300,
    )

    @app.post("/boom")
    async def boom() -> Any:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail="bad input")

    r = await _post(app, "/boom", _signed_headers(agent, token, "/boom"))
    assert r.status_code == 422
    # Nothing served → envelope not charged.
    assert r.headers["AAuth-Budget"] == 'cost=0, remaining=1000, unit="KZT", decimals=2'


async def test_streaming_cost_omitted_reserved_math(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§cost-omitted: no trailer runtime — the header states `reserved` (and no
    `cost`), `remaining` is net of the hold, and the agent recovers the exact
    figure from the NEXT response: prev remaining + reserved − next remaining."""
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    token = _auth_token(ps_priv, agent, amount=1000)
    app = _app(_verifier(ps_jwk, monkeypatch))

    r1 = await _post(app, "/v1/stream", _signed_headers(agent, token, "/v1/stream"))
    assert r1.status_code == 200
    d1 = SFDictionary()
    d1.parse(r1.headers["AAuth-Budget"].encode())
    assert "cost" not in d1                      # omitted — no trailer runtime
    assert int(str(d1["reserved"].value)) == 300  # REQUIRED when cost omitted
    assert int(str(d1["remaining"].value)) == 700  # net of the hold
    assert r1.text.count("data:") == 2

    # Stream ended → the actual 120 was committed, 180 returned to the grant.
    r2 = await _post(app, "/v1/search", _signed_headers(agent, token, "/v1/search"))
    d2 = SFDictionary()
    d2.parse(r2.headers["AAuth-Budget"].encode())
    next_remaining = int(str(d2["remaining"].value)) + 300  # add back r2's own cost
    assert 700 + 300 - next_remaining == 120     # …prev + reserved − next = cost


async def test_expired_auth_token_is_expired_jwt_with_person_token_requirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Budgets editor's copy (06.10) "auth token expired" + -11 RS-51: the
    resource names the token expired (Signature-Error: expired_jwt) and asks
    for a person token. No resource token, no AAuth-Budget — the final record
    reaches the issuer through the usage endpoint, not on the challenge."""
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    live = _auth_token(ps_priv, agent, amount=1000, jti="at-9")
    provider_calls: list[Any] = []

    def provider(key: Any, record: Any) -> str:
        provider_calls.append((key, record))
        return "resource.token.final"

    meter = InMemoryMeter()
    app = _app(_verifier(ps_jwk, monkeypatch), meter=meter,
               resource_token_provider=provider)
    r = await _post(app, "/v1/search", _signed_headers(agent, live, "/v1/search"))
    assert r.status_code == 200

    stale = _auth_token(ps_priv, agent, amount=1000, jti="at-9", age=700)
    r = await _post(app, "/v1/search", _signed_headers(agent, stale, "/v1/search"))
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["error"] == "expired_jwt" and r.json()["code"] == "AUTH_TOKEN_EXPIRED"
    assert r.headers["Signature-Error"] == "error=expired_jwt"
    assert r.headers["AAuth-Requirement"] == "requirement=person-token"
    assert "AAuth-Budget" not in r.headers
    assert not provider_calls  # no resource token on a revoked/expired challenge
    # Nothing was served and nothing more was metered; the usage endpoint
    # still holds the token's figure for the PS.
    assert await meter.consumed_record(
        (PS_ISS, "owner-1", RESOURCE), "at-9") == {"jti": "at-9", "consumed": 300}
    assert await meter.usage_scope(PS_ISS, "owner-1") is not None


async def test_plain_verify_rejects_expired_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    stale = _auth_token(ps_priv, agent, amount=1000, jti="at-9", age=700)
    verifier = _verifier(ps_jwk, monkeypatch)
    headers = _signed_headers(agent, stale, "/v1/search")
    assert await verifier.verify("POST", f"{RESOURCE}/v1/search", headers) is None
    err = await verifier.verify_detailed("POST", f"{RESOURCE}/v1/search", headers)
    assert err.code == "expired_jwt" and err.token_typ == "aa-auth+jwt"


async def test_middleware_refuses_invalid_signature_with_signature_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """-11 §11.3.4: a signed request that does not verify is 401 + Signature-Error
    on a priced route — it is never treated as unsigned."""
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    token = _auth_token(ps_priv, agent, amount=1000)
    headers = _signed_headers(agent, token, "/v1/search")
    headers["Signature"] = headers["Signature"][:-6] + "AAAA=:"  # corrupt the signature
    r = await _post(_app(_verifier(ps_jwk, monkeypatch)), "/v1/search", headers)
    assert r.status_code == 401
    assert r.headers["Signature-Error"] == "error=invalid_signature"
    assert "AAuth-Requirement" not in r.headers


# ── revocation (base protocol §Token Revocation · budgets §Token Scope · AAuth #151) ──

async def test_meter_revoke_drains_before_final_record() -> None:
    """Revocation stops new spend at once; a request already in flight completes;
    the token's record is withheld until nothing is in flight, then it is final."""
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "jti-r", _claim(1000), time.time() + 600)
    inflight = await meter.reserve(KEY, "jti-r", 300)
    assert isinstance(inflight, Reservation)

    assert await meter.revoke(KEY[0], "jti-r") is True
    assert await meter.revoke(KEY[0], "jti-r") is True   # idempotent
    assert await meter.revoke(KEY[0], "never-seen") is False

    # No new spend, and the record is withheld while the in-flight request runs.
    outcome = await meter.reserve(KEY, "jti-r", 1)
    assert outcome == TokenRevoked(drained=False)
    assert await meter.consumed_record(KEY, "jti-r") is None
    # The in-flight request completes and is committed as usual.
    await meter.commit(inflight, 250)
    assert await meter.reserve(KEY, "jti-r", 1) == TokenRevoked(drained=True)
    assert await meter.consumed_record(KEY, "jti-r") == {"jti": "jti-r", "consumed": 250}
    assert await meter.revocation_state(KEY, "jti-r") == TokenRevoked(drained=True)
    assert await meter.revocation_state(KEY, "other") is None
    # A later observe_grant of the same jti does not resurrect the grant.
    await meter.observe_grant(KEY, "jti-r", _claim(1000), time.time() + 600)
    assert await meter.reserve(KEY, "jti-r", 1) == TokenRevoked(drained=True)


def _revocation_app(meter: InMemoryMeter, caller: Any, **kw: Any) -> FastAPI:
    from regent_httpsig import make_revocation_endpoint

    async def auth(request: Any) -> Any:
        return caller

    handler = make_revocation_endpoint(meter, authenticate_ps=auth, **kw)
    app = FastAPI()

    @app.post("/revoke")
    async def revoke(request: Request):  # type: ignore[no-untyped-def]
        return await handler(request)

    return app


async def test_revocation_endpoint_contract() -> None:
    """-11 §11.12.1–3: body {jti, exp}; iss from the verified caller; the pair
    is recorded whether or not known here; 200 empty always; problem+json
    errors invalid_request / unsupported_iss; a failed signature is 401 +
    Signature-Error."""
    from starlette.testclient import TestClient

    from regent_httpsig import VerificationError

    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "jti-e", _claim(500), time.time() + 600)
    exp = int(time.time()) + 600

    # Signature failed → 401 with the verifier's code; nothing revoked.
    r = TestClient(_revocation_app(meter, VerificationError("invalid_key", "nope"))).post(
        "/revoke", json={"jti": "jti-e", "exp": exp})
    assert r.status_code == 401 and r.headers["Signature-Error"] == "error=invalid_key"
    assert r.json()["error"] == "invalid_key"
    r = TestClient(_revocation_app(meter, None)).post("/revoke", json={"jti": "jti-e", "exp": exp})
    assert r.status_code == 401 and r.headers["Signature-Error"] == "error=invalid_signature"
    assert isinstance(await meter.reserve(KEY, "jti-e", 1), Reservation)

    client = TestClient(_revocation_app(meter, PS_ISS))
    assert client.post("/revoke", json={"jti": "jti-e"}).status_code == 400          # exp REQUIRED
    assert client.post("/revoke", json={"exp": exp}).status_code == 400              # jti REQUIRED
    assert client.post("/revoke", json={"jti": "jti-e", "exp": "soon"}).status_code == 400
    far = client.post("/revoke", json={"jti": "jti-e", "exp": exp + 7 * 86400})
    assert far.status_code == 400 and far.json()["error"] == "invalid_request"  # > 24h + skew
    assert client.post("/revoke", content=b"not json",
                       headers={"content-type": "application/json"}).status_code == 400
    assert isinstance(await meter.reserve(KEY, "jti-e", 1), Reservation)             # still live

    # An issuer this resource does not accept → unsupported_iss, nothing recorded.
    picky = TestClient(_revocation_app(meter, "https://stranger.example",
                                       accepted_issuers=lambda iss: iss == PS_ISS))
    r = picky.post("/revoke", json={"jti": "jti-e", "exp": exp})
    assert r.status_code == 403 and r.json()["error"] == "unsupported_iss"
    assert not await meter.is_revoked("https://stranger.example", "jti-e")

    # A pair never seen here is recorded all the same (statelessly verified
    # tokens): 200, empty — there is no "not found".
    r = client.post("/revoke", json={"jti": "ghost", "exp": exp})
    assert r.status_code == 200 and r.content == b""
    assert await meter.is_revoked(PS_ISS, "ghost")

    r = client.post("/revoke", json={"jti": "jti-e", "exp": exp})
    assert r.status_code == 200 and r.content == b""
    again = client.post("/revoke", json={"jti": "jti-e", "exp": exp})
    assert again.status_code == 200  # idempotent
    assert isinstance(await meter.reserve(KEY, "jti-e", 1), TokenRevoked)
    assert await meter.is_revoked(PS_ISS, "jti-e")


async def test_revocation_record_expires_with_the_token() -> None:
    meter = InMemoryMeter()
    await meter.record_revocation(PS_ISS, "short", time.time() - 120)  # exp already past + skew
    assert not await meter.is_revoked(PS_ISS, "short")
    await meter.record_revocation(PS_ISS, "live", time.time() + 120)
    assert await meter.is_revoked(PS_ISS, "live")


async def test_middleware_revoked_token_is_revoked_jwt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RS-43 / -11 §11.12.5: a revoked auth token is answered revoked_jwt plus
    requirement=person-token; no resource token rides on it (the PS would
    reject one naming a revoked token), and the final record is the usage
    endpoint's. Both wirings — verifier hooked to the meter, or the meter
    alone — give the same answer."""
    ps_priv, ps_jwk = _ps_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=PS_ISS)
    token = _auth_token(ps_priv, agent, amount=1000, jti="at-rv")
    calls: list[Any] = []

    def provider(key: Any, record: Any) -> str:
        calls.append(record)
        return "resource.token.rv"

    for wired in (True, False):
        meter = InMemoryMeter()
        verifier = _verifier(ps_jwk, monkeypatch, meter if wired else None)
        app = _app(verifier, meter=meter, resource_token_provider=provider)
        first = await _post(app, "/v1/search", _signed_headers(agent, token, "/v1/search"))
        assert first.status_code == 200

        await meter.record_revocation(PS_ISS, "at-rv", time.time() + 600)
        r = await _post(app, "/v1/search", _signed_headers(agent, token, "/v1/search"))
        assert r.status_code == 401, wired
        assert r.headers["Signature-Error"] == "error=revoked_jwt"
        assert r.headers["AAuth-Requirement"] == "requirement=person-token"
        assert r.json()["error"] == "revoked_jwt"
        assert r.json()["code"] == "AUTH_TOKEN_REVOKED"
        assert "AAuth-Budget" not in r.headers
        assert calls == []  # no resource token on the revoked challenge
        # The final record is still there for the usage endpoint / audit view.
        assert await meter.consumed_record(
            (PS_ISS, "owner-1", RESOURCE), "at-rv") == {"jti": "at-rv", "consumed": 300}
