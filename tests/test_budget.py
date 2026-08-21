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
from regent_httpsig.budget import Reservation
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
    assert await meter.remaining(KEY) == 700  # 300 held
    assert await meter.commit(res, 120) == 880  # difference released
    assert await meter.consumed_records(KEY) == [{"jti": "jti-1", "consumed": 120}]


async def test_meter_pools_across_live_tokens() -> None:
    """The draft's (iss, sub, aud) aggregation: two live envelopes pool."""
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "a", _claim(300), time.time() + 60)
    await meter.observe_grant(KEY, "b", _claim(300), time.time() + 60)
    res = await meter.reserve(KEY, "a", 500)  # more than either grant alone
    assert isinstance(res, Reservation)
    assert await meter.commit(res, 500) == 100


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
    assert await meter.remaining(KEY) == 600
    assert await meter.consumed_records(KEY) == [{"jti": "jti-1", "consumed": 400}]


async def test_meter_commit_clamps_to_reservation() -> None:
    meter = InMemoryMeter()
    await meter.observe_grant(KEY, "jti-1", _claim(1000), time.time() + 60)
    res = await meter.reserve(KEY, "jti-1", 300)
    assert isinstance(res, Reservation)
    assert await meter.commit(res, 999999) == 700  # clamped to the 300 hold


async def test_consumed_records_scoped_to_presenting_jkt() -> None:
    """Two agents of one principal share the (iss, sub, aud) pool, but each
    sees only ITS OWN consumption records — never its siblings' (privacy +
    no extra figures to infer the ceiling from)."""
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
    # Unscoped (PS-side / audit view) still returns the whole pool.
    assert len(await meter.consumed_records(KEY)) == 2


async def test_refusal_records_scoped_to_presenter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The resource token embedded in a refusal carries only the presenting
    agent's records: sibling B's spend must not ride home with agent A."""
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

    # A spends 300 (price of /v1/search), B spends 300 — pool now at 200.
    assert (await _post(app, "/v1/search",
                        _signed_headers(agent_a, token_a, "/v1/search"))).status_code == 200
    assert (await _post(app, "/v1/search",
                        _signed_headers(agent_b, token_b, "/v1/search"))).status_code == 200
    # B asks again: 300 > 200 remaining → refusal with records — B's only.
    r = await _post(app, "/v1/search", _signed_headers(agent_b, token_b, "/v1/search"))
    assert r.status_code == 401
    assert provider_records == [[{"jti": "at-B", "consumed": 300}]]


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
                amount: int, jti: str = "at-1") -> str:
    from regent_httpsig.verify import _register_fully_specified_algs

    _register_fully_specified_algs()  # PyJWT knows "Ed25519" only after this
    now = int(time.time())
    return pyjwt.encode(
        {
            "iss": PS_ISS, "sub": "owner-1", "aud": RESOURCE, "jti": jti,
            "iat": now, "exp": now + 600,
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
        price_fn=lambda request: 300 if request.url.path == "/v1/search" else None,
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

    return app


def _mock_fetch(mapping: dict[str, dict[str, Any]]):  # type: ignore[no-untyped-def]
    async def fetch(url: str) -> dict[str, Any] | None:
        return mapping.get(url)
    return fetch


def _verifier(ps_jwk: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> HttpsigVerifier:
    verifier = HttpsigVerifier(HttpsigConfig(
        resource_url=RESOURCE,
        trusted_ps={PS_ISS: f"{PS_ISS}/jwks.json"},
    ))
    monkeypatch.setattr(
        verifier, "_fetch_json",
        _mock_fetch({f"{PS_ISS}/jwks.json": {"keys": [ps_jwk]}}),
    )
    return verifier


def _signed_headers(agent: EgressSigner, token: str, path: str) -> dict[str, str]:
    headers = agent.sign("POST", f"{RESOURCE}{path}", {"Host": "api.example"})
    headers["Signature-Key"] = f'sig1=jwt;jwt="{token}"'
    return headers


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
    assert r2.headers["AAuth-Budget"] == 'remaining=200, unit="KZT", decimals=2'
    assert provider_calls and provider_calls[0][0] == (PS_ISS, "owner-1", RESOURCE)
    assert provider_calls[0][1] == [{"jti": "at-1", "consumed": 300}]


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
