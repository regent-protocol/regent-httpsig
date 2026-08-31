"""AAuth Budgets §Usage Counters + the Aug-20 additions (required, streaming).

Every rule these tests pin comes with the draft's reasoning in the test name
or a comment — they double as our conformance notes.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from regent_httpsig import (
    BudgetClaim,
    InMemoryMeter,
    ResponseSigner,
    UsageQueryError,
    build_aauth_budget_header,
    build_usage_response,
    make_usage_endpoint,
    parse_usage_request,
)
from regent_httpsig.budget import MeterKey
from regent_httpsig.jwk import b64url, b64url_decode
from regent_httpsig.sfv import SFDictionary

KEY: MeterKey = ("https://ps.example", "sub-1", "https://api.example")
CLAIM = BudgetClaim.parse({"budget": {"amount": 10_000, "unit": "USD", "decimals": 2}})
JKT_A = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
JKT_B = "0ZcOCORZNYy-DWpqq30BbmLzO1Yw3ZQhIgnHZQKxNVE"


async def _spend(meter: InMemoryMeter, jti: str, jkt: str, cost: int) -> None:
    await meter.observe_grant(KEY, jti, CLAIM, time.time() + 3600, jkt=jkt)
    res = await meter.reserve(KEY, jti, cost)
    await meter.commit(res, cost)


# ── required member (header) ─────────────────────────────────────────────────

def test_header_golden_with_required() -> None:
    out = build_aauth_budget_header(remaining=300, required=750,
                                    unit="USD", decimals=2)
    assert out == 'remaining=300, required=750, unit="USD", decimals=2'
    parsed = SFDictionary()
    parsed.parse(out.encode())
    assert int(parsed["required"].value) == 750  # real SFV parser round-trip


def test_header_member_order_is_the_drafts() -> None:
    out = build_aauth_budget_header(remaining=1, cost=2, reserved=3, required=4)
    assert out == "cost=2, remaining=1, reserved=3, required=4"


# ── usage request validation (§usage-request) ────────────────────────────────

def test_query_two_scope_keys_is_an_error() -> None:
    with pytest.raises(UsageQueryError):
        parse_usage_request({"sub": "s", "tenant": "t"})


def test_query_neither_scope_nor_jkts_is_an_error() -> None:
    with pytest.raises(UsageQueryError):
        parse_usage_request({})


def test_query_scope_and_jkts_may_both_appear() -> None:
    scope_key, scope_value, jkts = parse_usage_request(
        {"sub": "s", "jkts": [JKT_A]})
    assert (scope_key, scope_value, jkts) == ("sub", "s", [JKT_A])


# ── calendar counters + per-key figures ──────────────────────────────────────

@pytest.mark.asyncio
async def test_scope_counters_accumulate_and_echo() -> None:
    meter = InMemoryMeter()
    await _spend(meter, "jti-1", JKT_A, 400)
    await _spend(meter, "jti-2", JKT_B, 100)
    doc = await build_usage_response(
        meter, iss=KEY[0], aud=KEY[0], unit="USD", decimals=2,
        scope_key="sub", scope_value="sub-1", jkts=[])
    assert doc["sub"] == "sub-1"
    assert doc["usage"]["all_time"] == 500
    assert doc["usage"]["day"] == 500  # committed just now, same UTC day
    assert doc["unit"] == "USD" and doc["decimals"] == 2 and doc["aud"] == KEY[0]


@pytest.mark.asyncio
async def test_unknown_scope_value_omits_usage_not_zero() -> None:
    """"Never seen" must be indistinguishable from "nothing consumed" — a
    query cannot be used to discover whether a person holds an account."""
    meter = InMemoryMeter()
    doc = await build_usage_response(
        meter, iss=KEY[0], aud=KEY[0], unit="USD", decimals=2,
        scope_key="sub", scope_value="nobody", jkts=[])
    assert "usage" not in doc and doc["sub"] == "nobody"


@pytest.mark.asyncio
async def test_per_key_totals_and_unknown_key_omitted() -> None:
    """Unknown/pruned thumbprints are OMITTED, never zero: a present zero
    would be a wrong answer to an allocation decision."""
    meter = InMemoryMeter()
    await _spend(meter, "jti-1", JKT_A, 400)
    doc = await build_usage_response(
        meter, iss=KEY[0], aud=KEY[0], unit="USD", decimals=2,
        scope_key=None, scope_value=None, jkts=[JKT_A, JKT_B])
    assert doc["jkts"] == {JKT_A: 400}


@pytest.mark.asyncio
async def test_per_key_pruned_on_idle_not_age() -> None:
    meter = InMemoryMeter(usage_key_retention=0.05)
    await _spend(meter, "jti-1", JKT_A, 100)
    await asyncio.sleep(0.08)
    assert await meter.usage_keys(KEY[0], [JKT_A]) == {}


@pytest.mark.asyncio
async def test_usage_scoped_to_the_calling_ps() -> None:
    """The resource only answers for tokens the calling PS issued — figures
    are keyed by iss, so another PS simply holds no records."""
    meter = InMemoryMeter()
    await _spend(meter, "jti-1", JKT_A, 400)
    assert await meter.usage_keys("https://other-ps.example", [JKT_A]) == {}
    assert await meter.usage_scope("https://other-ps.example", "sub-1") is None


@pytest.mark.asyncio
async def test_expired_reservation_reaches_usage_counters() -> None:
    """The conservative rule (unresolved reservation = consumed) must show up
    in usage too, or the PS's pull path would under-count a crashed handler."""
    meter = InMemoryMeter(reservation_ttl=0.01)
    await meter.observe_grant(KEY, "jti-1", CLAIM, time.time() + 3600, jkt=JKT_A)
    await meter.reserve(KEY, "jti-1", 700)
    await asyncio.sleep(0.02)
    await meter.remaining(KEY)  # triggers the purge
    assert (await meter.usage_keys(KEY[0], [JKT_A]))[JKT_A] == 700


# ── the endpoint handler ─────────────────────────────────────────────────────

def _app(meter: InMemoryMeter, iss: str | None,
         signer: ResponseSigner | None = None) -> FastAPI:
    async def auth(_request: Request) -> str | None:
        return iss

    handler = make_usage_endpoint(meter, authenticate_ps=auth,
                                  unit="USD", decimals=2, signer=signer)
    app = FastAPI()

    @app.post("/usage")
    async def usage(request: Request):  # type: ignore[no-untyped-def]
        return await handler(request)

    return app


def test_endpoint_refuses_unauthenticated_ps() -> None:
    client = TestClient(_app(InMemoryMeter(), iss=None))
    assert client.post("/usage", json={"sub": "s"}).status_code == 401


def test_endpoint_rejects_bad_query() -> None:
    client = TestClient(_app(InMemoryMeter(), iss=KEY[0]))
    r = client.post("/usage", json={"sub": "a", "tenant": "b"})
    assert r.status_code == 400 and r.json()["code"] == "INVALID_USAGE_QUERY"


@pytest.mark.asyncio
async def test_endpoint_end_to_end_signed() -> None:
    meter = InMemoryMeter()
    await _spend(meter, "jti-1", JKT_A, 400)
    seed = b64url(b"\x07" * 32)
    signer = ResponseSigner(seed=seed, jwks_url="https://api.example/jwks.json")
    client = TestClient(_app(meter, iss=KEY[0], signer=signer))
    r = client.post("/usage", json={"sub": "sub-1", "jkts": [JKT_A, JKT_B]})
    assert r.status_code == 200
    doc = r.json()
    assert doc["usage"]["all_time"] == 400 and doc["jkts"] == {JKT_A: 400}

    # The signature covers @status/content-type/content-digest + the request's
    # @authority/@path (req-bound) — verify it from scratch with the public key.
    digest = "sha-256=:" + base64.b64encode(
        __import__("hashlib").sha256(r.content).digest()).decode() + ":"
    assert r.headers["content-digest"] == digest
    inner = r.headers["signature-input"].split("=", 1)[1]
    base = "\n".join([
        '"@status": 200',
        '"content-type": application/json',
        f'"content-digest": {digest}',
        '"@authority";req: testserver',
        '"@path";req: /usage',
        f'"@signature-params": {inner}',
    ])
    sig_b64 = r.headers["signature"].split("=", 1)[1].strip(":")
    pub = Ed25519PublicKey.from_public_bytes(
        b64url_decode(signer.public_jwk["x"]))
    pub.verify(base64.b64decode(sig_b64), base.encode())  # raises on mismatch
    assert 'jwks_uri="https://api.example/jwks.json"' in r.headers["signature-key"]


def test_validate_budget_grant_enforces_declared_units() -> None:
    units = [{"unit": "USD", "decimals": 6, "max": 10_000_000}]
    from regent_httpsig import validate_budget_grant
    validate_budget_grant("USD", 6, units)  # declared → fine
    with pytest.raises(ValueError):
        validate_budget_grant("USD", 2, units)  # the thousandfold error
    with pytest.raises(ValueError):
        validate_budget_grant("EUR", 2, units)  # undeclared unit


def test_vectors_are_current() -> None:
    """The published vectors must match what the code emits today."""
    import pathlib
    import subprocess
    import sys
    root = pathlib.Path(__file__).resolve().parent.parent
    before = (root / "vectors" / "aauth-budgets-vectors.json").read_text()
    subprocess.run([sys.executable, str(root / "vectors" / "generate.py")],
                   check=True, capture_output=True)
    after = (root / "vectors" / "aauth-budgets-vectors.json").read_text()
    assert before == after
