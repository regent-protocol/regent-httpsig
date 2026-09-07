"""Generate the AAuth Budgets test vectors (vectors/*.json).

Deterministic by construction: fixed seeds, fixed timestamps. Re-run after any
serialization change; the test suite pins the same bytes.

    .venv/bin/python vectors/generate.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from regent_httpsig import ResponseSigner, build_aauth_budget_header  # noqa: E402
from regent_httpsig.jwk import b64url  # noqa: E402
from regent_httpsig.sfv import build_aauth_requirement  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent


def headers() -> dict:
    """AAuth-Budget / AAuth-Requirement serializations. The field is an
    RFC 9651 Dictionary — members are COMMA-separated (the draft's prose);
    parameters inside AAuth-Requirement members use semicolons."""
    cases = [
        {
            "name": "success-with-cost",
            "input": {"remaining": 1568800, "cost": 221200,
                      "unit": "USD", "decimals": 6},
            "expected": build_aauth_budget_header(
                remaining=1568800, cost=221200, unit="USD", decimals=6),
        },
        {
            "name": "refusal-insufficient-with-required",
            "note": "`required` rides only on insufficient-budget refusals: "
                    "what THIS request needed, so the retry is a calculation.",
            "input": {"remaining": 300, "required": 750,
                      "unit": "USD", "decimals": 6},
            "expected": build_aauth_budget_header(
                remaining=300, required=750, unit="USD", decimals=6),
        },
        {
            "name": "streaming-cost-omitted",
            "note": "No-trailer runtime: cost omitted, reserved REQUIRED, "
                    "remaining already net of the hold. The agent recovers "
                    "cost = prev remaining + reserved - next remaining.",
            "input": {"remaining": 1568800, "reserved": 431200,
                      "unit": "USD", "decimals": 6},
            "expected": build_aauth_budget_header(
                remaining=1568800, reserved=431200, unit="USD", decimals=6),
        },
        {
            "name": "exhaustion-zero",
            "input": {"remaining": 0, "unit": "USD", "decimals": 6},
            "expected": build_aauth_budget_header(
                remaining=0, unit="USD", decimals=6),
        },
    ]
    requirement = [
        {
            "name": "refusal-with-resource-token",
            "input": {"reason": "budget-exhausted",
                      "resource_token": "eyJexample"},
            "expected": build_aauth_requirement(
                reason="budget-exhausted", resource_token="eyJexample"),
        },
    ]
    return {"aauth_budget": cases, "aauth_requirement": requirement}


def budget_claim() -> dict:
    """The one budget-object shape, appearing unchanged in every position."""
    return {
        "shape": {"amount": 5000000, "unit": "USD", "decimals": 6},
        "notes": [
            "amount: non-negative integer, bounded by the 15-digit SF limit",
            "decimals is NOT constrained to the ISO 4217 minor unit",
            "all three members REQUIRED wherever `budget` appears",
        ],
    }


def consumption_records() -> dict:
    return {
        "budget_consumed": {"jti": "at-2", "consumed": 431200},
        "notes": [
            "ONE record — the presented token's — two members and no more; "
            "the issuer joins the rest from its ledger (#120)",
            "consumed is that token's total as of the resource token's iat",
            "final vs snapshot is decided by the issuer: resource token iat >= "
            "auth token exp is the final figure and releases the remainder; "
            "a record on a live token releases nothing",
            "the spend under a person's other tokens is the usage endpoint's "
            "to report — never carried by a sibling",
        ],
    }


def signed_usage_response() -> dict:
    """A fully worked signed usage response with a FIXED key and timestamp —
    verify it independently: Ed25519 over the base string below."""
    seed = b64url(bytes(range(32)))
    signer = ResponseSigner(seed=seed, jwks_url="https://api.example/jwks.json")
    body_doc = {
        "as_of": 1756500000,
        "aud": "https://ps.example",
        "unit": "USD",
        "decimals": 6,
        "sub": "8f14e45fceea167a5a36dedd4bea2543",
        "usage": {"day": 1243180, "all_time": 61438050},
        "jkts": {"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs": 38215600},
    }
    body = json.dumps(body_doc, separators=(",", ":")).encode()
    headers = signer.sign(status=200, content_type="application/json",
                          body=body, authority="api.example", path="/usage",
                          created=1756500001)
    digest = "sha-256=:" + base64.b64encode(
        hashlib.sha256(body).digest()).decode() + ":"
    base = "\n".join([
        '"@status": 200',
        '"content-type": application/json',
        f'"content-digest": {digest}',
        '"@authority";req: api.example',
        '"@path";req: /usage',
        '"@signature-params": ' + headers["Signature-Input"].split("=", 1)[1],
    ])
    return {
        "signing_key": {"seed_b64url": seed, "public_jwk": signer.public_jwk,
                        "keyid_rfc7638": signer.keyid},
        "request_context": {"authority": "api.example", "path": "/usage"},
        "body": body_doc,
        "body_canonical_json": body.decode(),
        "signature_base": base,
        "response_headers": headers,
    }


def main() -> None:
    vectors = {
        "source": "regent-httpsig, first implementation of "
                  "draft-hardt-aauth-budgets (editor's copy, 2026-08-20)",
        "headers": headers(),
        "budget_claim": budget_claim(),
        "consumption_records": consumption_records(),
        "signed_usage_response": signed_usage_response(),
    }
    out = OUT / "aauth-budgets-vectors.json"
    out.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
