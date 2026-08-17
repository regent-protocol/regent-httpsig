"""End-to-end HttpsigVerifier tests — directory fetching mocked, crypto real."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regent_httpsig import EgressSigner, HttpsigConfig, HttpsigVerifier, generate_seed
from regent_httpsig.jwk import b64url


def _mock_fetch(mapping: dict[str, dict[str, Any]]):
    async def fetch(url: str) -> dict[str, Any] | None:
        return mapping.get(url)

    return fetch


async def test_no_signature_header_is_none() -> None:
    verifier = HttpsigVerifier()
    assert await verifier.verify("GET", "https://api.example/x", {}) is None


async def test_wba_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """EgressSigner output verifies through the full verifier pipeline."""
    signer = EgressSigner(seed=generate_seed(), signature_agent="https://agent.example")
    url = "https://api.example/v1/orders?limit=5"
    headers = signer.sign("POST", url, {"Host": "api.example"})

    verifier = HttpsigVerifier(HttpsigConfig(trusted_agents=frozenset({"https://agent.example"})))
    monkeypatch.setattr(
        verifier, "_fetch_json",
        _mock_fetch({
            "https://agent.example/.well-known/http-message-signatures-directory":
                signer.directory(),
        }),
    )
    sig = await verifier.verify("POST", url, headers)
    assert sig is not None
    assert sig.scheme == "web-bot-auth"
    assert sig.agent == "https://agent.example"
    assert sig.keyid == signer.keyid
    assert sig.trusted is True
    assert sig.context()["signed_agent"] is True


async def test_wba_wrong_directory_key_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    signer = EgressSigner(seed=generate_seed(), signature_agent="https://agent.example")
    other = EgressSigner(seed=generate_seed(), signature_agent="https://agent.example")
    url = "https://api.example/v1/orders"
    headers = signer.sign("POST", url, {"Host": "api.example"})

    verifier = HttpsigVerifier()
    monkeypatch.setattr(
        verifier, "_fetch_json",
        _mock_fetch({
            "https://agent.example/.well-known/http-message-signatures-directory":
                other.directory(),  # directory publishes a DIFFERENT key
        }),
    )
    assert await verifier.verify("POST", url, headers) is None


async def test_aauth_identity_mode_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    """AAuth identity-based mode: agent_token verified against issuer JWKS, request
    signature verified against the token's cnf.jwk (proof of possession)."""
    issuer_priv = Ed25519PrivateKey.generate()
    issuer_jwk = {
        "kty": "OKP", "crv": "Ed25519", "kid": "iss-1", "alg": "EdDSA",
        "x": b64url(issuer_priv.public_key().public_bytes_raw()),
    }
    agent_signer = EgressSigner(seed=generate_seed(), signature_agent="https://issuer.example")

    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": "https://issuer.example", "sub": "agent-42",
            "iat": now, "exp": now + 600, "dwk": "aauth-agent.json",
            "cnf": {"jwk": agent_signer.public_jwk},
        },
        issuer_priv,
        algorithm="EdDSA",
        headers={"typ": "aa-agent+jwt", "kid": "iss-1"},
    )

    url = "https://api.example/v1/orders"
    headers = agent_signer.sign("POST", url, {"Host": "api.example"})
    headers["Signature-Key"] = f'sig1=jwt;jwt="{token}"'

    verifier = HttpsigVerifier()
    monkeypatch.setattr(
        verifier, "_fetch_json",
        _mock_fetch({
            "https://issuer.example/.well-known/aauth-agent.json":
                {"jwks_uri": "https://issuer.example/jwks.json"},
            "https://issuer.example/jwks.json": {"keys": [issuer_jwk]},
        }),
    )
    sig = await verifier.verify("POST", url, headers)
    assert sig is not None
    assert sig.scheme == "aauth"
    assert sig.agent == "https://issuer.example"
    assert sig.sub == "agent-42"
    assert sig.keyid == agent_signer.keyid


async def test_aauth_expired_token_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer_priv = Ed25519PrivateKey.generate()
    issuer_jwk = {
        "kty": "OKP", "crv": "Ed25519", "kid": "iss-1", "alg": "EdDSA",
        "x": b64url(issuer_priv.public_key().public_bytes_raw()),
    }
    agent_signer = EgressSigner(seed=generate_seed(), signature_agent="https://issuer.example")
    expired = int((datetime.now(UTC) - timedelta(hours=2)).timestamp())
    token = pyjwt.encode(
        {
            "iss": "https://issuer.example", "sub": "agent-42",
            "iat": expired, "exp": expired + 60, "dwk": "aauth-agent.json",
            "cnf": {"jwk": agent_signer.public_jwk},
        },
        issuer_priv, algorithm="EdDSA",
        headers={"typ": "aa-agent+jwt", "kid": "iss-1"},
    )
    url = "https://api.example/v1/orders"
    headers = agent_signer.sign("POST", url, {"Host": "api.example"})
    headers["Signature-Key"] = f'sig1=jwt;jwt="{token}"'

    verifier = HttpsigVerifier()
    monkeypatch.setattr(
        verifier, "_fetch_json",
        _mock_fetch({
            "https://issuer.example/.well-known/aauth-agent.json":
                {"jwks_uri": "https://issuer.example/jwks.json"},
            "https://issuer.example/jwks.json": {"keys": [issuer_jwk]},
        }),
    )
    assert await verifier.verify("POST", url, headers) is None


async def test_cache_is_per_instance() -> None:
    a, b = HttpsigVerifier(), HttpsigVerifier()
    a._cache_put("https://x.example/doc", {"keys": []}, ttl=60)
    hit_a, _ = a._cache_get("https://x.example/doc")
    hit_b, _ = b._cache_get("https://x.example/doc")
    assert hit_a is True and hit_b is False
