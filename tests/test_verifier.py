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


async def test_aauth_without_keyid_param(monkeypatch: pytest.MonkeyPatch) -> None:
    """RFC 9421 makes keyid OPTIONAL; on the AAuth path the key comes from the
    token's cnf.jwk, so conforming signers (e.g. christian-posta/aauth-signing)
    omit it. Pins the interop shape: signature built WITHOUT keyid must verify."""
    import base64

    agent_priv = Ed25519PrivateKey.generate()
    agent_jwk = {"kty": "OKP", "crv": "Ed25519",
                 "x": b64url(agent_priv.public_key().public_bytes_raw())}
    issuer_priv = Ed25519PrivateKey.generate()
    issuer_jwk = {
        "kty": "OKP", "crv": "Ed25519", "kid": "iss-1", "alg": "EdDSA",
        "x": b64url(issuer_priv.public_key().public_bytes_raw()),
    }
    now = int(time.time())
    token = pyjwt.encode(
        {"iss": "https://issuer.example", "sub": "agent-42", "iat": now,
         "exp": now + 600, "dwk": "aauth-agent.json", "cnf": {"jwk": agent_jwk}},
        issuer_priv, algorithm="EdDSA",
        headers={"typ": "aa-agent+jwt", "kid": "iss-1"},
    )

    # Build the signature exactly the way aauth-signing does: covered components
    # @method/@authority/@path/signature-key, created only — NO keyid param.
    sig_key_header = f'sig=jwt;jwt="{token}"'
    params = ('("@method" "@authority" "@path" "signature-key")'
              f";created={now}")
    base = "\n".join([
        '"@method": POST',
        '"@authority": api.example',
        '"@path": /v1/orders',
        f'"signature-key": {sig_key_header}',
        f'"@signature-params": {params}',
    ]).encode()
    signature = base64.b64encode(agent_priv.sign(base)).decode()
    headers = {
        "Host": "api.example",
        "Signature-Key": sig_key_header,
        "Signature-Input": f"sig={params}",
        "Signature": f"sig=:{signature}:",
    }

    verifier = HttpsigVerifier()
    monkeypatch.setattr(
        verifier, "_fetch_json",
        _mock_fetch({
            "https://issuer.example/.well-known/aauth-agent.json":
                {"jwks_uri": "https://issuer.example/jwks.json"},
            "https://issuer.example/jwks.json": {"keys": [issuer_jwk]},
        }),
    )
    sig = await verifier.verify("POST", "https://api.example/v1/orders", headers)
    assert sig is not None and sig.scheme == "aauth" and sig.sub == "agent-42"


def _issuer_pair(kid: str = "iss-1", alg: str = "EdDSA"):
    priv = Ed25519PrivateKey.generate()
    jwk = {"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": alg,
           "x": b64url(priv.public_key().public_bytes_raw())}
    return priv, jwk


def _mint(issuer_priv, *, typ: str, alg: str, claims: dict) -> str:
    from regent_httpsig.verify import _register_fully_specified_algs

    _register_fully_specified_algs()
    return pyjwt.encode(claims, issuer_priv, algorithm=alg,
                        headers={"typ": typ, "kid": "iss-1"})


class TestFullySpecifiedAlgs:
    """AAuth -11 / RFC 9864: Ed25519 accepted; polymorphic EdDSA gated by config."""

    async def _roundtrip(self, alg: str, config: HttpsigConfig,
                         monkeypatch: pytest.MonkeyPatch):
        issuer_priv, issuer_jwk = _issuer_pair(alg=alg)
        agent = EgressSigner(seed=generate_seed(), signature_agent="https://issuer.example")
        now = int(time.time())
        token = _mint(issuer_priv, typ="aa-agent+jwt", alg=alg, claims={
            "iss": "https://issuer.example", "sub": "a-1", "iat": now, "exp": now + 600,
            "dwk": "aauth-agent.json",
            "cnf": {"jwk": {**agent.public_jwk, "alg": "Ed25519"}},
        })
        url = "https://api.example/v1/x"
        headers = agent.sign("POST", url, {"Host": "api.example"})
        headers["Signature-Key"] = f'sig1=jwt;jwt="{token}"'
        verifier = HttpsigVerifier(config)
        monkeypatch.setattr(verifier, "_fetch_json", _mock_fetch({
            "https://issuer.example/.well-known/aauth-agent.json":
                {"jwks_uri": "https://issuer.example/j"},
            "https://issuer.example/j": {"keys": [issuer_jwk]},
        }))
        return await verifier.verify("POST", url, headers)

    async def test_ed25519_fully_specified_verifies(self, monkeypatch) -> None:
        sig = await self._roundtrip("Ed25519", HttpsigConfig(), monkeypatch)
        assert sig is not None and sig.scheme == "aauth"

    async def test_eddsa_accepted_in_transition_mode(self, monkeypatch) -> None:
        sig = await self._roundtrip("EdDSA", HttpsigConfig(), monkeypatch)
        assert sig is not None  # default: -10 ecosystem still accepted

    async def test_eddsa_rejected_in_strict_mode(self, monkeypatch) -> None:
        strict = HttpsigConfig(require_fully_specified_algs=True)
        assert await self._roundtrip("EdDSA", strict, monkeypatch) is None

    async def test_ed25519_verifies_in_strict_mode(self, monkeypatch) -> None:
        strict = HttpsigConfig(require_fully_specified_algs=True)
        sig = await self._roundtrip("Ed25519", strict, monkeypatch)
        assert sig is not None


class TestPersonTokens:
    """AAuth -11 person tokens: PS-issued, per-resource aud, cnf-bound, ≤1h."""

    def _headers(self, *, aud: str, lifetime: int = 600):
        ps_priv, ps_jwk = _issuer_pair()
        agent = EgressSigner(seed=generate_seed(), signature_agent="https://ps.example")
        now = int(time.time())
        token = _mint(ps_priv, typ="aa-person+jwt", alg="Ed25519", claims={
            "iss": "https://ps.example", "sub": "directed-sub-1", "aud": aud,
            "iat": now, "exp": now + lifetime, "dwk": "aauth-person.json",
            "jti": "pt-1", "cnf": {"jwk": {**agent.public_jwk, "alg": "Ed25519"}},
        })
        url = "https://api.example/v1/x"
        headers = agent.sign("POST", url, {"Host": "api.example"})
        headers["Signature-Key"] = f'sig1=jwt;jwt="{token}"'
        return url, headers, ps_jwk

    def _verifier(self, ps_jwk, monkeypatch, **cfg):
        verifier = HttpsigVerifier(HttpsigConfig(**cfg))
        monkeypatch.setattr(verifier, "_fetch_json", _mock_fetch({
            "https://ps.example/.well-known/aauth-person.json":
                {"jwks_uri": "https://ps.example/j"},
            "https://ps.example/j": {"keys": [ps_jwk]},
        }))
        return verifier

    async def test_person_token_roundtrip(self, monkeypatch) -> None:
        url, headers, ps_jwk = self._headers(aud="https://api.example")
        v = self._verifier(ps_jwk, monkeypatch, resource_url="https://api.example")
        sig = await v.verify("POST", url, headers)
        assert sig is not None
        assert sig.scheme == "aauth-person"
        assert sig.agent == "https://ps.example"  # the PS, not the agent operator
        assert sig.sub == "directed-sub-1"
        assert sig.claims.get("jti") == "pt-1"

    async def test_person_token_wrong_audience_rejected(self, monkeypatch) -> None:
        url, headers, ps_jwk = self._headers(aud="https://OTHER.example")
        v = self._verifier(ps_jwk, monkeypatch, resource_url="https://api.example")
        assert await v.verify("POST", url, headers) is None

    async def test_person_token_disabled_without_resource_url(self, monkeypatch) -> None:
        url, headers, ps_jwk = self._headers(aud="https://api.example")
        v = self._verifier(ps_jwk, monkeypatch)  # no resource_url → path disabled
        assert await v.verify("POST", url, headers) is None

    async def test_person_token_overlong_lifetime_rejected(self, monkeypatch) -> None:
        url, headers, ps_jwk = self._headers(aud="https://api.example", lifetime=7200)
        v = self._verifier(ps_jwk, monkeypatch, resource_url="https://api.example")
        assert await v.verify("POST", url, headers) is None


async def test_cache_is_per_instance() -> None:
    a, b = HttpsigVerifier(), HttpsigVerifier()
    a._cache_put("https://x.example/doc", {"keys": []}, ttl=60)
    hit_a, _ = a._cache_get("https://x.example/doc")
    hit_b, _ = b._cache_get("https://x.example/doc")
    assert hit_a is True and hit_b is False
