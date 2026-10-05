"""EgressSigner unit tests — key handling, directory shape, header emission."""

from __future__ import annotations

import pytest

from regent_httpsig import EgressSigner, generate_seed
from regent_httpsig.jwk import jwk_thumbprint


def test_bad_seed_raises_at_construction() -> None:
    with pytest.raises(ValueError):
        EgressSigner(seed="dG9vc2hvcnQ", signature_agent="https://a.example")


def test_directory_shape_and_stable_keyid() -> None:
    seed = generate_seed()
    s1 = EgressSigner(seed=seed, signature_agent="https://a.example")
    s2 = EgressSigner(seed=seed, signature_agent="https://a.example")
    assert s1.keyid == s2.keyid  # same seed → same key → same thumbprint
    doc = s1.directory()
    key = doc["keys"][0]
    assert key["kty"] == "OKP" and key["crv"] == "Ed25519"
    assert key["kid"] == s1.keyid == jwk_thumbprint(s1.public_jwk)
    assert key["use"] == "sig" and key["alg"] == "EdDSA"


def test_sign_emits_wba_headers_and_preserves_input() -> None:
    signer = EgressSigner(seed=generate_seed(), signature_agent="https://a.example")
    headers = signer.sign(
        "post", "https://api.example/v1/x", {"Content-Type": "application/json"}
    )
    assert headers["Signature-Agent"] == '"https://a.example"'  # legacy sf-string
    assert "Signature-Input" in headers and "Signature" in headers
    assert 'tag="web-bot-auth"' in headers["Signature-Input"]
    assert headers["Content-Type"] == "application/json"  # original headers intact


def test_public_jwk_is_fully_specified_and_directory_is_wba() -> None:
    """AAuth -11 wants `alg: Ed25519` on cnf.jwk (RFC 9864); the Web Bot Auth
    directory keeps the profile's own `EdDSA` — two profiles, two documents."""
    signer = EgressSigner(seed=generate_seed(), signature_agent="https://a.example")
    assert signer.public_jwk["alg"] == "Ed25519"
    assert signer.directory()["keys"][0]["alg"] == "EdDSA"
    assert jwk_thumbprint(signer.public_jwk) == signer.keyid  # alg never enters the thumbprint


def test_sign_aauth_shape() -> None:
    signer = EgressSigner(seed=generate_seed(), signature_agent="https://a.example")
    headers = signer.sign_aauth("POST", "https://api.example/v1/x", token="a.b.c", body=b"{}")
    assert headers["Signature-Key"] == 'sig=jwt;jwt="a.b.c"'
    assert headers["Content-Digest"].startswith("sha-256=:")
    assert headers["Content-Type"] == "application/json"
    assert headers["Signature-Input"].startswith(
        'sig=("@method" "@authority" "@path" "signature-key" "content-digest" '
        '"content-type");created=')
    assert "keyid" not in headers["Signature-Input"] and "alg=" not in headers["Signature-Input"]

