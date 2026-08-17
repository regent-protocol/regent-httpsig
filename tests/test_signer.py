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
