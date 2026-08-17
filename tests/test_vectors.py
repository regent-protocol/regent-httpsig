"""RFC 9421 / Web Bot Auth verification against the official test vectors.

- RFC 9421 Appendix B.2.6 (Ed25519, deterministic — must verify byte-exactly).
- Web Bot Auth architecture draft -05 Appendix A.2.2: the CURRENT sf-dictionary
  ``Signature-Agent`` form covered with ``;key=`` — exercises our
  DictKeyComponentResolver (the upstream library cannot resolve ``;key=``).
- A.2.3 legacy sf-string form (what OpenAI sends today) — signature is valid but
  expired, so we verify with expiry checks disabled to pin the canonicalization.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from http_message_signatures import HTTPMessageVerifier, InvalidSignature, algorithms

from regent_httpsig.jwk import b64url, jwk_thumbprint, load_ed25519_jwk
from regent_httpsig.sfv import (
    DictKeyComponentResolver,
    Message,
    StaticKeyResolver,
    parse_signature_agent,
)

# RFC 9421 B.1.4 test-key-ed25519 (public half, JWK form).
RFC_ED25519_JWK = {"kty": "OKP", "crv": "Ed25519",
                   "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
# The Web Bot Auth drafts reuse the same key; keyid = its RFC 8037 A.3 thumbprint.
WBA_KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"


def _verifier(keys: dict) -> HTTPMessageVerifier:
    return HTTPMessageVerifier(
        signature_algorithm=algorithms.ED25519,
        key_resolver=StaticKeyResolver(keys),
        component_resolver_class=DictKeyComponentResolver,
    )


class NoExpiryVerifier(HTTPMessageVerifier):
    """Vector-pinning only: the drafts' example timestamps are fixed in the past."""

    def validate_created_and_expires(self, sig_input, max_age=None):  # type: ignore[no-untyped-def]
        return None


def test_thumbprint_matches_wba_keyid() -> None:
    assert jwk_thumbprint(RFC_ED25519_JWK) == WBA_KEYID


def test_rfc9421_b26_ed25519_vector() -> None:
    message = Message(
        "POST",
        "https://example.com/foo?param=Value&Pet=dog",
        {
            "Host": "example.com",
            "Date": "Tue, 20 Apr 2021 02:07:55 GMT",
            "Content-Type": "application/json",
            "Content-Digest": "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+"
                              "AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            "Content-Length": "18",
            "Signature-Input": 'sig-b26=("date" "@method" "@path" "@authority" '
                               '"content-type" "content-length");created=1618884473'
                               ';keyid="test-key-ed25519"',
            "Signature": "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02G"
                         "b04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
        },
    )
    keys = {"test-key-ed25519": load_ed25519_jwk(RFC_ED25519_JWK)}
    results = _verifier(keys).verify(message, max_age=None)
    assert len(results) == 1 and results[0].label == "sig-b26"


def test_wba_a22_dictionary_signature_agent_vector() -> None:
    """Current WBA form: Signature-Agent as sf-dictionary, covered with ;key=.

    NOTE: the signature bytes in draft -05 Appendix A.2.2 do NOT verify over the
    draft's own printed signature base with the draft's key (checked manually;
    the legacy A.2.3 vector and RFC 9421 B.2.6 both verify, so the defect is in
    the draft's example, not our canonicalization). Ed25519 is deterministic, so
    we pin the signature RE-SIGNED with the same RFC test key over the SAME
    byte-exact base — any canonicalization drift still fails this test."""
    message = Message(
        "POST",
        "https://example.com/foo?param=Value&Pet=dog",
        {
            "Host": "example.com",
            "Signature-Agent": 'agent2="https://signature-agent.test"',
            "Signature-Input": 'sig2=("@authority" "signature-agent";key="agent2")'
                               ";created=1735689600"
                               f';keyid="{WBA_KEYID}"'
                               ';alg="ed25519";expires=4889289600'
                               ';nonce="XeP72svPKNiGEg3aDE7WJuTpN69H08oMFqC8NLFy1Mptp'
                               'ENAT3WZTYwK+MYdsFMlaqHCJGo9ZAhqer1NWY9Epg=="'
                               ';tag="web-bot-auth"',
            "Signature": "sig2=:wcdt15OqjHqwTonruLNZ2bW/p1QPNQgYOHqjRt0GuXMRSNp9a8Qw4"
                         "ny/iTti7TjvLj4GAFoKRCvsEetB1nO4BQ==:",
        },
    )
    keys = {WBA_KEYID: load_ed25519_jwk(RFC_ED25519_JWK)}
    verifier = NoExpiryVerifier(  # created=2025 is outside any sane max_age window
        signature_algorithm=algorithms.ED25519,
        key_resolver=StaticKeyResolver(keys),
        component_resolver_class=DictKeyComponentResolver,
    )
    results = verifier.verify(message, expect_tag="web-bot-auth")
    assert len(results) == 1 and results[0].parameters["keyid"] == WBA_KEYID


def test_wba_a23_legacy_string_signature_agent_vector() -> None:
    """Legacy WBA form (OpenAI production): Signature-Agent as bare sf-string."""
    message = Message(
        "POST",
        "https://example.com/foo?param=Value&Pet=dog",
        {
            "Host": "example.com",
            "Signature-Agent": '"https://signature-agent.test"',
            "Signature-Input": 'sig2=("@authority" "signature-agent")'
                               ";created=1735689600"
                               f';keyid="{WBA_KEYID}"'
                               ';alg="ed25519";expires=1735693200'
                               ';nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4l'
                               'AZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg=="'
                               ';tag="web-bot-auth"',
            "Signature": "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD"
                         "+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
        },
    )
    keys = {WBA_KEYID: load_ed25519_jwk(RFC_ED25519_JWK)}
    verifier = NoExpiryVerifier(  # the draft's legacy vector is intentionally expired
        signature_algorithm=algorithms.ED25519,
        key_resolver=StaticKeyResolver(keys),
        component_resolver_class=DictKeyComponentResolver,
    )
    results = verifier.verify(message, expect_tag="web-bot-auth")
    assert len(results) == 1


def test_tampered_request_fails() -> None:
    message = Message(
        "POST",
        "https://EVIL.example/foo?param=Value&Pet=dog",  # authority differs from signed
        {
            "Host": "evil.example",
            "Signature-Agent": 'agent2="https://signature-agent.test"',
            "Signature-Input": 'sig2=("@authority" "signature-agent";key="agent2")'
                               ";created=1735689600"
                               f';keyid="{WBA_KEYID}"'
                               ';alg="ed25519";expires=4889289600'
                               ';nonce="XeP72svPKNiGEg3aDE7WJuTpN69H08oMFqC8NLFy1Mptp'
                               'ENAT3WZTYwK+MYdsFMlaqHCJGo9ZAhqer1NWY9Epg=="'
                               ';tag="web-bot-auth"',
            "Signature": "sig2=:wcdt15OqjHqwTonruLNZ2bW/p1QPNQgYOHqjRt0GuXMRSNp9a8Qw4"
                         "ny/iTti7TjvLj4GAFoKRCvsEetB1nO4BQ==:",
        },
    )
    keys = {WBA_KEYID: load_ed25519_jwk(RFC_ED25519_JWK)}
    verifier = NoExpiryVerifier(
        signature_algorithm=algorithms.ED25519,
        key_resolver=StaticKeyResolver(keys),
        component_resolver_class=DictKeyComponentResolver,
    )
    with pytest.raises(InvalidSignature):
        verifier.verify(message, expect_tag="web-bot-auth")


def test_expired_signature_rejected_by_real_verifier() -> None:
    """The REAL verifier (no expiry bypass) must reject the expired legacy vector."""
    message = Message(
        "POST",
        "https://example.com/foo?param=Value&Pet=dog",
        {
            "Host": "example.com",
            "Signature-Agent": '"https://signature-agent.test"',
            "Signature-Input": 'sig2=("@authority" "signature-agent")'
                               ";created=1735689600"
                               f';keyid="{WBA_KEYID}"'
                               ';alg="ed25519";expires=1735693200'
                               ';nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4l'
                               'AZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg=="'
                               ';tag="web-bot-auth"',
            "Signature": "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD"
                         "+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
        },
    )
    keys = {WBA_KEYID: load_ed25519_jwk(RFC_ED25519_JWK)}
    with pytest.raises(InvalidSignature):
        _verifier(keys).verify(message, max_age=timedelta(hours=25),
                               expect_tag="web-bot-auth")


def test_parse_signature_agent_both_forms() -> None:
    assert parse_signature_agent('"https://chatgpt.com"') == "https://chatgpt.com"
    assert parse_signature_agent('agent2="https://signature-agent.test"') == \
        "https://signature-agent.test"
    assert parse_signature_agent("") is None
    assert parse_signature_agent("garbage \x00") is None


def test_sign_then_verify_roundtrip() -> None:
    """Sign a fresh request with a generated key, verify with the strict verifier."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver

    priv = Ed25519PrivateKey.generate()
    jwk = {"kty": "OKP", "crv": "Ed25519",
           "x": b64url(priv.public_key().public_bytes_raw())}
    keyid = jwk_thumbprint(jwk)

    class PrivResolver(HTTPSignatureKeyResolver):
        def resolve_private_key(self, key_id: str):  # type: ignore[no-untyped-def]
            return priv

        def resolve_public_key(self, key_id: str):  # type: ignore[no-untyped-def]
            raise NotImplementedError

    message = Message("POST", "https://api.example/v1/agents/register",
                      {"Host": "api.example",
                       "Signature-Agent": '"https://agent.example"'})
    signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519,
                               key_resolver=PrivResolver(),
                               component_resolver_class=DictKeyComponentResolver)
    signer.sign(message, key_id=keyid, tag="web-bot-auth", label="sig1",
                covered_component_ids=("@method", "@authority", "@path",
                                       "signature-agent"))

    keys = {keyid: load_ed25519_jwk(jwk)}
    results = _verifier(keys).verify(message, max_age=timedelta(minutes=5),
                                     expect_tag="web-bot-auth")
    assert len(results) == 1 and results[0].parameters["keyid"] == keyid
