"""End-to-end HttpsigVerifier tests — directory fetching mocked, crypto real.

The AAuth half pins draft-hardt-oauth-aauth-protocol-11 §11.3 as published:
the Signature-Error codes of §11.3.4, the covered components of §11.3.3.1, the
60-second ``created`` window, fully-specified algorithms, the jwks_uri server
scheme, and the RS-43/RS-51/RS-52 points from the role upgrade guides."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regent_httpsig import (
    EgressSigner,
    HttpsigConfig,
    HttpsigVerifier,
    ServerSigner,
    VerificationError,
    VerifiedSignature,
    generate_seed,
)
from regent_httpsig.jwk import b64url
from regent_httpsig.verify import _register_fully_specified_algs

ISS = "https://issuer.example"
URL = "https://api.example/v1/orders"


def _mock_fetch(mapping: dict[str, dict[str, Any]]):
    async def fetch(url: str) -> dict[str, Any] | None:
        return mapping.get(url)

    return fetch


def _issuer_pair(kid: str = "iss-1", alg: str = "Ed25519"):
    priv = Ed25519PrivateKey.generate()
    jwk = {"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": alg,
           "x": b64url(priv.public_key().public_bytes_raw())}
    return priv, jwk


def _mint(issuer_priv, *, typ: str, alg: str = "Ed25519", claims: dict, kid: str = "iss-1") -> str:
    _register_fully_specified_algs()
    return pyjwt.encode(claims, issuer_priv, algorithm=alg, headers={"typ": typ, "kid": kid})


def _agent_token(issuer_priv, agent: EgressSigner, *, iss: str = ISS,
                 alg: str = "Ed25519", lifetime: int = 600,
                 cnf_alg: str | None = "Ed25519", **extra: Any) -> str:
    now = int(time.time())
    jwk = dict(agent.public_jwk)
    if cnf_alg is None:
        jwk.pop("alg", None)
    else:
        jwk["alg"] = cnf_alg
    return _mint(issuer_priv, typ="aa-agent+jwt", alg=alg, claims={
        "iss": iss, "sub": "agent-42", "iat": now, "exp": now + lifetime,
        "dwk": "aauth-agent.json", "cnf": {"jwk": jwk}, **extra,
    })


def _docs(issuer_jwk: dict[str, Any], *, iss: str = ISS, dwk: str = "aauth-agent.json",
          metadata_issuer: str | None = None) -> dict[str, dict[str, Any]]:
    return {
        f"{iss}/.well-known/{dwk}": {"issuer": metadata_issuer or iss,
                                     "jwks_uri": f"{iss}/jwks.json"},
        f"{iss}/jwks.json": {"keys": [issuer_jwk]},
    }


def _verifier(docs: dict[str, dict[str, Any]], monkeypatch: pytest.MonkeyPatch,
              config: HttpsigConfig | None = None, **kw: Any) -> HttpsigVerifier:
    verifier = HttpsigVerifier(config, **kw)
    monkeypatch.setattr(verifier, "_fetch_json", _mock_fetch(docs))
    return verifier


def _error(result: Any) -> VerificationError:
    assert isinstance(result, VerificationError), result
    return result


# ── no signature / Web Bot Auth ──────────────────────────────────────────────


async def test_no_signature_header_is_none() -> None:
    verifier = HttpsigVerifier()
    assert await verifier.verify("GET", "https://api.example/x", {}) is None
    assert await verifier.verify_detailed("GET", "https://api.example/x", {}) is None


async def test_wba_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """EgressSigner output verifies through the full verifier pipeline."""
    signer = EgressSigner(seed=generate_seed(), signature_agent="https://agent.example")
    url = "https://api.example/v1/orders?limit=5"
    headers = signer.sign("POST", url, {"Host": "api.example"})

    verifier = _verifier({
        "https://agent.example/.well-known/http-message-signatures-directory": signer.directory(),
    }, monkeypatch, HttpsigConfig(trusted_agents=frozenset({"https://agent.example"})))
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
    headers = signer.sign("POST", URL, {"Host": "api.example"})
    verifier = _verifier({
        "https://agent.example/.well-known/http-message-signatures-directory": other.directory(),
    }, monkeypatch)
    assert await verifier.verify("POST", URL, headers) is None
    assert _error(await verifier.verify_detailed("POST", URL, headers)).code == "invalid_signature"


# ── AAuth agent tokens (jwt scheme) ──────────────────────────────────────────


async def test_aauth_identity_mode_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Agent token verified against the issuer JWKS (discovered through
    aauth-agent.json), request signature verified against cnf.jwk."""
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    token = _agent_token(issuer_priv, agent)
    headers = agent.sign_aauth("POST", URL, {"Host": "api.example"}, token=token)
    assert "keyid" not in headers["Signature-Input"]  # -11: agents SHOULD NOT send keyid

    sig = await _verifier(_docs(issuer_jwk), monkeypatch).verify("POST", URL, headers)
    assert sig is not None
    assert sig.scheme == "aauth"
    assert sig.agent == ISS
    assert sig.sub == "agent-42"
    assert sig.keyid == agent.keyid
    assert sig.claims["dwk"] == "aauth-agent.json"


async def test_aauth_required_components_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """§11.3.3.1: a signature that does not cover signature-key is invalid_input
    with required_input naming the full set."""
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    token = _agent_token(issuer_priv, agent)
    headers = agent.sign("POST", URL, {"Host": "api.example"})  # WBA components only
    headers["Signature-Key"] = f'sig1=jwt;jwt="{token}"'
    verifier = _verifier(_docs(issuer_jwk), monkeypatch)
    err = _error(await verifier.verify_detailed("POST", URL, headers))
    assert err.code == "invalid_input"
    assert err.required_input == ("@method", "@authority", "@path", "signature-key")
    assert err.headers()["Signature-Error"] == (
        'error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key")')


async def test_aauth_body_must_be_covered_and_match(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    token = _agent_token(issuer_priv, agent)
    verifier = _verifier(_docs(issuer_jwk), monkeypatch)
    body = json.dumps({"sku": "x"}).encode()

    headers = agent.sign_aauth("POST", URL,
                               {"Host": "api.example", "Content-Type": "application/json"},
                               token=token, body=body)
    assert "content-digest" in headers["Signature-Input"]
    assert isinstance(await verifier.verify_detailed("POST", URL, headers, body), VerifiedSignature)
    tampered = _error(await verifier.verify_detailed("POST", URL, headers, b'{"sku":"y"}'))
    assert tampered.code == "invalid_signature" and "Content-Digest" in tampered.detail

    bare = agent.sign_aauth("POST", URL, {"Host": "api.example"}, token=token)  # body not covered
    err = _error(await verifier.verify_detailed("POST", URL, bare, body))
    assert err.code == "invalid_input"
    assert err.required_input[-2:] == ("content-digest", "content-type")


async def test_aauth_created_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """§11.3.4 step 3: older than the window → invalid_signature; ahead of our
    clock by more than the window → clock_skew; inside it → accepted."""
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    token = _agent_token(issuer_priv, agent)
    verifier = _verifier(_docs(issuer_jwk), monkeypatch)
    now = int(time.time())

    host = {"Host": "api.example"}
    old = agent.sign_aauth("POST", URL, host, token=token, created=now - 61)
    assert _error(await verifier.verify_detailed("POST", URL, old)).code == "invalid_signature"
    ahead = agent.sign_aauth("POST", URL, host, token=token, created=now + 61)
    assert _error(await verifier.verify_detailed("POST", URL, ahead)).code == "clock_skew"
    near = agent.sign_aauth("POST", URL, host, token=token, created=now + 30)
    assert isinstance(await verifier.verify_detailed("POST", URL, near), VerifiedSignature)

    wide = _verifier(_docs(issuer_jwk), monkeypatch,
                     HttpsigConfig(signature_window_seconds=120))
    assert isinstance(await wide.verify_detailed("POST", URL, old), VerifiedSignature)


async def test_aauth_expired_token_is_expired_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    """RS-51: exp has no tolerance, and an expired token is named expired, not invalid."""
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    now = int(time.time())
    token = _mint(issuer_priv, typ="aa-agent+jwt", claims={
        "iss": ISS, "sub": "agent-42", "iat": now - 120, "exp": now - 1,
        "dwk": "aauth-agent.json", "cnf": {"jwk": agent.public_jwk},
    })
    headers = agent.sign_aauth("POST", URL, {"Host": "api.example"}, token=token)
    verifier = _verifier(_docs(issuer_jwk), monkeypatch)
    assert await verifier.verify("POST", URL, headers) is None
    err = _error(await verifier.verify_detailed("POST", URL, headers))
    assert err.code == "expired_jwt" and err.token_typ == "aa-agent+jwt"


async def test_aauth_iat_ahead_is_clock_skew(monkeypatch: pytest.MonkeyPatch) -> None:
    """RS-51: iat is not a validity check — only an iat beyond the window ahead
    of our clock is refused, and as clock_skew."""
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    now = int(time.time())
    headers = agent.sign_aauth("POST", URL, {"Host": "api.example"}, token=_mint(
        issuer_priv, typ="aa-agent+jwt", claims={
            "iss": ISS, "sub": "a", "iat": now + 300, "exp": now + 900,
            "dwk": "aauth-agent.json", "cnf": {"jwk": agent.public_jwk}}))
    verifier = _verifier(_docs(issuer_jwk), monkeypatch)
    assert _error(await verifier.verify_detailed("POST", URL, headers)).code == "clock_skew"


async def test_aauth_revoked_token_is_revoked_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    """RS-43 / §11.12.5: a token the application marked revoked is named revoked."""
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    token = _agent_token(issuer_priv, agent, jti="tok-1")
    headers = agent.sign_aauth("POST", URL, {"Host": "api.example"}, token=token)
    seen: list[tuple[str, str]] = []

    async def is_revoked(iss: str, jti: str) -> bool:
        seen.append((iss, jti))
        return jti == "tok-1"

    verifier = _verifier(_docs(issuer_jwk), monkeypatch, is_revoked=is_revoked)
    err = _error(await verifier.verify_detailed("POST", URL, headers))
    assert err.code == "revoked_jwt" and seen == [(ISS, "tok-1")]
    assert err.headers() == {"Signature-Error": "error=revoked_jwt"}
    assert err.problem()["type"] == "urn:ietf:params:sig-error:revoked_jwt"


async def test_aauth_issuer_mismatch_and_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    headers = agent.sign_aauth("POST", URL, {"Host": "api.example"},
                               token=_agent_token(issuer_priv, agent))
    mismatch = _verifier(_docs(issuer_jwk, metadata_issuer="https://other.example"),
                         monkeypatch)
    assert _error(await mismatch.verify_detailed("POST", URL, headers)).code == "issuer_mismatch"
    missing = _verifier({}, monkeypatch)
    assert _error(await missing.verify_detailed("POST", URL, headers)).code == "issuer_missing"


async def test_aauth_unknown_kid_refetches_once_then_unknown_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    headers = agent.sign_aauth("POST", URL, {"Host": "api.example"},
                               token=_mint(issuer_priv, typ="aa-agent+jwt", kid="rotated", claims={
                                   "iss": ISS, "sub": "a", "iat": int(time.time()),
                                   "exp": int(time.time()) + 60, "dwk": "aauth-agent.json",
                                   "cnf": {"jwk": agent.public_jwk}}))
    calls: list[str] = []
    docs = _docs(issuer_jwk)
    verifier = HttpsigVerifier()

    async def fetch(url: str) -> dict[str, Any] | None:
        calls.append(url)
        return docs.get(url)

    monkeypatch.setattr(verifier, "_fetch_json", fetch)
    assert _error(await verifier.verify_detailed("POST", URL, headers)).code == "unknown_key"
    assert calls.count(f"{ISS}/jwks.json") == 2  # one refetch for rotation, then give up


async def test_aauth_without_keyid_param_hand_built(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pins the interop shape of christian-posta/aauth-signing: the signature
    base built by hand over @method/@authority/@path/signature-key, created
    only — NO keyid param — verifies."""
    agent_priv = Ed25519PrivateKey.generate()
    agent_jwk = {"kty": "OKP", "crv": "Ed25519", "alg": "Ed25519",
                 "x": b64url(agent_priv.public_key().public_bytes_raw())}
    issuer_priv, issuer_jwk = _issuer_pair()
    now = int(time.time())
    token = _mint(issuer_priv, typ="aa-agent+jwt", claims={
        "iss": ISS, "sub": "agent-42", "iat": now, "exp": now + 600,
        "dwk": "aauth-agent.json", "cnf": {"jwk": agent_jwk}})
    sig_key_header = f'sig=jwt;jwt="{token}"'
    params = f'("@method" "@authority" "@path" "signature-key");created={now}'
    base = "\n".join([
        '"@method": POST',
        '"@authority": api.example',
        '"@path": /v1/orders',
        f'"signature-key": {sig_key_header}',
        f'"@signature-params": {params}',
    ]).encode()
    signature = base64.b64encode(agent_priv.sign(base)).decode()
    headers = {"Host": "api.example", "Signature-Key": sig_key_header,
               "Signature-Input": f"sig={params}", "Signature": f"sig=:{signature}:"}
    sig = await _verifier(_docs(issuer_jwk), monkeypatch).verify("POST", URL, headers)
    assert sig is not None and sig.scheme == "aauth" and sig.sub == "agent-42"


async def test_aauth_sub_is_case_sensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    """RS-52: agent identifiers are compared exactly; no case folding anywhere."""
    issuer_priv, issuer_jwk = _issuer_pair()
    agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
    now = int(time.time())
    headers = agent.sign_aauth("POST", URL, {"Host": "api.example"}, token=_mint(
        issuer_priv, typ="aa-agent+jwt", claims={
            "iss": ISS, "sub": "Agent-42", "iat": now, "exp": now + 60,
            "dwk": "aauth-agent.json", "cnf": {"jwk": agent.public_jwk}}))
    sig = await _verifier(_docs(issuer_jwk), monkeypatch).verify("POST", URL, headers)
    assert sig is not None and sig.sub == "Agent-42" and sig.sub != "agent-42"


class TestFullySpecifiedAlgs:
    """AAuth -11 §11.3.1 / RFC 9864: Ed25519 accepted; the polymorphic EdDSA and
    keys without alg are refused by default; the transition flag is opt-in."""

    async def _run(self, monkeypatch: pytest.MonkeyPatch, *, token_alg: str = "Ed25519",
                   key_alg: str = "Ed25519", cnf_alg: str | None = "Ed25519",
                   config: HttpsigConfig | None = None):
        issuer_priv, issuer_jwk = _issuer_pair(alg=key_alg)
        agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
        token = _agent_token(issuer_priv, agent, alg=token_alg, cnf_alg=cnf_alg)
        headers = agent.sign_aauth("POST", URL, {"Host": "api.example"}, token=token)
        verifier = _verifier(_docs(issuer_jwk), monkeypatch, config)
        return await verifier.verify_detailed("POST", URL, headers)

    async def test_ed25519_verifies(self, monkeypatch) -> None:
        assert isinstance(await self._run(monkeypatch), VerifiedSignature)

    async def test_eddsa_token_refused_with_accept_alg(self, monkeypatch) -> None:
        err = _error(await self._run(monkeypatch, token_alg="EdDSA", key_alg="EdDSA"))
        assert err.code == "unsupported_algorithm"
        assert err.headers()["Accept-Signature-Alg"] == "Ed25519, ES256, RS256"

    async def test_eddsa_issuer_key_refused(self, monkeypatch) -> None:
        err = _error(await self._run(monkeypatch, key_alg="EdDSA"))
        assert err.code == "unsupported_algorithm"

    async def test_cnf_without_alg_refused(self, monkeypatch) -> None:
        err = _error(await self._run(monkeypatch, cnf_alg=None))
        assert err.code == "unsupported_algorithm"

    async def test_transition_flag_accepts_eddsa(self, monkeypatch) -> None:
        lax = HttpsigConfig(require_fully_specified_algs=False)
        result = await self._run(monkeypatch, token_alg="EdDSA", key_alg="EdDSA",
                                 cnf_alg=None, config=lax)
        assert isinstance(result, VerifiedSignature)


async def test_aauth_es256_cnf_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A P-256 possession key (ES256, SHOULD in -11) signs the request."""
    from regent_httpsig.sign import sign_request

    issuer_priv, issuer_jwk = _issuer_pair()
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    nums = ec_priv.public_key().public_numbers()
    cnf = {"kty": "EC", "crv": "P-256", "alg": "ES256",
           "x": b64url(nums.x.to_bytes(32, "big")), "y": b64url(nums.y.to_bytes(32, "big"))}
    now = int(time.time())
    token = _mint(issuer_priv, typ="aa-agent+jwt", claims={
        "iss": ISS, "sub": "ec-agent", "iat": now, "exp": now + 60,
        "dwk": "aauth-agent.json", "cnf": {"jwk": cnf}})
    headers = sign_request(ec_priv, "POST", URL,
                           {"Host": "api.example", "Signature-Key": f'sig=jwt;jwt="{token}"'},
                           covered=("@method", "@authority", "@path", "signature-key"))
    sig = await _verifier(_docs(issuer_jwk), monkeypatch).verify("POST", URL, headers)
    assert sig is not None and sig.sub == "ec-agent"


async def test_unsupported_scheme_names_what_is_accepted() -> None:
    headers = {"Host": "api.example", "Signature-Key": 'sig=hwk;jwk="{}"',
               "Signature-Input": 'sig=("@method");created=1', "Signature": "sig=:AA==:"}
    err = _error(await HttpsigVerifier().verify_detailed("POST", URL, headers))
    assert err.code == "unsupported_scheme"
    assert err.headers()["Accept-Signature-Scheme"] == "jwt, jwks_uri"


# ── person tokens ────────────────────────────────────────────────────────────


class TestPersonTokens:
    """AAuth -11 person tokens: PS-issued, per-resource aud, cnf-bound, ≤1h strict."""

    def _headers(self, *, aud: str, lifetime: int = 600):
        ps_priv, ps_jwk = _issuer_pair()
        agent = EgressSigner(seed=generate_seed(), signature_agent="https://ps.example")
        now = int(time.time())
        token = _mint(ps_priv, typ="aa-person+jwt", claims={
            "iss": "https://ps.example", "sub": "directed-sub-1", "aud": aud,
            "iat": now, "exp": now + lifetime, "dwk": "aauth-person.json",
            "jti": "pt-1", "cnf": {"jwk": agent.public_jwk},
        })
        url = "https://api.example/v1/x"
        headers = agent.sign_aauth("POST", url, {"Host": "api.example"}, token=token)
        return url, headers, ps_jwk

    def _verifier(self, ps_jwk, monkeypatch, **cfg):
        return _verifier(_docs(ps_jwk, iss="https://ps.example", dwk="aauth-person.json"),
                         monkeypatch, HttpsigConfig(**cfg))

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
        assert _error(await v.verify_detailed("POST", url, headers)).code == "invalid_jwt"

    async def test_person_token_disabled_without_resource_url(self, monkeypatch) -> None:
        url, headers, ps_jwk = self._headers(aud="https://api.example")
        v = self._verifier(ps_jwk, monkeypatch)  # no resource_url → path disabled
        assert await v.verify("POST", url, headers) is None

    async def test_person_token_lifetime_cap_is_exactly_one_hour(self, monkeypatch) -> None:
        url, headers, ps_jwk = self._headers(aud="https://api.example", lifetime=3601)
        v = self._verifier(ps_jwk, monkeypatch, resource_url="https://api.example")
        assert _error(await v.verify_detailed("POST", url, headers)).code == "invalid_jwt"
        url, headers, ps_jwk = self._headers(aud="https://api.example", lifetime=3600)
        v = self._verifier(ps_jwk, monkeypatch, resource_url="https://api.example")
        assert isinstance(await v.verify_detailed("POST", url, headers), VerifiedSignature)


# ── servers (jwks_uri scheme) ────────────────────────────────────────────────


class TestServerScheme:
    """-11 §11.3.2: a PS/AS signs ``sig=jwks_uri;id=…;dwk=…;kid=…``; the resource
    resolves {id}/.well-known/{dwk} → jwks_uri → kid."""

    def _ps(self):
        return ServerSigner(seed=generate_seed(), server_id="https://ps.example",
                            dwk="aauth-person.json")

    def _docs(self, ps: ServerSigner, issuer: str = "https://ps.example"):
        return {"https://ps.example/.well-known/aauth-person.json":
                    {"issuer": issuer, "jwks_uri": "https://ps.example/j"},
                "https://ps.example/j": ps.jwks()}

    async def test_server_signature_with_body(self, monkeypatch) -> None:
        ps = self._ps()
        body = b'{"jti":"t","exp":1}'
        headers = ps.sign("POST", "https://api.example/revoke", body=body)
        assert headers["Signature-Key"] == (
            f'sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="{ps.keyid}"')
        v = _verifier(self._docs(ps), monkeypatch,
                      HttpsigConfig(trusted_ps={"https://ps.example": ""}))
        sig = await v.verify_server("POST", "https://api.example/revoke", headers, body)
        assert isinstance(sig, VerifiedSignature)
        assert sig.scheme == "aauth-server" and sig.agent == "https://ps.example"
        assert sig.keyid == ps.keyid and sig.trusted is True
        # The generic path accepts it too, as an untrusted server when not pinned.
        plain = _verifier(self._docs(ps), monkeypatch)
        sig2 = await plain.verify_detailed("POST", "https://api.example/revoke", headers, body)
        assert isinstance(sig2, VerifiedSignature) and sig2.trusted is False

    async def test_server_wrong_dwk_and_mismatch(self, monkeypatch) -> None:
        ps = self._ps()
        headers = ps.sign("POST", "https://api.example/revoke", body=b"{}")
        v = _verifier(self._docs(ps, issuer="https://evil.example"), monkeypatch)
        err = await v.verify_server("POST", "https://api.example/revoke", headers, b"{}")
        assert _error(err).code == "issuer_mismatch"
        err = await v.verify_server("POST", "https://api.example/revoke", headers, b"{}",
                                    allowed_dwk=("aauth-access.json",))
        assert _error(err).code == "invalid_key"

    async def test_server_endpoint_refuses_agent_jwt_scheme(self, monkeypatch) -> None:
        issuer_priv, issuer_jwk = _issuer_pair()
        agent = EgressSigner(seed=generate_seed(), signature_agent=ISS)
        headers = agent.sign_aauth("POST", "https://api.example/revoke", {"Host": "api.example"},
                                   token=_agent_token(issuer_priv, agent))
        err = await _verifier(_docs(issuer_jwk), monkeypatch).verify_server(
            "POST", "https://api.example/revoke", headers)
        assert _error(err).code == "unsupported_scheme"
        assert err.headers()["Accept-Signature-Scheme"] == "jwks_uri"


async def test_cache_is_per_instance() -> None:
    a, b = HttpsigVerifier(), HttpsigVerifier()
    a._cache_put("https://x.example/doc", {"keys": []}, ttl=60)
    hit_a, _ = a._cache_get("https://x.example/doc")
    hit_b, _ = b._cache_get("https://x.example/doc")
    assert hit_a is True and hit_b is False
