"""Inbound agent-identity verification — RFC 9421 HTTP Message Signatures.

Two schemes are accepted side by side (both ride the same ``Signature`` /
``Signature-Input`` headers; the difference is where the public key comes from):

- **Web Bot Auth** (draft-meunier-web-bot-auth-architecture): the agent's
  operator publishes an Ed25519 JWKS at
  ``{Signature-Agent}/.well-known/http-message-signatures-directory`` and signs
  every request with ``tag="web-bot-auth"``. OpenAI's agents sign all their
  traffic this way today. Both wire forms of ``Signature-Agent`` are accepted:
  the draft -05 sf-dictionary (covered with ``;key=``) and the legacy bare
  sf-string OpenAI ships.
- **AAuth** (draft-hardt-oauth-aauth-protocol-11): the agent carries a JWT in
  the ``Signature-Key`` header under the ``jwt`` scheme — an agent token
  (``typ: aa-agent+jwt``), a person token (``aa-person+jwt``) or an auth token
  (``aa-auth+jwt``, the budget carrier). The issuer's JWKS, discovered through
  ``{iss}/.well-known/{dwk}``, verifies the token; the token's ``cnf.jwk``
  verifies the request signature (proof of possession). Servers (a PS or AS
  calling a resource's usage or revocation endpoint) sign under the ``jwks_uri``
  scheme with ``id``, ``dwk`` and ``kid``. Requires the ``[aauth]`` extra.

Failures are typed, not silent: :meth:`HttpsigVerifier.verify_detailed` returns
a :class:`VerificationError` carrying the ``Signature-Error`` code of
draft-hardt-httpbis-signature-key (``invalid_signature``, ``clock_skew``,
``expired_jwt``, ``revoked_jwt``, ``unsupported_scheme``, …) exactly as -11
§11.3.4 assigns them, so a resource can answer ``401`` with the header the
agent needs. :meth:`HttpsigVerifier.verify` keeps the old ``None``-on-failure
contract for callers that only want a yes or no.

Directory fetches are SSRF-guarded (https-only, public-IP-only, size-capped,
no redirects) and cached per verifier instance.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from http_message_signatures import HTTPMessageVerifier  # type: ignore[attr-defined]

from regent_httpsig.config import HttpsigConfig
from regent_httpsig.jwk import jwk_thumbprint, load_ed25519_jwk
from regent_httpsig.netguard import NotPublicURL, assert_public_url
from regent_httpsig.sfv import (
    ED25519,
    DictKeyComponentResolver,
    Message,
    StaticKeyResolver,
    parse_signature_agent,
    parse_signature_input,
    parse_signature_key,
)

__all__ = [
    "AAUTH_ACCEPT_ALGS",
    "AAUTH_ACCEPT_SCHEMES",
    "HttpsigVerifier",
    "VerificationError",
    "VerifiedSignature",
    "WBA_TAG",
]

logger = logging.getLogger("regent_httpsig")

WBA_TAG = "web-bot-auth"
WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
AAUTH_METADATA_PATH = "/.well-known/aauth-agent.json"
AAUTH_PERSON_METADATA_PATH = "/.well-known/aauth-person.json"
AAUTH_JWT_TYP = "aa-agent+jwt"
AAUTH_PERSON_TYP = "aa-person+jwt"
AAUTH_AUTH_TYP = "aa-auth+jwt"  # PS/AS-issued auth tokens — the budget carrier
# The well-known documents a server may sign under (§11.3.2).
SERVER_DWKS = ("aauth-person.json", "aauth-access.json", "aauth-agent.json", "aauth-resource.json")
# -11 §11.5.2: person and auth tokens live at most one hour. No tolerance.
PERSON_TOKEN_MAX_LIFETIME = 3600
# What this verifier accepts, as advertised on Signature-Error responses.
AAUTH_ACCEPT_SCHEMES: tuple[str, ...] = ("jwt", "jwks_uri")
AAUTH_ACCEPT_ALGS: tuple[str, ...] = ("Ed25519", "ES256", "RS256")

# JOSE alg → (RFC 9421 signature algorithm, key type, curve)
_ALG_TABLE: dict[str, tuple[str, str, str | None]] = {
    "Ed25519": ("ED25519", "OKP", "Ed25519"),
    "ES256": ("ECDSA_P256_SHA256", "EC", "P-256"),
    "RS256": ("RSA_V1_5_SHA256", "RSA", None),
}

RevocationCheck = Callable[[str, str], Awaitable[bool]]


def _register_fully_specified_algs() -> None:
    """Register 'Ed25519' (RFC 9864 fully-specified) with PyJWT — same math as
    the polymorphic 'EdDSA', which AAuth -11 forbids implementations to accept."""
    import contextlib

    import jwt as pyjwt
    from jwt.algorithms import OKPAlgorithm

    with contextlib.suppress(ValueError):  # already registered = fine
        pyjwt.register_algorithm("Ed25519", OKPAlgorithm())


@dataclass
class VerifiedSignature:
    """A successfully verified inbound signature."""

    scheme: str  # "web-bot-auth" | "aauth" | "aauth-person" | "aauth-auth" | "aauth-server"
    agent: str  # WBA: Signature-Agent origin; AAuth: the token issuer / the server id
    keyid: str  # RFC 7638 / RFC 8037 A.3 JWK thumbprint (server scheme: the JWKS kid)
    trusted: bool  # agent/issuer is on the configured trust list
    sub: str | None = None  # AAuth agent id (token `sub`)
    label: str = ""
    claims: dict[str, Any] = field(default_factory=dict)  # AAuth token claims (redacted)

    def context(self) -> dict[str, Any]:
        """A flat dict suitable for logging / policy engines / audit trails."""
        out: dict[str, Any] = {
            "signed_agent": True,
            "signature_scheme": self.scheme,
            "signature_agent": self.agent,
            "signature_keyid": self.keyid,
            "signature_trusted": self.trusted,
        }
        if self.sub:
            out["signature_sub"] = self.sub
        return out


@dataclass
class VerificationError:
    """Why a signed request was refused — the ``Signature-Error`` vocabulary of
    draft-hardt-httpbis-signature-key, assigned as AAuth -11 §11.3.4 assigns it.
    ``headers()`` is what a 401 carries; ``problem()`` is the RFC 9457 body."""

    code: str
    detail: str = ""
    accept_schemes: tuple[str, ...] = ()
    accept_algs: tuple[str, ...] = ()
    required_input: tuple[str, ...] = ()
    token_typ: str | None = None  # the AAuth token typ, once known (jwt scheme only)

    def headers(self) -> dict[str, str]:
        value = f"error={self.code}"
        if self.required_input:
            inner = " ".join(f'"{c}"' for c in self.required_input)
            value += f", required_input=({inner})"
        out = {"Signature-Error": value}
        if self.accept_schemes:
            out["Accept-Signature-Scheme"] = ", ".join(self.accept_schemes)
        if self.accept_algs:
            out["Accept-Signature-Alg"] = ", ".join(self.accept_algs)
        return out

    def problem(self, status: int = 401) -> dict[str, Any]:
        return {
            "type": f"urn:ietf:params:sig-error:{self.code}",
            "title": self.code.replace("_", " "),
            "status": status,
            "detail": self.detail or self.code,
            "error": self.code,
        }


class _KeyidOptionalParams(dict):  # type: ignore[type-arg]
    """RFC 9421 makes ``keyid`` OPTIONAL, but the upstream verifier reads
    ``params["keyid"]`` unconditionally. On the AAuth path the key comes from
    the Signature-Key header, so conforming signers omit keyid (§11.3.3.2).
    Returning None for a missing keyid routes resolution to our
    StaticKeyResolver default WITHOUT adding the key to the params — iteration
    is unchanged, so the reconstructed signature base stays byte-identical."""

    def __getitem__(self, key: str) -> Any:
        if key == "keyid" and key not in self:
            return None
        return super().__getitem__(key)


class _KeyidOptionalVerifier(HTTPMessageVerifier):
    def validate_created_and_expires(self, sig_input: Any, max_age: Any = None) -> None:
        """No-op: the -11 window (`created` ± signature_window, `expires`) was
        judged in ``_check_signature_input`` with the draft's own error codes;
        the upstream 5-second skew rule must not pre-empt them."""

    def _verify_one(self, *, label: Any, sig_input: Any, signature: Any,
                    message: Any, max_age: Any) -> Any:
        if "keyid" not in sig_input.params:
            sig_input.params = _KeyidOptionalParams(sig_input.params)
        return super()._verify_one(  # type: ignore[no-untyped-call]
            label=label, sig_input=sig_input, signature=signature,
            message=message, max_age=max_age,
        )


def _keys_from_jwks(doc: dict[str, Any]) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for jwk in list(doc.get("keys") or [])[:10]:
        try:
            keys[jwk_thumbprint(jwk)] = load_ed25519_jwk(jwk)
        except Exception:  # noqa: BLE001 — skip non-Ed25519 / malformed keys
            continue
    return keys


class _Refused(Exception):
    """Internal: carries a VerificationError out of the AAuth path."""

    def __init__(self, error: VerificationError) -> None:
        super().__init__(error.code)
        self.error = error


def _refuse(code: str, detail: str = "", **extra: Any) -> _Refused:
    return _Refused(VerificationError(code, detail, **extra))


def _load_public_key(jwk: dict[str, Any]) -> tuple[Any, Any]:
    """Return ``(public key object, http_message_signatures algorithm)`` for a JWK
    whose ``alg`` is fully specified. Raises _Refused with the -11 code."""
    from http_message_signatures import algorithms as hms_algs

    alg = jwk.get("alg")
    if not isinstance(alg, str) or alg not in _ALG_TABLE:
        raise _refuse("unsupported_algorithm",
                      f"key alg {alg!r} is absent, polymorphic or not implemented",
                      accept_algs=AAUTH_ACCEPT_ALGS)
    hms_name, kty, crv = _ALG_TABLE[alg]
    if jwk.get("kty") != kty or (crv is not None and jwk.get("crv") != crv):
        raise _refuse("invalid_key", f"key type disagrees with alg {alg}")
    try:
        if alg == "Ed25519":
            key: Any = load_ed25519_jwk(jwk)
        else:
            import jwt as pyjwt

            key = pyjwt.PyJWK({k: v for k, v in jwk.items() if k != "alg"}).key
    except Exception as exc:  # noqa: BLE001
        raise _refuse("invalid_key", f"cannot parse key: {str(exc)[:80]}") from exc
    return key, getattr(hms_algs, hms_name)


class HttpsigVerifier:
    """Verify RFC 9421-signed agent requests (Web Bot Auth + AAuth).

    Instances are cheap and hold their own directory cache; create one per
    application and reuse it. ``http_client`` is optional — pass your app's
    shared :class:`httpx.AsyncClient` to reuse its pool. ``is_revoked(iss,
    jti)`` is how the application tells the verifier about revocations it has
    received (§11.12.5): a token it says yes for is answered ``revoked_jwt``.

    Usage::

        verifier = HttpsigVerifier()
        sig = await verifier.verify("POST", "https://api.example/v1/orders", headers)
        if sig:
            print(sig.agent)   # e.g. "https://chatgpt.com"
    """

    def __init__(
        self,
        config: HttpsigConfig | None = None,
        *,
        http_client: httpx.AsyncClient | None = None,
        is_revoked: RevocationCheck | None = None,
    ) -> None:
        self.config = config or HttpsigConfig()
        self._http = http_client
        self._owns_client = http_client is None
        self._is_revoked = is_revoked
        # url -> (expires_monotonic, parsed JSON | None for negative entries)
        self._cache: dict[str, tuple[float, dict[str, Any] | None]] = {}

    async def verify(
        self, method: str, url: str, headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> VerifiedSignature | None:
        """Verify the request's signature. ``None`` when there is no ``Signature``
        header, the signature is invalid, or the signer's keys cannot be (safely)
        fetched — never raises on untrusted input. Use :meth:`verify_detailed`
        to learn why."""
        result = await self.verify_detailed(method, url, headers, body)
        return result if isinstance(result, VerifiedSignature) else None

    async def verify_detailed(
        self, method: str, url: str, headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> VerifiedSignature | VerificationError | None:
        """Like :meth:`verify`, but a failure comes back as a
        :class:`VerificationError` (``None`` only when no ``Signature`` header is
        present at all). ``body`` enables the -11 body-coverage rule: when
        given and non-empty, ``content-digest`` and ``content-type`` must be
        covered and the digest must match."""
        hdrs = {str(k): str(v) for k, v in headers.items()}
        if not any(k.lower() == "signature" for k in hdrs):
            return None
        try:
            if any(k.lower() == "signature-key" for k in hdrs):
                return await self._verify_signature_key(method, url, hdrs, body)
            result = await self._verify_web_bot_auth(method, url, hdrs)
            if result is None:
                return VerificationError("invalid_signature",
                                         "Web Bot Auth signature did not verify")
            logger.info("httpsig verified scheme=%s agent=%s keyid=%s trusted=%s",
                        result.scheme, result.agent, result.keyid[:16], result.trusted)
            return result
        except _Refused as exc:
            logger.info("httpsig refused: %s %s", exc.error.code, exc.error.detail[:160])
            return exc.error
        except Exception as exc:  # noqa: BLE001 — belt and braces
            logger.warning("httpsig verify error: %s", str(exc)[:200])
            return VerificationError("invalid_signature", "verifier error")

    async def verify_server(
        self, method: str, url: str, headers: Mapping[str, str],
        body: bytes | None = None, *, allowed_dwk: tuple[str, ...] = SERVER_DWKS,
    ) -> VerifiedSignature | VerificationError:
        """Verify a request a *server* signed under the ``jwks_uri`` scheme
        (§11.3.2): a PS or AS at a revocation or usage endpoint. The caller is
        identified by ``id``; ``trusted`` says whether it is a configured PS."""
        hdrs = {str(k): str(v) for k, v in headers.items()}
        try:
            members = parse_signature_key(_header(hdrs, "signature-key"))
            if not members:
                raise _refuse("invalid_signature", "Signature-Key header missing or malformed")
            label, scheme, params = members[0]
            if scheme != "jwks_uri":
                raise _refuse("unsupported_scheme",
                              f"scheme {scheme!r}; servers sign under jwks_uri",
                              accept_schemes=("jwks_uri",))
            dwk = str(params.get("dwk") or "")
            if dwk not in allowed_dwk:
                raise _refuse("invalid_key", f"dwk {dwk!r} is not accepted here")
            return await self._verify_server_scheme(method, url, hdrs, body, label, params)
        except _Refused as exc:
            logger.info("httpsig server refused: %s %s", exc.error.code, exc.error.detail[:160])
            return exc.error
        except Exception as exc:  # noqa: BLE001
            logger.warning("httpsig server verify error: %s", str(exc)[:200])
            return VerificationError("invalid_signature", "verifier error")

    async def aclose(self) -> None:
        if self._owns_client and self._http is not None:
            await self._http.aclose()
            self._http = None

    # ── directory fetching (SSRF-guarded, cached) ────────────────────────────

    def _cache_get(self, url: str) -> tuple[bool, dict[str, Any] | None]:
        entry = self._cache.get(url)
        if entry and entry[0] > time.monotonic():
            return True, entry[1]
        return False, None

    def _cache_put(self, url: str, doc: dict[str, Any] | None, ttl: float) -> None:
        if len(self._cache) >= self.config.cache_max_entries:
            # Evict the soonest-to-expire entry; bounds memory against keyid spam.
            self._cache.pop(min(self._cache, key=lambda k: self._cache[k][0]), None)
        self._cache[url] = (time.monotonic() + ttl, doc)

    def _cache_forget(self, url: str) -> None:
        self._cache.pop(url, None)

    async def _fetch_json(self, url: str) -> dict[str, Any] | None:
        """Fetch an attacker-nameable identity document safely: https-only
        (except allow-listed dev hosts), public-IP-only, size-capped, cached."""
        cfg = self.config
        hit, doc = self._cache_get(url)
        if hit:
            return doc
        try:
            parsed = urlsplit(url)
            if parsed.scheme != "https" and parsed.hostname not in cfg.insecure_hosts:
                raise NotPublicURL("identity directories must be https")
            await assert_public_url(url, cfg.insecure_hosts)
            if self._http is None:
                self._http = httpx.AsyncClient()
            resp = await self._http.get(
                url,
                timeout=cfg.fetch_timeout,
                follow_redirects=False,
                headers={"accept": "application/json"},
            )
            resp.raise_for_status()
            if len(resp.content) > cfg.max_directory_bytes:
                raise ValueError("directory too large")
            doc = resp.json()
            if not isinstance(doc, dict):
                raise ValueError("directory is not a JSON object")
        except Exception as exc:  # noqa: BLE001 — any failure = unverifiable, not fatal
            logger.info("directory fetch failed url=%s: %s", url, str(exc)[:200])
            self._cache_put(url, None, cfg.negative_cache_ttl)
            return None
        self._cache_put(url, doc, cfg.cache_ttl)
        return doc

    async def _jwks_key(self, jwks_url: str, kid: str | None) -> dict[str, Any]:
        """The JWK with ``kid`` from the JWKS at ``jwks_url``; on an unknown kid the
        document is refetched once (key rotation, §11.4). A JWKS of exactly one
        key serves a header that names no kid."""
        for attempt in (0, 1):
            jwks = await self._fetch_json(jwks_url)
            keys = list((jwks or {}).get("keys") or [])[:10]
            if kid is None and len(keys) == 1 and isinstance(keys[0], dict):
                return keys[0]
            for k in keys:
                if isinstance(k, dict) and k.get("kid") == kid:
                    return k
            if attempt == 0:
                self._cache_forget(jwks_url)
        raise _refuse("unknown_key", f"kid {kid!r} is not in the issuer's JWKS")

    async def _issuer_jwks_url(self, iss: str, dwk: str, *, override: str | None = None) -> str:
        """Resolve ``{iss}/.well-known/{dwk}`` to its ``jwks_uri`` (§11.4), checking
        the document's ``issuer`` against ``iss`` (issuer_missing / issuer_mismatch)."""
        if override:
            return override
        metadata = await self._fetch_json(iss.rstrip("/") + "/.well-known/" + dwk)
        if not metadata:
            raise _refuse("issuer_missing",
                          f"metadata at {iss}/.well-known/{dwk} is unavailable")
        issuer = metadata.get("issuer")
        if not isinstance(issuer, str) or not issuer:
            raise _refuse("issuer_missing", "metadata document has no issuer")
        if issuer != iss:
            raise _refuse("issuer_mismatch",
                          "metadata issuer differs from the identity it was fetched under")
        jwks_url = metadata.get("jwks_uri")
        if not isinstance(jwks_url, str) or not jwks_url:
            raise _refuse("issuer_missing", "metadata document has no jwks_uri")
        return jwks_url

    # ── Web Bot Auth ─────────────────────────────────────────────────────────

    async def _verify_web_bot_auth(
        self, method: str, url: str, headers: dict[str, str]
    ) -> VerifiedSignature | None:
        message = Message(method, url, headers)
        agent_header = message.headers.get("signature-agent")
        if not agent_header:
            return None  # no directory to verify against — can't establish identity
        origin = parse_signature_agent(agent_header)
        if not origin or not origin.startswith(("https://", "http://")):
            return None
        directory = await self._fetch_json(origin.rstrip("/") + WBA_DIRECTORY_PATH)
        if not directory:
            return None
        keys = _keys_from_jwks(directory)
        if not keys:
            return None

        verifier = HTTPMessageVerifier(
            signature_algorithm=ED25519,
            key_resolver=StaticKeyResolver(keys),
            component_resolver_class=DictKeyComponentResolver,
        )
        try:
            results = await asyncio.to_thread(
                verifier.verify,
                message,
                max_age=timedelta(hours=self.config.max_age_hours),
                expect_tag=WBA_TAG,
            )
        except Exception as exc:  # noqa: BLE001 — invalid signature = unverified
            logger.info("web-bot-auth invalid agent=%s: %s", origin, str(exc)[:200])
            return None
        if not results:
            return None
        res = results[0]
        return VerifiedSignature(
            scheme=WBA_TAG,
            agent=origin,
            keyid=str(res.parameters.get("keyid", "")),
            trusted=origin in self.config.trusted_agents,
            label=str(res.label),
        )

    # ── AAuth: the Signature-Key header (§11.3) ──────────────────────────────

    async def _verify_signature_key(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None,
    ) -> VerifiedSignature:
        members = parse_signature_key(_header(headers, "signature-key"))
        if not members:
            raise _refuse("invalid_signature", "Signature-Key header is malformed")
        label, scheme, params = members[0]
        if scheme == "jwt":
            return await self._verify_jwt_scheme(method, url, headers, body, label, params)
        if scheme == "jwks_uri":
            return await self._verify_server_scheme(method, url, headers, body, label, params)
        raise _refuse("unsupported_scheme", f"scheme {scheme!r} is not accepted",
                      accept_schemes=AAUTH_ACCEPT_SCHEMES)

    def _check_signature_input(
        self, headers: dict[str, str], label: str, body: bytes | None,
    ) -> None:
        """§11.3.3.1 covered components, §11.3.4 step 3 `created` window, `expires`."""
        inputs = parse_signature_input(_header(headers, "signature-input"))
        if label not in inputs:
            raise _refuse("invalid_signature", f"Signature-Input has no member {label!r}")
        covered, params = inputs[label]
        required = list(self.config.required_components)
        has_body = bool(body) or bool(_header(headers, "content-digest"))
        if has_body:
            required += ["content-digest", "content-type"]
        missing = [c for c in required if c not in covered]
        if missing:
            raise _refuse("invalid_input", f"signature does not cover {', '.join(missing)}",
                          required_input=tuple(required))
        now = int(time.time())
        window = int(self.config.signature_window_seconds)
        created = params.get("created")
        if not isinstance(created, int):
            raise _refuse("invalid_signature", "created parameter is required")
        if created > now + window:
            raise _refuse("clock_skew", "signature created ahead of the server's clock")
        if created < now - window:
            raise _refuse("invalid_signature", "signature created outside the validity window")
        expires = params.get("expires")
        if isinstance(expires, int) and expires < now:
            raise _refuse("invalid_signature", "signature has expired")
        if body:
            digest = _header(headers, "content-digest")
            expected = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
            if digest.replace(" ", "") != expected:
                raise _refuse("invalid_signature", "Content-Digest does not match the body")

    async def _verify_pop(
        self, method: str, url: str, headers: dict[str, str], label: str,
        key: Any, algorithm: Any, detail: str,
    ) -> None:
        """Verify the HTTP Message Signature labelled ``label`` with ``key``."""
        message = Message(method, url, headers)
        verifier = _KeyidOptionalVerifier(
            signature_algorithm=algorithm,
            key_resolver=StaticKeyResolver({}, default=key),
            component_resolver_class=DictKeyComponentResolver,
        )
        try:
            # created/expires were judged above against the -11 window; the
            # library's own max_age is set wide so it cannot pre-empt our codes.
            results = await asyncio.to_thread(
                verifier.verify, message, max_age=timedelta(days=365),
            )
        except Exception as exc:  # noqa: BLE001
            raise _refuse("invalid_signature", f"{detail}: {str(exc)[:120]}") from exc
        if not any(str(r.label) == label for r in results):
            raise _refuse("invalid_signature", f"no verified signature labelled {label!r}")

    async def _verify_jwt_scheme(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None,
        label: str, params: dict[str, Any],
    ) -> VerifiedSignature:
        try:
            import jwt as pyjwt  # the [aauth] extra
        except ImportError as exc:
            raise _refuse("unsupported_scheme",
                          "pyjwt is not installed (pip install 'regent-httpsig[aauth]')",
                          accept_schemes=("jwks_uri",)) from exc
        token = str(params.get("jwt") or "")
        if not token:
            raise _refuse("invalid_jwt", "jwt parameter is empty")
        self._check_signature_input(headers, label, body)
        _register_fully_specified_algs()
        try:
            header = pyjwt.get_unverified_header(token)
            unverified = pyjwt.decode(token, options={"verify_signature": False})
        except Exception as exc:  # noqa: BLE001
            raise _refuse("invalid_jwt", "token is malformed") from exc

        typ = header.get("typ")
        try:
            return await self._verify_jwt_token(method, url, headers, label, token,
                                                header, unverified, typ)
        except _Refused as exc:
            exc.error.token_typ = typ if isinstance(typ, str) else None
            raise

    async def _verify_jwt_token(
        self, method: str, url: str, headers: dict[str, str], label: str,
        token: str, header: dict[str, Any], unverified: dict[str, Any], typ: Any,
    ) -> VerifiedSignature:
        import jwt as pyjwt

        # §11.5.2 step 1: typ first.
        cfg = self.config
        jwks_override: str | None = None
        expected_dwks: tuple[str, ...]
        audience: str | None = None
        if typ == AAUTH_JWT_TYP:
            scheme, expected_dwks = "aauth", ("aauth-agent.json",)
        elif typ == AAUTH_PERSON_TYP:
            if not cfg.resource_url:
                raise _refuse("invalid_key",
                              "person tokens are not accepted here (resource_url unset)")
            scheme, expected_dwks = "aauth-person", ("aauth-person.json",)
            audience = cfg.resource_url
        elif typ == AAUTH_AUTH_TYP:
            if not cfg.resource_url or not cfg.trusted_ps:
                raise _refuse("invalid_key",
                              "auth tokens are not accepted here (resource_url/trusted_ps unset)")
            scheme, expected_dwks = "aauth-auth", ("aauth-person.json", "aauth-access.json")
            audience = cfg.resource_url
        else:
            raise _refuse("invalid_jwt", f"typ {typ!r} is not an AAuth token type")

        alg = header.get("alg")
        allowed = list(AAUTH_ACCEPT_ALGS)
        if not cfg.require_fully_specified_algs:
            allowed.append("EdDSA")
        if alg not in allowed:
            raise _refuse("unsupported_algorithm", f"token alg {alg!r}",
                          accept_algs=AAUTH_ACCEPT_ALGS)

        iss = str(unverified.get("iss") or "")
        dwk = str(unverified.get("dwk") or "")
        dev = bool(iss) and urlsplit(iss).hostname in cfg.insecure_hosts
        if not iss or (not iss.startswith("https://") and not dev):
            raise _refuse("invalid_jwt", "iss is not an https server identifier")
        if dwk not in expected_dwks:
            raise _refuse("invalid_jwt", f"dwk {dwk!r} is not {' or '.join(expected_dwks)}")
        if typ == AAUTH_AUTH_TYP:
            # The resource pins its PS/AS: the issuer must be configured.
            override = cfg.trusted_ps.get(iss)
            if override is None:
                raise _refuse("invalid_key", f"issuer {iss} is not a configured PS/AS")
            jwks_override = override or None

        # 1) The issuer's key, discovered through its metadata (or the pinned URL).
        jwks_url = await self._issuer_jwks_url(iss, dwk, override=jwks_override)
        issuer_jwk = await self._jwks_key(jwks_url, header.get("kid"))
        key_alg = issuer_jwk.get("alg")
        if cfg.require_fully_specified_algs and key_alg != alg:
            raise _refuse("unsupported_algorithm", f"issuer key alg {key_alg!r} is not {alg}",
                          accept_algs=AAUTH_ACCEPT_ALGS)
        try:
            if key_alg in (None, "EdDSA") or alg == "Ed25519":
                issuer_key: Any = load_ed25519_jwk(issuer_jwk)
            else:
                issuer_key = pyjwt.PyJWK({k: v for k, v in issuer_jwk.items() if k != "alg"}).key
        except Exception as exc:  # noqa: BLE001
            raise _refuse("invalid_key", "issuer key cannot be parsed") from exc

        # 2) The token itself: signature, exp with no tolerance, iat bound by the window.
        try:
            claims = pyjwt.decode(
                token, key=issuer_key, algorithms=[alg], audience=audience,
                options={"require": ["iss", "sub", "exp", "iat"],
                         "verify_aud": audience is not None,
                         "verify_iat": False, "verify_exp": False},
            )
        except Exception as exc:  # noqa: BLE001
            raise _refuse("invalid_jwt", f"token does not verify: {str(exc)[:120]}") from exc
        now = int(time.time())
        window = int(cfg.signature_window_seconds)
        try:
            exp, iat = int(claims["exp"]), int(claims["iat"])
        except (TypeError, ValueError) as exc:
            raise _refuse("invalid_jwt", "exp/iat are not integers") from exc
        if exp <= now:
            raise _refuse("expired_jwt", "token exp is in the past")
        if iat > now + window:
            raise _refuse("clock_skew", "token iat is ahead of the server's clock")
        lifetime = exp - iat
        short_lived = typ in (AAUTH_PERSON_TYP, AAUTH_AUTH_TYP)
        if short_lived and not 0 < lifetime <= PERSON_TOKEN_MAX_LIFETIME:
            raise _refuse("invalid_jwt", f"{typ} lifetime {lifetime}s exceeds one hour")
        jti = claims.get("jti")
        if (self._is_revoked is not None and isinstance(jti, str) and jti
                and await self._is_revoked(iss, jti)):
            raise _refuse("revoked_jwt", "the issuer has withdrawn this token")

        # 3) Proof of possession: the request signature must verify against cnf.jwk.
        cnf_jwk = (claims.get("cnf") or {}).get("jwk")
        if not isinstance(cnf_jwk, dict):
            raise _refuse("invalid_key", "token carries no cnf.jwk")
        if not cfg.require_fully_specified_algs and "alg" not in cnf_jwk:
            cnf_jwk = {**cnf_jwk, "alg": "Ed25519"}
        pop_key, algorithm = _load_public_key(cnf_jwk)
        await self._verify_pop(method, url, headers, label, pop_key, algorithm,
                               "proof of possession failed")

        return VerifiedSignature(
            scheme=scheme,
            agent=iss,
            keyid=jwk_thumbprint(cnf_jwk),
            # An auth-token issuer is by definition a configured, trusted PS/AS.
            trusted=iss in cfg.trusted_agents or typ == AAUTH_AUTH_TYP,
            sub=str(claims.get("sub", "")),
            label=label,
            claims={
                k: claims[k]
                for k in ("iss", "sub", "exp", "iat", "ps", "aud", "jti", "dwk", "mission_s256",
                          "tenant", "budget")  # budgets: the envelope rides in the token
                if k in claims
            },
        )

    async def _verify_server_scheme(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None,
        label: str, params: dict[str, Any],
    ) -> VerifiedSignature:
        """§11.3.2 / Signature-Key §3.6: ``sig=jwks_uri;id=…;dwk=…;kid=…``."""
        server_id = str(params.get("id") or "")
        dwk = str(params.get("dwk") or "")
        kid = params.get("kid")
        cfg = self.config
        dev = bool(server_id) and urlsplit(server_id).hostname in cfg.insecure_hosts
        if not server_id or (not server_id.startswith("https://") and not dev):
            raise _refuse("invalid_key", "id is not an https server identifier")
        if dwk not in SERVER_DWKS:
            raise _refuse("invalid_key", f"dwk {dwk!r} is not an AAuth metadata document")
        if not isinstance(kid, str) or not kid:
            raise _refuse("invalid_key", "kid is required under the jwks_uri scheme")
        self._check_signature_input(headers, label, body)
        override = cfg.trusted_ps.get(server_id)
        jwks_url = await self._issuer_jwks_url(server_id, dwk, override=override or None)
        jwk = await self._jwks_key(jwks_url, kid)
        key, algorithm = _load_public_key(jwk)
        await self._verify_pop(method, url, headers, label, key, algorithm,
                               "server signature failed")
        return VerifiedSignature(
            scheme="aauth-server",
            agent=server_id,
            keyid=kid,
            trusted=server_id in cfg.trusted_ps or server_id in cfg.trusted_agents,
            label=label,
            claims={"iss": server_id, "dwk": dwk, "kid": kid},
        )


def _header(headers: Mapping[str, str], name: str) -> str:
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            return v
    return ""
