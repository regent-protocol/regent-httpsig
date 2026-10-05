"""Outbound RFC 9421 signing — give your agent (or your server) a verifiable identity.

Three signers, one key format (a 32-byte Ed25519 seed, base64url):

- :class:`EgressSigner` signs as a **Web Bot Auth** agent: ``tag="web-bot-auth"``,
  key published at ``{signature_agent}/.well-known/http-message-signatures-directory``.
  Verifiers that speak Web Bot Auth (Cloudflare, AWS WAF, Vercel, this library…)
  then see a *signed agent* instead of an anonymous bot. The ``Signature-Agent``
  header is emitted in the LEGACY sf-string form (``"https://…"``) — the form
  OpenAI ships in production, accepted by every deployed verifier today.
- :meth:`EgressSigner.sign_aauth` signs as an **AAuth** agent (-11 §11.3.3): the
  token rides in ``Signature-Key`` under the ``jwt`` scheme, the signature covers
  ``@method @authority @path signature-key`` (plus ``content-digest`` and
  ``content-type`` when there is a body), ``created`` only — no ``keyid``, no
  ``tag``, no ``alg`` parameter (the key comes from the token's ``cnf.jwk``).
- :class:`ServerSigner` signs as an AAuth **server** (-11 §11.3.2): a PS or AS
  calling a resource's usage or revocation endpoint, under the ``jwks_uri``
  scheme with ``id``, ``dwk`` and ``kid``.

Unlike a service-level integration, this library FAILS LOUD: a bad seed raises
at construction and a signing error raises from the ``sign`` methods. Wrap in
try/except yourself if your egress path must never break on signing.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from http_message_signatures import (  # type: ignore[attr-defined]
    HTTPMessageSigner,
    HTTPSignatureKeyResolver,
)

from regent_httpsig.config import AAUTH_REQUIRED_COMPONENTS
from regent_httpsig.jwk import b64url, b64url_decode, jwk_thumbprint
from regent_httpsig.sfv import ED25519, Message

__all__ = [
    "DIRECTORY_MEDIA_TYPE",
    "EgressSigner",
    "ServerSigner",
    "content_digest",
    "generate_seed",
    "sign_request",
]

DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
_DEFAULT_COVERED = ("@method", "@authority", "@path", "signature-agent")
_BODY_COMPONENTS = ("content-digest", "content-type")


def generate_seed() -> str:
    """A fresh Ed25519 seed, base64url-encoded — store it like any secret."""
    return b64url(secrets.token_bytes(32))


def content_digest(body: bytes) -> str:
    """RFC 9530 ``Content-Digest`` value for ``body`` (sha-256, sf-byte-sequence)."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _load_seed(seed: str) -> Ed25519PrivateKey:
    raw = b64url_decode(seed)
    if len(raw) != 32:
        raise ValueError("seed must be 32 bytes (base64url-encoded)")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _ed25519_jwk(key: Ed25519PrivateKey) -> dict[str, Any]:
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(key.public_key().public_bytes_raw())}


# ── RFC 9421 signature base, request side ─────────────────────────────────────


def _field(headers: Mapping[str, str], name: str) -> str:
    """RFC 9421 §2.1: the field value, whitespace trimmed, instances joined by ', '."""
    values = [v.strip() for k, v in headers.items() if k.lower() == name]
    if not values:
        raise ValueError(f'covered header "{name}" is not in the message')
    return ", ".join(values)


def _derived(name: str, method: str, url: str) -> str:
    parts = urlsplit(url)
    if name == "@method":
        return method.upper()
    if name == "@authority":
        host = (parts.hostname or "").lower()
        port = parts.port
        default = {"https": 443, "http": 80}.get(parts.scheme)
        return host if port is None or port == default else f"{host}:{port}"
    if name == "@path":
        return parts.path or "/"
    if name == "@query":
        return "?" + parts.query
    if name == "@target-uri":
        return url
    if name == "@scheme":
        return parts.scheme
    raise ValueError(f"unsupported derived component {name!r}")


def _signature_base(method: str, url: str, headers: Mapping[str, str],
                    covered: tuple[str, ...], params: str) -> str:
    lines = []
    for component in covered:
        value = (_derived(component, method, url) if component.startswith("@")
                 else _field(headers, component))
        lines.append(f'"{component}": {value}')
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def _raw_sign(key: Any, data: bytes) -> bytes:
    """RFC 9421 §3.3 signature bytes: Ed25519 raw, ECDSA as raw ``r || s``."""
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(data)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        size = (key.curve.key_size + 7) // 8
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    raise TypeError("key must be an Ed25519 or EC private key")


def sign_request(
    key: Any,
    method: str,
    url: str,
    headers: Mapping[str, str],
    *,
    covered: tuple[str, ...],
    label: str = "sig",
    created: int | None = None,
    expires: int | None = None,
) -> dict[str, str]:
    """Sign ``(method, url, headers)`` the AAuth way: the covered components as
    given, ``created`` (and ``expires`` if asked), no ``keyid``/``alg``/``tag``.
    Returns ``headers`` plus ``Signature-Input`` and ``Signature``. Every
    covered header must already be present (``Signature-Key``, ``Content-Digest``,
    ``Content-Type``…) — the caller adds them first."""
    created = int(created if created is not None else time.time())
    inner = "(" + " ".join(f'"{c}"' for c in covered) + f");created={created}"
    if expires is not None:
        inner += f";expires={int(expires)}"
    base = _signature_base(method, url, headers, covered, inner)
    signature = base64.b64encode(_raw_sign(key, base.encode())).decode()
    out = dict(headers)
    out["Signature-Input"] = f"{label}={inner}"
    out["Signature"] = f"{label}=:{signature}:"
    return out


def _covered_for(body: bytes | None, headers: Mapping[str, str]) -> tuple[str, ...]:
    has_body = body is not None and len(body) > 0
    return AAUTH_REQUIRED_COMPONENTS + (_BODY_COMPONENTS if has_body else ())


def _with_body(headers: dict[str, str], body: bytes | None) -> dict[str, str]:
    if body:
        headers["Content-Digest"] = content_digest(body)
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/json"
    return headers


# ── Web Bot Auth / AAuth agent ────────────────────────────────────────────────


class _Resolver(HTTPSignatureKeyResolver):
    def __init__(self, key: Ed25519PrivateKey):
        self._key = key

    def resolve_private_key(self, key_id: str) -> Ed25519PrivateKey:
        return self._key

    def resolve_public_key(self, key_id: str) -> Any:
        raise NotImplementedError


class EgressSigner:
    """Sign outbound requests as an agent — Web Bot Auth (:meth:`sign`) or
    AAuth (:meth:`sign_aauth`) with the same Ed25519 key.

    Usage::

        signer = EgressSigner(seed=os.environ["AGENT_KEY_SEED"],
                              signature_agent="https://myagent.example")
        headers = signer.sign("POST", url, {"content-type": "application/json"})
        httpx.post(url, json=body, headers=headers)

    Publish ``signer.directory()`` as JSON at
    ``https://myagent.example/.well-known/http-message-signatures-directory``
    (or run ``regent-httpsig keygen`` to generate both the seed and the files).
    For AAuth, register ``signer.public_jwk`` as the ``cnf.jwk`` of your agent
    token and call :meth:`sign_aauth` with the token.
    """

    def __init__(self, *, seed: str, signature_agent: str, ttl_minutes: int = 5):
        self._key = _load_seed(seed)
        self.signature_agent = signature_agent
        self._ttl = ttl_minutes
        self._jwk = _ed25519_jwk(self._key)
        self.keyid = jwk_thumbprint(self._jwk)

    @property
    def public_jwk(self) -> dict[str, Any]:
        """The public key as a JWK with a fully-specified ``alg`` (RFC 9864) —
        what an AAuth token's ``cnf.jwk`` must carry under -11."""
        return {**self._jwk, "alg": "Ed25519"}

    def directory(self) -> dict[str, Any]:
        """The JWKS document to serve at
        ``/.well-known/http-message-signatures-directory``."""
        return {
            "keys": [{**self._jwk, "kid": self.keyid, "use": "sig", "alg": "EdDSA"}]
        }

    def sign(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        covered: tuple[str, ...] = _DEFAULT_COVERED,
        label: str = "sig1",
    ) -> dict[str, str]:
        """Web Bot Auth: ``headers`` + ``Signature-Agent``/``Signature-Input``/``Signature``."""
        out = dict(headers or {})
        out["Signature-Agent"] = f'"{self.signature_agent}"'  # legacy sf-string form
        message = Message(method.upper(), url, out)
        signer = HTTPMessageSigner(
            signature_algorithm=ED25519, key_resolver=_Resolver(self._key)
        )
        now = datetime.now()
        signer.sign(
            message,
            key_id=self.keyid,
            label=label,
            tag="web-bot-auth",
            created=now,
            expires=now + timedelta(minutes=self._ttl),
            covered_component_ids=covered,
        )
        return dict(message.headers)

    def sign_aauth(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        token: str,
        body: bytes | None = None,
        label: str = "sig",
        created: int | None = None,
    ) -> dict[str, str]:
        """AAuth -11 §11.3.3: carry ``token`` (an agent, person or auth token
        whose ``cnf.jwk`` is this signer's key) in ``Signature-Key`` under the
        ``jwt`` scheme and sign ``@method @authority @path signature-key`` —
        plus ``content-digest content-type`` when ``body`` is given, with
        ``Content-Digest`` computed here. Send ``body`` exactly as passed."""
        out = _with_body(dict(headers or {}), body)
        out["Signature-Key"] = f'{label}=jwt;jwt="{token}"'
        return sign_request(self._key, method, url, out,
                            covered=_covered_for(body, out), label=label, created=created)


# ── AAuth server (PS / AS / resource calling another server) ──────────────────


class ServerSigner:
    """Sign requests as an AAuth server under the ``jwks_uri`` scheme (-11
    §11.3.2): ``Signature-Key: sig=jwks_uri;id="<server_id>";dwk="<dwk>";kid="…"``.
    The recipient fetches ``{server_id}/.well-known/{dwk}``, follows its
    ``jwks_uri`` and finds ``kid`` — serve :meth:`jwks` there.

    ``dwk`` names the metadata document you publish: ``aauth-person.json`` for
    a PS, ``aauth-access.json`` for an AS, ``aauth-resource.json`` for a
    resource, ``aauth-agent.json`` for an agent provider.
    """

    def __init__(self, *, seed: str, server_id: str, dwk: str,
                 kid: str | None = None, label: str = "sig") -> None:
        self._key = _load_seed(seed)
        self.server_id = server_id.rstrip("/")
        self.dwk = dwk
        self.label = label
        self._jwk = _ed25519_jwk(self._key)
        self.keyid = kid or jwk_thumbprint(self._jwk)

    @property
    def public_jwk(self) -> dict[str, Any]:
        return {**self._jwk, "kid": self.keyid, "alg": "Ed25519", "use": "sig"}

    def jwks(self) -> dict[str, Any]:
        """The JWKS to serve at your metadata document's ``jwks_uri``."""
        return {"keys": [self.public_jwk]}

    def signature_key_header(self) -> str:
        return (f'{self.label}=jwks_uri;id="{self.server_id}";'
                f'dwk="{self.dwk}";kid="{self.keyid}"')

    def sign(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        body: bytes | None = None,
        created: int | None = None,
    ) -> dict[str, str]:
        """Return ``headers`` + ``Signature-Key``/``Signature-Input``/``Signature``
        (+ ``Content-Digest`` when ``body`` is given)."""
        out = _with_body(dict(headers or {}), body)
        out["Signature-Key"] = self.signature_key_header()
        return sign_request(self._key, method, url, out,
                            covered=_covered_for(body, out), label=self.label, created=created)
