"""Outbound RFC 9421 signing (Web Bot Auth) — give your agent a verifiable identity.

Sign every request your agent makes with an Ed25519 key whose public half you
publish at ``{signature_agent}/.well-known/http-message-signatures-directory``.
Verifiers that speak Web Bot Auth (Cloudflare, AWS WAF, Vercel, this library…)
then see a *signed agent* instead of an anonymous bot.

The ``Signature-Agent`` header is emitted in the LEGACY sf-string form
(``"https://…"``) — the form OpenAI ships in production, accepted by every
deployed verifier today; the draft -05 sf-dictionary form still has patchy
support.

Unlike a service-level integration, this library FAILS LOUD: a bad seed raises
at construction and a signing error raises from :meth:`EgressSigner.sign`.
Wrap in try/except yourself if your egress path must never break on signing.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from http_message_signatures import (  # type: ignore[attr-defined]
    HTTPMessageSigner,
    HTTPSignatureKeyResolver,
)

from regent_httpsig.jwk import b64url, b64url_decode, jwk_thumbprint
from regent_httpsig.sfv import ED25519, Message

__all__ = ["DIRECTORY_MEDIA_TYPE", "EgressSigner", "generate_seed"]

DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
_DEFAULT_COVERED = ("@method", "@authority", "@path", "signature-agent")


def generate_seed() -> str:
    """A fresh Ed25519 seed, base64url-encoded — store it like any secret."""
    return b64url(secrets.token_bytes(32))


class _Resolver(HTTPSignatureKeyResolver):
    def __init__(self, key: Ed25519PrivateKey):
        self._key = key

    def resolve_private_key(self, key_id: str) -> Ed25519PrivateKey:
        return self._key

    def resolve_public_key(self, key_id: str) -> Any:
        raise NotImplementedError


class EgressSigner:
    """Sign outbound requests as a Web Bot Auth agent.

    Usage::

        signer = EgressSigner(seed=os.environ["AGENT_KEY_SEED"],
                              signature_agent="https://myagent.example")
        headers = signer.sign("POST", url, {"content-type": "application/json"})
        httpx.post(url, json=body, headers=headers)

    Publish ``signer.directory()`` as JSON at
    ``https://myagent.example/.well-known/http-message-signatures-directory``
    (or run ``regent-httpsig keygen`` to generate both the seed and the files).
    """

    def __init__(self, *, seed: str, signature_agent: str, ttl_minutes: int = 5):
        raw = b64url_decode(seed)
        if len(raw) != 32:
            raise ValueError("seed must be 32 bytes (base64url-encoded)")
        self._key = Ed25519PrivateKey.from_private_bytes(raw)
        self.signature_agent = signature_agent
        self._ttl = ttl_minutes
        self._jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url(self._key.public_key().public_bytes_raw()),
        }
        self.keyid = jwk_thumbprint(self._jwk)

    @property
    def public_jwk(self) -> dict[str, Any]:
        return dict(self._jwk)

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
        """Return ``headers`` + ``Signature-Agent``/``Signature-Input``/``Signature``."""
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
