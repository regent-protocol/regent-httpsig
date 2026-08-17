"""RFC 9421 plumbing over the ``http-message-signatures`` library.

Contains the pieces the upstream library is missing for the AI-agent profiles:

- :class:`DictKeyComponentResolver` — RFC 9421 §2.1.2 ``;key=`` dictionary-member
  selection (needed for the current Web Bot Auth ``"signature-agent";key="agent2"``
  covered component; upstream resolves whole header values only).
- :func:`parse_signature_agent` — both wire forms of ``Signature-Agent``:
  the draft -05 sf-dictionary AND the legacy bare sf-string OpenAI ships today.
- :class:`Message` / :class:`StaticKeyResolver` — the minimal request shape and
  key resolution the verifier needs.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from http_message_signatures import (  # type: ignore[attr-defined]
    HTTPSignatureComponentResolver,
    HTTPSignatureKeyResolver,
    algorithms,
    http_sfv,
)
from http_message_signatures.structures import CaseInsensitiveDict

__all__ = [
    "ED25519",
    "CaseInsensitiveDict",
    "DictKeyComponentResolver",
    "Message",
    "SFDictionary",
    "SFItem",
    "StaticKeyResolver",
    "parse_signature_agent",
    "parse_signature_key_header",
]

# The library ships no explicit re-exports (strict mypy: attr-defined) — alias once.
SFDictionary = http_sfv.Dictionary  # type: ignore[attr-defined]
SFItem = http_sfv.Item  # type: ignore[attr-defined]
ED25519 = algorithms.ED25519  # type: ignore[attr-defined]


class Message:
    """The minimal request shape http-message-signatures needs (.method/.url/.headers).

    ``headers`` is wrapped in the library's own case-insensitive mapping — ASGI
    frameworks lowercase header names, and the upstream verifier looks up
    ``Signature-Input`` case-sensitively."""

    def __init__(self, method: str, url: str, headers: dict[str, str]):
        self.method = method
        self.url = url
        self.headers = CaseInsensitiveDict(headers)  # type: ignore[no-untyped-call]


class DictKeyComponentResolver(HTTPSignatureComponentResolver):
    """Adds RFC 9421 §2.1.2 ``;key=`` dictionary-member selection for header
    components (the upstream resolver returns the whole header value only).
    Needed for the current Web Bot Auth form: ``"signature-agent";key="agent2"``
    must resolve to the serialized member value (e.g. ``"https://…"``)."""

    def resolve(self, component_node: Any) -> Any:  # http_sfv Item (untyped lib)
        component_id = str(component_node.value)
        key = component_node.params.get("key")
        if key is not None and not component_id.startswith("@"):
            if component_id not in self.headers:
                raise ValueError(f'covered header "{component_id}" not in message')
            node = SFDictionary()
            node.parse(self.headers[component_id].encode())
            if key not in node:
                raise ValueError(f'member "{key}" not in dictionary header "{component_id}"')
            return str(node[key])
        return super().resolve(component_node)


class StaticKeyResolver(HTTPSignatureKeyResolver):
    """Resolves keyids from a prefetched map; ``default`` (AAuth cnf.jwk) wins
    when the map has no entry — the possession key comes from the token, not
    from the wire keyid."""

    def __init__(
        self,
        keys: dict[str, Ed25519PublicKey],
        default: Ed25519PublicKey | None = None,
    ):
        self._keys = keys
        self._default = default

    def resolve_public_key(self, key_id: str) -> Ed25519PublicKey:
        key = self._keys.get(key_id, self._default)
        if key is None:
            raise ValueError(f"unknown keyid {key_id!r}")
        return key

    def resolve_private_key(self, key_id: str) -> Any:
        raise NotImplementedError


def parse_signature_agent(value: str) -> str | None:
    """Extract the directory origin from ``Signature-Agent`` — sf-dictionary
    (draft -05) or bare sf-string (legacy, what OpenAI sends)."""
    value = value.strip()
    if not value:
        return None
    try:
        if value.startswith('"'):
            item = SFItem()
            item.parse(value.encode())
            return str(item.value)
        node = SFDictionary()
        node.parse(value.encode())
        for member in node.values():
            return str(member.value)
    except Exception:  # noqa: BLE001 — malformed header = no directory
        return None
    return None


def parse_signature_key_header(value: str) -> tuple[str, str] | None:
    """``Signature-Key: sig=jwt;jwt="eyJ…"`` → (label, jwt) — the AAuth carrier."""
    try:
        node = SFDictionary()
        node.parse(value.encode())
        for label, member in node.items():
            jwt_param = member.params.get("jwt")
            if jwt_param:
                return str(label), str(jwt_param)
    except Exception:  # noqa: BLE001
        return None
    return None
