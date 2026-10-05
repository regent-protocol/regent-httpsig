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
    "build_aauth_budget_header",
    "build_aauth_requirement",
    "build_person_token_requirement",
    "parse_signature_agent",
    "parse_signature_input",
    "parse_signature_key",
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


def _plain(value: Any) -> Any:
    """An sf-value as a plain Python value (Token/String → str, Integer → int)."""
    if isinstance(value, (int, str, bool)):
        return value
    try:
        inner = getattr(value, "value", value)
        return inner if isinstance(inner, (int, str, bool)) else str(inner)
    except Exception:  # noqa: BLE001
        return str(value)


def parse_signature_key(value: str) -> list[tuple[str, str, dict[str, Any]]]:
    """``Signature-Key`` (draft-hardt-httpbis-signature-key) → one
    ``(label, scheme, params)`` per member, in header order. The member's bare
    item is the scheme token (``jwt``, ``jwks_uri``, ``hwk``, …); its parameters
    are returned as plain values. Malformed header → ``[]``."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    try:
        node = SFDictionary()
        node.parse(value.encode())
        for label, member in node.items():
            scheme = _plain(getattr(member, "value", member))
            params = {str(k): _plain(v) for k, v in member.params.items()}
            out.append((str(label), str(scheme), params))
    except Exception:  # noqa: BLE001
        return []
    return out


def parse_signature_key_header(value: str) -> tuple[str, str] | None:
    """``Signature-Key: sig=jwt;jwt="eyJ…"`` → (label, jwt) — the AAuth carrier.
    Kept for callers of 0.6; :func:`parse_signature_key` sees every scheme."""
    for label, scheme, params in parse_signature_key(value):
        if scheme == "jwt" and params.get("jwt"):
            return label, str(params["jwt"])
    return None


def parse_signature_input(value: str) -> dict[str, tuple[list[str], dict[str, Any]]]:
    """``Signature-Input`` (RFC 9421 §4.1) → ``{label: (covered components, params)}``.
    Components come back as their identifiers (``@method``, ``content-digest``,
    ``"signature-agent";key="agent2"`` → ``signature-agent``); params as plain values."""
    out: dict[str, tuple[list[str], dict[str, Any]]] = {}
    try:
        node = SFDictionary()
        node.parse(value.encode())
        for label, member in node.items():
            # An InnerList is a UserList of Items; a bare Item is not a valid member here.
            items = list(member) if hasattr(member, "data") else []
            covered = [str(_plain(getattr(item, "value", item))) for item in items]
            params = {str(k): _plain(v) for k, v in member.params.items()}
            out[str(label)] = (covered, params)
    except Exception:  # noqa: BLE001
        return {}
    return out


def build_person_token_requirement() -> str:
    """``AAuth-Requirement: requirement=person-token`` (-11 §6.4): what a resource
    answers a revoked or expired auth token with. The header takes no parameters."""
    return "requirement=person-token"


# ── AAuth Budgets response headers (draft-hardt-aauth-budgets) ───────────────
# Hand-serialized: the value space is tiny (non-negative sf-integers, one
# sf-string, sf-tokens) and the golden tests round-trip the output through the
# real http_sfv parser. NOTE: the field is declared an RFC 9651 *Dictionary*,
# so members are comma-separated — the draft's §11 example shows semicolons,
# which is the *parameter* separator; flagged for the implementation report.


def _sf_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_aauth_budget_header(
    *,
    remaining: int,
    cost: int | None = None,
    reserved: int | None = None,
    required: int | None = None,
    unit: str | None = None,
    decimals: int | None = None,
) -> str:
    """Serialize the ``AAuth-Budget`` response header. ``remaining`` is the only
    REQUIRED member; ``unit``/``decimals`` must travel together or not at all.
    ``required`` is the maximum cost of a request refused ``insufficient-budget``
    — sent only with that refusal, so the agent's retry is a calculation
    (lower the bound to fit ``remaining``) rather than a search."""
    if (unit is None) != (decimals is None):
        raise ValueError("unit and decimals must be provided together")
    members: list[str] = []
    if cost is not None:
        members.append(f"cost={cost}")
    members.append(f"remaining={remaining}")
    if reserved is not None:
        members.append(f"reserved={reserved}")
    if required is not None:
        members.append(f"required={required}")
    if unit is not None and decimals is not None:
        members.append(f"unit={_sf_string(unit)}")
        members.append(f"decimals={decimals}")
    return ", ".join(members)


def build_aauth_requirement(*, reason: str | None,
                            resource_token: str | None = None) -> str:
    """Serialize ``AAuth-Requirement`` for a budget challenge:
    ``requirement=auth-token;resource-token="eyJ…";reason=insufficient-budget``.
    ``reason`` is an sf-token (``insufficient-budget`` | ``budget-exhausted``)
    for an exhaustion refusal, or ``None`` for the base protocol's plain
    challenge (an EXPIRED auth token — the budget did not run out, the token
    did); the resource token (when the resource issues one) rides as an
    sf-string."""
    out = "requirement=auth-token"
    if resource_token:
        out += f";resource-token={_sf_string(resource_token)}"
    if reason:
        out += f";reason={reason}"
    return out
