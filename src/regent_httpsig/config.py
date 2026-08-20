"""Verifier configuration — a plain frozen dataclass, no framework coupling."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

__all__ = ["HttpsigConfig"]


@dataclass(frozen=True)
class HttpsigConfig:
    """Configuration for :class:`regent_httpsig.HttpsigVerifier`.

    Defaults are production-safe: https-only directory fetching over public IPs,
    bounded cache, 25-hour max signature age (Web Bot Auth signatures carry
    ``created``/``expires``; 25h tolerates a day of clock drift)."""

    # Origins/issuers you additionally mark as trusted (``VerifiedSignature.trusted``).
    # Verification itself never depends on this — it only annotates the result.
    trusted_agents: frozenset[str] = field(default_factory=frozenset)
    # Reject signatures created earlier than this many hours ago.
    max_age_hours: int = 25
    # Key-directory cache TTL (seconds); failures are cached for negative_cache_ttl.
    cache_ttl: float = 600.0
    negative_cache_ttl: float = 120.0
    cache_max_entries: int = 256
    # Directory fetching: timeout, response size cap, redirects are never followed.
    fetch_timeout: float = 5.0
    max_directory_bytes: int = 64 * 1024
    # Hosts exempt from the https-only + public-IP SSRF guard (local dev only —
    # e.g. frozenset({"localhost"})). Leave empty in production.
    insecure_hosts: frozenset[str] = field(default_factory=frozenset)
    # AAuth -11 (editor's copy): JOSE algs must be fully-specified per RFC 9864 —
    # implementations MUST NOT accept the polymorphic "EdDSA". True enforces that;
    # the False default keeps accepting "EdDSA" while the -10 ecosystem migrates.
    require_fully_specified_algs: bool = False
    # This service's public URL (e.g. "https://api.example"). Required to accept
    # AAuth person tokens — their `aud` must name this resource. None disables
    # the person-token path entirely.
    resource_url: str | None = None
    # AAuth auth tokens (typ "aa-auth+jwt" — the carrier of budget envelopes):
    # issuer → JWKS URL for each Person Server this resource accepts auth tokens
    # from. A resource has an established relationship with its PS, so the key
    # location is pinned by configuration rather than discovered open-world.
    # Empty (the default) disables the auth-token path entirely.
    trusted_ps: Mapping[str, str] = field(default_factory=dict)
