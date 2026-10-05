"""Verifier configuration — a plain frozen dataclass, no framework coupling."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

__all__ = ["AAUTH_REQUIRED_COMPONENTS", "HttpsigConfig"]

# AAuth -11 §11.3.3.1: what every agent signature MUST cover. A request with a
# body to a PS/AS/revocation endpoint additionally covers content-digest and
# content-type; the verifier adds those when it is handed the body.
AAUTH_REQUIRED_COMPONENTS: tuple[str, ...] = ("@method", "@authority", "@path", "signature-key")


@dataclass(frozen=True)
class HttpsigConfig:
    """Configuration for :class:`regent_httpsig.HttpsigVerifier`.

    Defaults are production-safe and, on the AAuth path, follow -11 as
    published: a 60-second ``created`` window, fully-specified algorithms only,
    no clock-skew tolerance on ``exp``. Web Bot Auth keeps its own, looser age
    rule (``max_age_hours``) because that profile defines no window."""

    # Origins/issuers you additionally mark as trusted (``VerifiedSignature.trusted``).
    # Verification itself never depends on this — it only annotates the result.
    trusted_agents: frozenset[str] = field(default_factory=frozenset)
    # Web Bot Auth only: reject signatures created earlier than this many hours ago.
    max_age_hours: int = 25
    # AAuth -11 §11.3.4 step 3: the signature validity window for `created`, in
    # seconds. Older than the window → invalid_signature; further ahead of our
    # clock → clock_skew. The same window bounds a token's `iat` (§11.5.2).
    # Advertise a different value in resource metadata as `signature_window`.
    signature_window_seconds: int = 60
    # AAuth -11 §11.3.3.1: covered components every agent signature must include.
    required_components: tuple[str, ...] = AAUTH_REQUIRED_COMPONENTS
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
    # AAuth -11 §11.3.1: JOSE algs must be fully-specified (RFC 9864); the
    # polymorphic "EdDSA" and keys without `alg` are refused. False is the
    # pre-cut-over behaviour kept only for private test rigs; -11 forbids it.
    require_fully_specified_algs: bool = True
    # This service's public URL (e.g. "https://api.example"). Required to accept
    # AAuth person tokens and auth tokens — their `aud` must name this resource.
    # None disables both paths.
    resource_url: str | None = None
    # AAuth auth tokens (typ "aa-auth+jwt" — the carrier of budget envelopes) and
    # signed server requests (the jwks_uri scheme, §11.3.2): issuer → JWKS URL
    # for each Person Server / Access Server this resource accepts. A resource has
    # an established relationship with its PS, so trust is pinned by
    # configuration. The value may be "" to discover the JWKS through the
    # issuer's metadata document ({id}/.well-known/{dwk}) instead of a fixed URL.
    # Empty (the default) disables the auth-token and server paths entirely.
    trusted_ps: Mapping[str, str] = field(default_factory=dict)
