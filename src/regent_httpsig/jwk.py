"""JWK helpers — RFC 7638 thumbprints (RFC 8037 A.3 for Ed25519) and key loading."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["b64url", "b64url_decode", "jwk_thumbprint", "load_ed25519_jwk"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK thumbprint (RFC 8037 A.3 for OKP): sha256 over the canonical
    JSON of the required members, base64url without padding.

    This is the keyid form Web Bot Auth uses — e.g. the RFC test key's thumbprint
    is ``poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U``."""
    required_by_kty = {
        "OKP": ("crv", "kty", "x"),
        "EC": ("crv", "kty", "x", "y"),
        "RSA": ("e", "kty", "n"),
    }
    members = required_by_kty.get(str(jwk.get("kty", "")))
    if not members:
        raise ValueError(f"unsupported kty {jwk.get('kty')!r}")
    canonical = json.dumps(
        {m: jwk[m] for m in sorted(members)}, separators=(",", ":"), sort_keys=True
    )
    return b64url(hashlib.sha256(canonical.encode()).digest())


def load_ed25519_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        raise ValueError("only OKP/Ed25519 JWKs are supported")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(str(jwk["x"])))
