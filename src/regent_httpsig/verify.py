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
- **AAuth** (draft-hardt-oauth-aauth-protocol, identity-based mode): the agent
  carries a JWT ``agent_token`` (``typ: aa-agent+jwt``) in the ``Signature-Key``
  header; the token's issuer JWKS (``{iss}/.well-known/aauth-agent.json`` →
  ``jwks_uri``) verifies the token, and the token's ``cnf.jwk`` verifies the
  request signature (proof of possession). Requires the ``[aauth]`` extra.

Directory fetches are SSRF-guarded (https-only, public-IP-only, size-capped,
no redirects) and cached per verifier instance. A bad or missing signature
yields ``None`` — verification failure is a result, not an exception.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping
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
    parse_signature_key_header,
)

__all__ = ["HttpsigVerifier", "VerifiedSignature", "WBA_TAG"]

logger = logging.getLogger("regent_httpsig")

WBA_TAG = "web-bot-auth"
WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
AAUTH_METADATA_PATH = "/.well-known/aauth-agent.json"
AAUTH_PERSON_METADATA_PATH = "/.well-known/aauth-person.json"
AAUTH_JWT_TYP = "aa-agent+jwt"
AAUTH_PERSON_TYP = "aa-person+jwt"
AAUTH_AUTH_TYP = "aa-auth+jwt"  # PS-issued auth tokens — the budget carrier
# -11: person and auth tokens live at most one hour — enforced with tolerance.
PERSON_TOKEN_MAX_LIFETIME = 3600 + 90


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
    """A successfully verified inbound agent signature."""

    scheme: str  # "web-bot-auth" | "aauth"
    agent: str  # WBA: Signature-Agent origin; AAuth: the token issuer
    keyid: str  # RFC 7638 / RFC 8037 A.3 JWK thumbprint
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


class _KeyidOptionalParams(dict):  # type: ignore[type-arg]
    """RFC 9421 makes ``keyid`` OPTIONAL, but the upstream verifier reads
    ``params["keyid"]`` unconditionally. On the AAuth path the key comes from
    the token's ``cnf.jwk``, so conforming signers (e.g. aauth-signing) omit
    keyid entirely. Returning None for a missing keyid routes resolution to our
    StaticKeyResolver default WITHOUT adding the key to the params — iteration
    is unchanged, so the reconstructed signature base stays byte-identical."""

    def __getitem__(self, key: str) -> Any:
        if key == "keyid" and key not in self:
            return None
        return super().__getitem__(key)


class _KeyidOptionalVerifier(HTTPMessageVerifier):
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


class HttpsigVerifier:
    """Verify RFC 9421-signed agent requests (Web Bot Auth + AAuth).

    Instances are cheap and hold their own directory cache; create one per
    application and reuse it. ``http_client`` is optional — pass your app's
    shared :class:`httpx.AsyncClient` to reuse its pool.

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
    ) -> None:
        self.config = config or HttpsigConfig()
        self._http = http_client
        self._owns_client = http_client is None
        # url -> (expires_monotonic, parsed JSON | None for negative entries)
        self._cache: dict[str, tuple[float, dict[str, Any] | None]] = {}

    async def verify(
        self, method: str, url: str, headers: Mapping[str, str]
    ) -> VerifiedSignature | None:
        """Verify the request's agent signature. Returns ``None`` when there is
        no ``Signature`` header, the signature is invalid, or the signer's keys
        cannot be (safely) fetched — never raises on untrusted input."""
        hdrs = {str(k): str(v) for k, v in headers.items()}
        if not any(k.lower() == "signature" for k in hdrs):
            return None
        result: VerifiedSignature | None = None
        try:
            if any(k.lower() == "signature-key" for k in hdrs):
                result = await self._verify_aauth(method, url, hdrs)
            if result is None:
                result = await self._verify_web_bot_auth(method, url, hdrs)
        except Exception as exc:  # noqa: BLE001 — belt and braces
            logger.warning("httpsig verify error: %s", str(exc)[:200])
            return None
        if result is not None:
            logger.info(
                "httpsig verified scheme=%s agent=%s keyid=%s trusted=%s",
                result.scheme, result.agent, result.keyid[:16], result.trusted,
            )
        return result

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

    # ── AAuth (identity-based mode) ──────────────────────────────────────────

    async def _verify_aauth(
        self, method: str, url: str, headers: dict[str, str]
    ) -> VerifiedSignature | None:
        try:
            import jwt as pyjwt  # the [aauth] extra
        except ImportError:
            logger.info("Signature-Key present but pyjwt is not installed "
                        "(pip install 'regent-httpsig[aauth]')")
            return None

        message = Message(method, url, headers)
        parsed = parse_signature_key_header(message.headers.get("signature-key", ""))
        if not parsed:
            return None
        label, token = parsed

        _register_fully_specified_algs()
        try:
            header = pyjwt.get_unverified_header(token)
            unverified = pyjwt.decode(token, options={"verify_signature": False})
        except Exception:  # noqa: BLE001
            return None
        if header.get("alg") in (None, "none"):
            return None

        # -11 token-type dispatch: agent tokens (identity mode), person tokens
        # (PS-issued, per-resource, opt-in via config.resource_url) and auth
        # tokens (PS-issued budget carriers, opt-in via config.trusted_ps).
        typ = header.get("typ")
        jwks_override: str | None = None
        if typ == AAUTH_JWT_TYP:
            scheme, expected_dwk = "aauth", "aauth-agent.json"
            metadata_path, audience = AAUTH_METADATA_PATH, None
        elif typ == AAUTH_PERSON_TYP:
            if not self.config.resource_url:
                logger.info("person token presented but config.resource_url is not "
                            "set — person-token verification is disabled")
                return None
            scheme, expected_dwk = "aauth-person", "aauth-person.json"
            metadata_path, audience = AAUTH_PERSON_METADATA_PATH, self.config.resource_url
        elif typ == AAUTH_AUTH_TYP:
            if not self.config.resource_url or not self.config.trusted_ps:
                logger.info("auth token presented but resource_url/trusted_ps is not "
                            "configured — auth-token verification is disabled")
                return None
            scheme, expected_dwk = "aauth-auth", None
            metadata_path, audience = None, self.config.resource_url
        else:
            return None

        iss = str(unverified.get("iss", ""))
        if typ == AAUTH_AUTH_TYP:
            # The resource pins its PS: issuer must be explicitly trusted and its
            # JWKS location comes from configuration, not open-world discovery.
            override = self.config.trusted_ps.get(iss)
            if override is None:
                logger.info("auth token issuer %s is not a configured PS", iss[:100])
                return None
            jwks_override = override
        else:
            bad_iss = (unverified.get("dwk") != expected_dwk
                       or not iss.startswith("https://"))
            if bad_iss and not (
                iss and urlsplit(iss).hostname in self.config.insecure_hosts  # dev escape
            ):
                return None

        # AAuth -11 / RFC 9864: fully-specified algorithms. "EdDSA" (polymorphic)
        # is accepted only while require_fully_specified_algs is False — a
        # transition affordance for the -10 ecosystem.
        allowed_algs = ["Ed25519", "ES256", "RS256"]
        if not self.config.require_fully_specified_algs:
            allowed_algs.append("EdDSA")

        # 1) Verify the token against the issuer's published JWKS.
        if jwks_override is not None:
            jwks = await self._fetch_json(jwks_override)
        else:
            metadata = await self._fetch_json(iss.rstrip("/") + str(metadata_path))
            if not metadata or not metadata.get("jwks_uri"):
                return None
            jwks = await self._fetch_json(str(metadata["jwks_uri"]))
        if not jwks:
            return None
        issuer_key = None
        for k in list(jwks.get("keys") or [])[:10]:
            if k.get("kid") == header.get("kid") or len(jwks.get("keys") or []) == 1:
                try:
                    issuer_key = pyjwt.PyJWK(k).key
                    break
                except Exception:  # noqa: BLE001
                    # PyJWK's internal registry predates RFC 9864 names — a JWKS
                    # advertising alg "Ed25519" is valid in -11 but unknown to it.
                    try:
                        issuer_key = load_ed25519_jwk(k)
                        break
                    except ValueError:
                        continue
        if issuer_key is None:
            return None
        try:
            claims = pyjwt.decode(
                token,
                key=issuer_key,
                algorithms=allowed_algs,
                audience=audience,
                options={
                    "require": ["iss", "sub", "exp", "iat"],
                    "verify_aud": audience is not None,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.info("aauth token invalid iss=%s: %s", iss, str(exc)[:200])
            return None

        # -11: person and auth tokens live at most one hour.
        if typ in (AAUTH_PERSON_TYP, AAUTH_AUTH_TYP):
            lifetime = int(claims.get("exp", 0)) - int(claims.get("iat", 0))
            if lifetime <= 0 or lifetime > PERSON_TOKEN_MAX_LIFETIME:
                logger.info("%s lifetime %ss out of bounds iss=%s", typ, lifetime, iss)
                return None

        # 2) Proof of possession: the request signature must verify against cnf.jwk.
        cnf_jwk = (claims.get("cnf") or {}).get("jwk")
        if not isinstance(cnf_jwk, dict):
            return None
        # -11 strict mode: the cnf JWK "MUST carry a fully-specified alg member".
        if self.config.require_fully_specified_algs and cnf_jwk.get("alg") != "Ed25519":
            logger.info("cnf.jwk alg %r is not fully-specified iss=%s",
                        cnf_jwk.get("alg"), iss)
            return None
        try:
            pop_key = load_ed25519_jwk(cnf_jwk)
        except ValueError:
            return None
        verifier = _KeyidOptionalVerifier(
            signature_algorithm=ED25519,
            key_resolver=StaticKeyResolver({}, default=pop_key),
            component_resolver_class=DictKeyComponentResolver,
        )
        try:
            # No expect_label: upstream requires expect_tag alongside it, and the
            # AAuth drafts' tag is still moving — we verify all signatures against
            # the possession key and match the Signature-Key label ourselves.
            results = await asyncio.to_thread(
                verifier.verify,
                message,
                max_age=timedelta(hours=self.config.max_age_hours),
            )
        except Exception as exc:  # noqa: BLE001
            logger.info("aauth PoP invalid iss=%s: %s", iss, str(exc)[:200])
            return None
        if not any(str(r.label) == label for r in results):
            return None

        return VerifiedSignature(
            scheme=scheme,
            agent=iss,
            keyid=jwk_thumbprint(cnf_jwk),
            # An auth-token issuer is by definition a configured, trusted PS.
            trusted=iss in self.config.trusted_agents or typ == AAUTH_AUTH_TYP,
            sub=str(claims.get("sub", "")),
            label=label,
            claims={
                k: claims[k]
                for k in ("iss", "sub", "exp", "ps", "aud", "jti", "mission_s256",
                          "budget")  # budgets: the envelope rides in the token
                if k in claims
            },
        )
