"""AAuth Budgets usage endpoint (draft-hardt-aauth-budgets, §Usage Counters).

Consumption records reach the PS only when an agent carries a resource token
home; this endpoint removes the agent from that loop — the PS queries the
resource directly, on a channel the agent is never on.

The library owns the contract: query validation, the response shape, and the
RECOMMENDED response signature. Caller authentication is the application's
(``authenticate_ps``) — it already knows which person servers it trusts and
how it verifies their signatures, exactly as it does for auth tokens.

Draft rules encoded here, each load-bearing:

- Exactly one scope key (``sub`` | ``tenant`` | ``mission_s256``) or ``jkts``;
  both MAY appear; two scope keys or neither-nor-jkts is an error.
- An unrecognized scope value returns ``200`` with ``usage`` omitted — "never
  seen" and "nothing consumed" are deliberately indistinguishable, so a query
  cannot discover whether a person holds an account.
- An unrecognized or pruned thumbprint is OMITTED from ``jkts``, never zero:
  absence means "cannot answer"; a present zero would be a wrong answer to an
  allocation decision.
- One unit per response, named once at the top level.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regent_httpsig.jwk import b64url_decode, jwk_thumbprint

__all__ = ["UsageQueryError", "ResponseSigner", "build_usage_response",
           "parse_usage_request", "make_usage_endpoint", "make_revocation_endpoint",
           "validate_budget_grant"]

_SCOPE_KEYS = ("sub", "tenant", "mission_s256")
_MAX_JKTS = 100


class UsageQueryError(ValueError):
    """The query violates the request contract (two scope keys, neither a
    scope key nor ``jkts``, or malformed members)."""


def parse_usage_request(body: Any) -> tuple[str | None, str | None, list[str]]:
    """Validate a usage query. Returns ``(scope_key, scope_value, jkts)``."""
    if not isinstance(body, dict):
        raise UsageQueryError("body must be a JSON object")
    present = [k for k in _SCOPE_KEYS if k in body]
    if len(present) > 1:
        raise UsageQueryError("at most one scope key may appear")
    jkts_raw = body.get("jkts", [])
    if not isinstance(jkts_raw, list) or len(jkts_raw) > _MAX_JKTS or not all(
        isinstance(j, str) and 20 <= len(j) <= 100 for j in jkts_raw
    ):
        raise UsageQueryError("jkts must be a short array of JWK thumbprints")
    if not present and not jkts_raw:
        raise UsageQueryError("a scope key or jkts is required")
    scope_key = present[0] if present else None
    scope_value = None
    if scope_key is not None:
        scope_value = body[scope_key]
        if not isinstance(scope_value, str) or not scope_value:
            raise UsageQueryError(f"{scope_key} must be a non-empty string")
    return scope_key, scope_value, [str(j) for j in jkts_raw]


async def build_usage_response(
    meter: Any,
    *,
    iss: str,
    aud: str,
    unit: str,
    decimals: int,
    scope_key: str | None,
    scope_value: str | None,
    jkts: list[str],
    now: float | None = None,
) -> dict[str, Any]:
    """Assemble the response body per §Usage Response. ``iss`` scopes every
    figure to tokens the calling PS issued; ``aud`` echoes who the response is
    for (what stops a signed response being shown to a third party)."""
    out: dict[str, Any] = {
        "as_of": int(now if now is not None else time.time()),
        "aud": aud,
        "unit": unit,
        "decimals": decimals,
    }
    if scope_key is not None:
        out[scope_key] = scope_value
        if scope_key == "sub":
            counters = await meter.usage_scope(iss, str(scope_value))
            if counters is not None:
                out["usage"] = counters
        # tenant / mission_s256: this meter holds no figure for them — the
        # scope value is echoed and ``usage`` omitted, per the unrecognized
        # scope rule. A backend that tracks them plugs in here.
    if jkts:
        out["jkts"] = await meter.usage_keys(iss, jkts)
    return out


class ResponseSigner:
    """Signs a usage response per §The Signed Response: an Ed25519 HTTP Sig
    covering ``@status``, ``content-type``, ``content-digest``, bound to the
    request via ``@authority``/``@path`` with the ``req`` parameter. The key is
    identified the -11 way (§11.3.2): ``Signature-Key: sig=jwks_uri;
    id="<server_id>";dwk="aauth-resource.json";kid="…"`` — the PS fetches
    ``{server_id}/.well-known/aauth-resource.json``, follows ``jwks_uri`` and
    finds ``kid`` there (serve :meth:`jwks`).

    Hand-built base string: response signing with request-bound components is
    beyond the request-oriented helper libraries, the component set is fixed by
    the draft, and the golden tests freeze every byte of it.
    """

    def __init__(self, *, seed: str, server_id: str, dwk: str = "aauth-resource.json",
                 kid: str | None = None, label: str = "sig") -> None:
        raw = b64url_decode(seed)
        if len(raw) != 32:
            raise ValueError("seed must be 32 bytes (base64url-encoded)")
        self._key = Ed25519PrivateKey.from_private_bytes(raw)
        self.server_id = server_id.rstrip("/")
        self.dwk = dwk
        self._label = label
        self.public_jwk = {
            "kty": "OKP", "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(
                self._key.public_key().public_bytes_raw()
            ).rstrip(b"=").decode(),
        }
        self.keyid = kid or jwk_thumbprint(self.public_jwk)

    def jwks(self) -> dict[str, Any]:
        """The JWKS to serve at the ``jwks_uri`` your metadata document names."""
        return {"keys": [{**self.public_jwk, "kid": self.keyid, "alg": "Ed25519", "use": "sig"}]}

    def signature_key_header(self) -> str:
        return (f'{self._label}=jwks_uri;id="{self.server_id}";'
                f'dwk="{self.dwk}";kid="{self.keyid}"')

    def sign(self, *, status: int, content_type: str, body: bytes,
             authority: str, path: str,
             created: int | None = None) -> dict[str, str]:
        """Return the four response headers: ``Content-Digest``,
        ``Signature-Input``, ``Signature``, ``Signature-Key``."""
        digest = "sha-256=:" + base64.b64encode(
            hashlib.sha256(body).digest()).decode() + ":"
        created = int(created if created is not None else time.time())
        inner = (
            '("@status" "content-type" "content-digest" '
            '"@authority";req "@path";req)'
            f";created={created}"
        )
        base = "\n".join([
            f'"@status": {status}',
            f'"content-type": {content_type}',
            f'"content-digest": {digest}',
            f'"@authority";req: {authority}',
            f'"@path";req: {path}',
            f'"@signature-params": {inner}',
        ])
        sig = base64.b64encode(self._key.sign(base.encode())).decode()
        return {
            "Content-Digest": digest,
            "Signature-Input": f"{self._label}={inner}",
            "Signature": f"{self._label}=:{sig}:",
            "Signature-Key": self.signature_key_header(),
        }


def _problem(status: int, error: str, detail: str,
             headers: dict[str, str] | None = None) -> Any:
    """-11 §11.9.2: ``application/problem+json`` with the REQUIRED ``error`` member.
    Typed ``Any`` because starlette is an optional extra; it is a ``JSONResponse``."""
    from starlette.responses import JSONResponse

    return JSONResponse(
        status_code=status, media_type="application/problem+json",
        content={"error": error, "status": status, "title": error.replace("_", " "),
                 "detail": detail},
        headers=headers or {},
    )


async def _caller(authenticate: Callable[[Any], Awaitable[Any]],
                  request: Any) -> tuple[str | None, Any]:
    """Normalize what ``authenticate_ps`` returns: an issuer string, a
    :class:`VerifiedSignature` (its ``agent``), a :class:`VerificationError`
    (→ 401 + Signature-Error) or ``None`` (→ 401 invalid_signature)."""
    from regent_httpsig.verify import VerificationError, VerifiedSignature

    result = await authenticate(request)
    if isinstance(result, VerifiedSignature):
        return result.agent, None
    if isinstance(result, str) and result:
        return result, None
    error = result if isinstance(result, VerificationError) else VerificationError(
        "invalid_signature", "sign the request as a server (jwks_uri scheme)")
    return None, _problem(401, error.code, error.detail, error.headers())


def make_usage_endpoint(
    meter: Any,
    *,
    authenticate_ps: Callable[[Any], Awaitable[str | None]],
    unit: str,
    decimals: int,
    signer: ResponseSigner | None = None,
) -> Callable[[Any], Awaitable[Any]]:
    """Build an ASGI-framework-agnostic handler: ``handler(request)`` returns a
    Starlette/FastAPI ``Response``. ``authenticate_ps(request)`` verifies the
    calling person server's signature (-11 §11.3.2, jwks_uri scheme) and
    returns its identity — a ``VerifiedSignature`` from
    :meth:`HttpsigVerifier.verify_server`, or the issuer string — or a
    ``VerificationError``/``None`` to refuse with 401 + ``Signature-Error``.
    The resource MUST only answer for values seen in tokens from that PS,
    which the ``iss``-keyed counters enforce structurally."""
    from starlette.responses import JSONResponse, Response

    async def handler(request: Any) -> Response:
        iss, refused = await _caller(authenticate_ps, request)
        if iss is None:
            refused_response: Response = refused
            return refused_response
        try:
            payload = json.loads(await request.body() or b"{}")
            scope_key, scope_value, jkts = parse_usage_request(payload)
        except (UsageQueryError, ValueError) as exc:
            return JSONResponse(status_code=400, content={
                "code": "INVALID_USAGE_QUERY", "message": str(exc)[:200]})
        doc = await build_usage_response(
            meter, iss=iss, aud=iss, unit=unit, decimals=decimals,
            scope_key=scope_key, scope_value=scope_value, jkts=jkts)
        body = json.dumps(doc, separators=(",", ":")).encode()
        headers: dict[str, str] = {}
        if signer is not None:
            headers = signer.sign(
                status=200, content_type="application/json", body=body,
                authority=request.url.netloc, path=request.url.path)
        return Response(content=body, media_type="application/json",
                        headers=headers)

    return handler


def validate_budget_grant(unit: str, decimals: int,
                          budget_units: list[dict[str, Any]]) -> None:
    """Enforce the §Resource Metadata MUSTs before minting a resource token:
    a resource that declares ``budget_units`` MUST NOT issue a token whose
    ``budget.unit`` is absent from the array, and MUST set ``budget.decimals``
    to the declared value — the mismatch this stops is the draft's
    "thousandfold error"."""
    for entry in budget_units:
        if entry.get("unit") == unit:
            declared = entry.get("decimals")
            if declared != decimals:
                raise ValueError(
                    f"budget.decimals must be {declared} for {unit!r} "
                    f"(declared in budget_units), got {decimals}")
            return
    raise ValueError(f"unit {unit!r} is not declared in budget_units")


def make_revocation_endpoint(
    meter: Any,
    *,
    authenticate_ps: Callable[[Any], Awaitable[Any]],
    accepted_issuers: Callable[[str], bool] | None = None,
    max_token_lifetime: float = 86400.0,
    clock_skew: float = 60.0,
) -> Callable[[Any], Awaitable[Any]]:
    """The base protocol's revocation endpoint (-11 §11.12) for the budgets
    meter: a signed ``POST {"jti", "exp"}``. The issuer is NOT a request
    parameter — it is the identity verified on the caller's server signature
    (§11.3.2), so a caller revokes only its own tokens. The pair ``(iss, jti)``
    is recorded whether or not the token was ever seen here (a resource that
    verifies statelessly still answers 200), and the answer is always an empty
    ``200``: there is no "not found" (Appendix C.2.7).

    Errors (§11.12.3, problem+json): ``invalid_request`` 400 for malformed
    JSON or a missing/malformed ``jti``/``exp`` — including an ``exp`` further
    ahead than ``max_token_lifetime`` + ``clock_skew``, the longest lifetime
    this resource accepts; ``unsupported_iss`` 403 when ``accepted_issuers``
    says no (default: any verified caller); a signature that does not verify
    is 401 + ``Signature-Error``. ``rate_limited`` and ``server_error`` are
    the application's to raise.

    What revocation does to the meter is :meth:`InMemoryMeter.record_revocation`:
    no new spend, in-flight requests complete, and the token's consumption
    record is withheld until they have (AAuth #151); a later presentation of
    the token is refused with ``revoked_jwt`` (§11.12.5)."""
    from starlette.responses import Response

    async def handler(request: Any) -> Response:
        caller, refused = await _caller(authenticate_ps, request)
        if caller is None:
            refused_response: Response = refused
            return refused_response
        if accepted_issuers is not None and not accepted_issuers(caller):
            unsupported: Response = _problem(
                403, "unsupported_iss",
                "this resource does not accept revocations from that issuer")
            return unsupported
        try:
            payload = json.loads(await request.body() or b"")
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
            jti, exp = payload.get("jti"), payload.get("exp")
            if not isinstance(jti, str) or not jti or len(jti) > 512:
                raise ValueError("jti is REQUIRED (string)")
            if isinstance(exp, bool) or not isinstance(exp, int | float):
                raise ValueError("exp is REQUIRED (integer seconds)")
            if exp > time.time() + max_token_lifetime + clock_skew:
                raise ValueError("exp is further ahead than any token this resource accepts")
        except (ValueError, json.JSONDecodeError) as exc:
            invalid: Response = _problem(400, "invalid_request", str(exc)[:200])
            return invalid
        await meter.record_revocation(caller, jti, float(exp))
        return Response(status_code=200)

    return handler
