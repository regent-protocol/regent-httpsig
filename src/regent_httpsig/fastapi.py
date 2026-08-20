"""FastAPI integration — the 5-line path (requires the ``[fastapi]`` extra).

Usage::

    from regent_httpsig import HttpsigVerifier
    from regent_httpsig.fastapi import attach, SignatureDep, VerifiedSignature

    app = FastAPI()
    attach(app, HttpsigVerifier())

    @app.post("/v1/orders")
    async def create_order(sig: VerifiedSignature | None = SignatureDep):
        if sig:
            ...  # sig.agent == "https://chatgpt.com", sig.keyid, sig.trusted

``SignatureDep`` is enrichment: ``None`` when absent/invalid, never raises.
``RequiredSignatureDep`` is authentication: a coded 401 tells the agent exactly
how to sign.

Proxy note: the signer signed the PUBLIC url. Behind a reverse proxy this
dependency rebuilds it from ``X-Forwarded-Proto`` + ``Host`` — make sure your
proxy sets ``X-Forwarded-Proto`` (nginx: ``proxy_set_header X-Forwarded-Proto
$scheme;``), or verification will fail on the scheme mismatch.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from regent_httpsig.budget import (
    BudgetClaim,
    InMemoryMeter,
    InsufficientBudget,
    InvalidBudgetClaim,
    MeterKey,
    Reservation,
    UnitMismatch,
)
from regent_httpsig.sfv import build_aauth_budget_header, build_aauth_requirement
from regent_httpsig.verify import HttpsigVerifier, VerifiedSignature

__all__ = [
    "BudgetMiddleware",
    "RequiredSignatureDep",
    "SignatureDep",
    "VerifiedSignature",
    "attach",
]

_STATE_ATTR = "regent_httpsig_verifier"
logger = logging.getLogger("regent_httpsig")


def attach(app: FastAPI, verifier: HttpsigVerifier) -> None:
    """Register the verifier on the app; the dependencies below read it back."""
    setattr(app.state, _STATE_ATTR, verifier)


def _public_url(request: Request) -> str:
    """Rebuild the URL the signer signed: scheme from the proxy, authority from
    Host — an ASGI server behind a proxy would otherwise see http://<container>."""
    host = request.headers.get("host") or request.url.netloc
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    path = request.url.path
    query = f"?{request.url.query}" if request.url.query else ""
    return f"{scheme}://{host}{path}{query}"


async def get_signature(request: Request) -> VerifiedSignature | None:
    """Optional verification: zero-cost without a Signature header, never raises."""
    verifier: HttpsigVerifier | None = getattr(request.app.state, _STATE_ATTR, None)
    if verifier is None:
        raise RuntimeError(
            "regent-httpsig verifier not attached — call "
            "regent_httpsig.fastapi.attach(app, HttpsigVerifier()) at startup"
        )
    if "signature" not in request.headers:
        return None
    cached = getattr(request.state, "regent_httpsig_result", "unset")
    if cached != "unset":
        return cached  # type: ignore[return-value]
    result = await verifier.verify(
        request.method, _public_url(request), dict(request.headers)
    )
    request.state.regent_httpsig_result = result
    return result


async def require_signature(request: Request) -> VerifiedSignature:
    """Hard requirement: a fully verified signature, or a 401 that tells the
    agent exactly how to sign."""
    sig = await get_signature(request)
    if sig is None:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "SIGNATURE_REQUIRED",
                "message": (
                    "Sign this request with RFC 9421 HTTP Message Signatures: either "
                    'Web Bot Auth (tag="web-bot-auth", Ed25519 key published at '
                    "{your-origin}/.well-known/http-message-signatures-directory, "
                    "Signature-Agent header naming that origin) or AAuth (agent_token "
                    "in the Signature-Key header, signature bound to its cnf.jwk)."
                ),
            },
        )
    return sig


SignatureDep = Depends(get_signature)
RequiredSignatureDep = Depends(require_signature)


# ── AAuth Budgets enforcement (draft-hardt-aauth-budgets) ────────────────────

PriceFn = Callable[[Request], "int | None | Awaitable[int | None]"]
ResourceTokenProvider = Callable[
    [MeterKey, "list[dict[str, Any]]"], "str | None | Awaitable[str | None]"
]


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class BudgetMiddleware(BaseHTTPMiddleware):
    """Meter budget-carrying requests: reserve the maximum cost atomically,
    serve, commit the actual, release the difference, and answer with an
    ``AAuth-Budget`` header. The full checklist a resource owes the draft —
    pricing excepted, which is the one thing only the resource can know.

    Usage::

        meter = InMemoryMeter()
        app.add_middleware(
            BudgetMiddleware,
            verifier=HttpsigVerifier(HttpsigConfig(
                resource_url="https://api.example",
                trusted_ps={"https://ps.example": "https://ps.example/jwks.json"},
            )),
            meter=meter,
            price_fn=lambda request: PRICES.get(request.url.path),
        )

    - ``price_fn(request)`` returns the request's MAXIMUM cost in the envelope's
      minor units, or ``None`` for routes outside budget enforcement.
    - A handler that knows the actual cost sets ``request.state.budget_cost``
      before returning; otherwise the full reservation is committed.
    - ``require=False`` (default) lets requests without a budget envelope pass
      through untouched — run per-decision authorization for them instead.
      ``require=True`` refuses them with 401 + ``AAuth-Requirement``.
    - Error responses (4xx/5xx) release the reservation — nothing was served,
      the envelope is not charged.
    - ``resource_token_provider(key, consumed_records)`` (optional) mints the
      resource token embedded in budget-refusal responses so the agent can
      carry ``budget_consumed`` back to its PS for re-authorization.
    """

    def __init__(
        self,
        app: Any,
        *,
        verifier: HttpsigVerifier,
        meter: InMemoryMeter | Any = None,
        price_fn: PriceFn,
        require: bool = False,
        resource_token_provider: ResourceTokenProvider | None = None,
    ) -> None:
        super().__init__(app)
        self._verifier = verifier
        self._meter = meter if meter is not None else InMemoryMeter()
        self._price_fn = price_fn
        self._require = require
        self._resource_token = resource_token_provider

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        max_cost = await _maybe_await(self._price_fn(request))
        if max_cost is None:
            return await call_next(request)

        sig = await self._verified(request)
        envelope: BudgetClaim | None = None
        if sig is not None:
            try:
                envelope = BudgetClaim.parse(sig.claims)
            except InvalidBudgetClaim as exc:
                logger.warning("malformed budget claim from %s: %s", sig.agent, exc)
        jti = str(sig.claims.get("jti") or "") if sig else ""

        if sig is None or envelope is None or not jti:
            if self._require:
                return self._refusal(reason=None, envelope=None, remaining=None)
            return await call_next(request)  # per-decision path handles it

        key: MeterKey = (
            str(sig.claims.get("iss", "")),
            str(sig.claims.get("sub", "")),
            str(sig.claims.get("aud", "")),
        )
        try:
            await self._meter.observe_grant(key, jti, envelope,
                                            float(sig.claims.get("exp", 0)))
        except UnitMismatch as exc:
            logger.warning("budget unit mismatch for %s: %s", key, exc)
            return self._refusal(reason="insufficient-budget", envelope=envelope,
                                 remaining=0, key=key)

        outcome = await self._meter.reserve(key, jti, int(max_cost))
        if isinstance(outcome, InsufficientBudget):
            reason = "budget-exhausted" if outcome.exhausted else "insufficient-budget"
            return await self._refusal_with_token(
                reason=reason, envelope=envelope, remaining=outcome.remaining, key=key
            )

        reservation: Reservation = outcome
        try:
            response = await call_next(request)
        except Exception:
            await self._meter.release(reservation)
            raise

        if response.status_code >= 400:
            # Nothing was served — the envelope is not charged for errors.
            remaining = await self._meter.release(reservation)
            cost = 0
        else:
            actual = getattr(request.state, "budget_cost", None)
            cost = int(actual) if actual is not None else int(max_cost)
            remaining = await self._meter.commit(reservation, cost)
        response.headers["AAuth-Budget"] = build_aauth_budget_header(
            remaining=remaining, cost=cost,
            unit=envelope.unit, decimals=envelope.decimals,
        )
        return response

    # ── helpers ──────────────────────────────────────────────────────────────

    async def _verified(self, request: Request) -> VerifiedSignature | None:
        cached = getattr(request.state, "regent_httpsig_result", "unset")
        if cached != "unset":
            return cached  # type: ignore[return-value]
        result = None
        if "signature" in request.headers:
            result = await self._verifier.verify(
                request.method, _public_url(request), dict(request.headers)
            )
        request.state.regent_httpsig_result = result
        return result

    async def _refusal_with_token(
        self, *, reason: str, envelope: BudgetClaim,
        remaining: int, key: MeterKey,
    ) -> Response:
        token: str | None = None
        if self._resource_token is not None:
            try:
                records = await self._meter.consumed_records(key)
                token = await _maybe_await(self._resource_token(key, records))
            except Exception:  # noqa: BLE001 — refusal must not fail on the extras
                logger.warning("resource_token_provider failed", exc_info=True)
        return self._refusal(reason=reason, envelope=envelope,
                             remaining=remaining, resource_token=token)

    def _refusal(
        self, *, reason: str | None, envelope: BudgetClaim | None,
        remaining: int | None, key: MeterKey | None = None,
        resource_token: str | None = None,
    ) -> Response:
        headers = {
            "AAuth-Requirement": build_aauth_requirement(
                reason=reason or "insufficient-budget",
                resource_token=resource_token,
            )
        }
        if remaining is not None and envelope is not None:
            headers["AAuth-Budget"] = build_aauth_budget_header(
                remaining=remaining, unit=envelope.unit, decimals=envelope.decimals
            )
        code = "AUTH_TOKEN_REQUIRED" if reason is None else reason.upper().replace("-", "_")
        return JSONResponse(
            status_code=401,
            content={
                "code": code,
                "message": (
                    "Present an auth token with a budget envelope "
                    "(AAuth Budgets) to call this endpoint."
                    if reason is None else
                    "The request's maximum cost exceeds the envelope's remaining "
                    "balance. Re-authorize with your PS for a fresh auth token."
                ),
            },
            headers=headers,
        )
