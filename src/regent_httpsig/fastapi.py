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

``SignatureDep`` is enrichment: ``None`` when absent/invalid, never raises
(``SignatureErrorDep`` tells you why). ``RequiredSignatureDep`` is
authentication: a signed request that fails is answered ``401`` with the
``Signature-Error`` header of draft-hardt-httpbis-signature-key (the code
AAuth -11 §11.3.4 assigns), an unsigned one with ``AAuth-Requirement:
requirement=agent-token`` (-11 §6.1).

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
    TokenRevoked,
    UnitMismatch,
)
from regent_httpsig.sfv import (
    build_aauth_budget_header,
    build_aauth_requirement,
    build_person_token_requirement,
)
from regent_httpsig.verify import (
    AAUTH_AUTH_TYP,
    AAUTH_PERSON_TYP,
    HttpsigVerifier,
    VerificationError,
    VerifiedSignature,
)

__all__ = [
    "BudgetMiddleware",
    "RequiredSignatureDep",
    "SignatureDep",
    "SignatureErrorDep",
    "VerificationError",
    "VerifiedSignature",
    "attach",
    "get_signature",
    "get_signature_error",
    "require_server_signature",
    "signature_error_response",
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


def _verifier_of(request: Request) -> HttpsigVerifier:
    verifier: HttpsigVerifier | None = getattr(request.app.state, _STATE_ATTR, None)
    if verifier is None:
        raise RuntimeError(
            "regent-httpsig verifier not attached — call "
            "regent_httpsig.fastapi.attach(app, HttpsigVerifier()) at startup"
        )
    return verifier


async def _run_verifier(
    verifier: HttpsigVerifier, request: Request,
) -> VerifiedSignature | VerificationError | None:
    """Verify once per request; both outcomes are cached on ``request.state``."""
    cached: Any = getattr(request.state, "regent_httpsig_outcome", "unset")
    if cached != "unset":
        return cached if isinstance(cached, VerifiedSignature | VerificationError) else None
    outcome: VerifiedSignature | VerificationError | None = None
    if "signature" in request.headers:
        # The -11 body rule (content-digest covered and matching) applies to the
        # Signature-Key path; Web Bot Auth has no such rule and needs no body.
        body = await request.body() if "signature-key" in request.headers else None
        outcome = await verifier.verify_detailed(
            request.method, _public_url(request), dict(request.headers), body,
        )
    request.state.regent_httpsig_outcome = outcome
    request.state.regent_httpsig_result = (
        outcome if isinstance(outcome, VerifiedSignature) else None)
    request.state.regent_httpsig_error = (
        outcome if isinstance(outcome, VerificationError) else None)
    return outcome


def signature_error_response(
    error: VerificationError, *, code: str | None = None, requirement: str | None = None,
) -> JSONResponse:
    """``401`` + ``Signature-Error`` (+ ``Accept-Signature-*``) with the
    problem+json body of draft-hardt-httpbis-signature-key §5. ``requirement``
    adds an ``AAuth-Requirement`` header; ``code`` adds a legacy ``code`` member."""
    headers = error.headers()
    if requirement:
        headers["AAuth-Requirement"] = requirement
    body = error.problem(401)
    if code:
        body["code"] = code
    return JSONResponse(status_code=401, content=body, headers=headers,
                        media_type="application/problem+json")


def _repair_requirement(error: VerificationError) -> str | None:
    """-11 §11.12.5 / budgets "auth token expired": a revoked or expired person
    or auth token is repaired by a fresh person token; nothing repairs an agent
    token (the agent obtains a new one from its provider)."""
    if error.code in ("revoked_jwt", "expired_jwt") and error.token_typ in (
        AAUTH_PERSON_TYP, AAUTH_AUTH_TYP,
    ):
        return build_person_token_requirement()
    return None


async def get_signature(request: Request) -> VerifiedSignature | None:
    """Optional verification: zero-cost without a Signature header, never raises."""
    outcome = await _run_verifier(_verifier_of(request), request)
    return outcome if isinstance(outcome, VerifiedSignature) else None


async def get_signature_error(request: Request) -> VerificationError | None:
    """Why a signed request did not verify (``None`` when unsigned or verified)."""
    outcome = await _run_verifier(_verifier_of(request), request)
    return outcome if isinstance(outcome, VerificationError) else None


async def require_signature(request: Request) -> VerifiedSignature:
    """Hard requirement: a fully verified signature, or a 401 that tells the
    agent exactly what went wrong (``Signature-Error``) or what to present
    (``AAuth-Requirement: requirement=agent-token``)."""
    outcome = await _run_verifier(_verifier_of(request), request)
    if isinstance(outcome, VerifiedSignature):
        return outcome
    if isinstance(outcome, VerificationError):
        headers = outcome.headers()
        requirement = _repair_requirement(outcome)
        if requirement:
            headers["AAuth-Requirement"] = requirement
        raise HTTPException(status_code=401, headers=headers,
                            detail={**outcome.problem(401), "code": "SIGNATURE_INVALID"})
    raise HTTPException(
        status_code=401,
        headers={"AAuth-Requirement": "requirement=agent-token"},
        detail={
            "code": "SIGNATURE_REQUIRED",
            "message": (
                "Sign this request with RFC 9421 HTTP Message Signatures: either "
                "AAuth (your agent token in the Signature-Key header under the jwt "
                "scheme, signature over @method @authority @path signature-key bound "
                'to its cnf.jwk) or Web Bot Auth (tag="web-bot-auth", Ed25519 key '
                "published at {your-origin}/.well-known/http-message-signatures-directory, "
                "Signature-Agent header naming that origin)."
            ),
        },
    )


async def require_server_signature(request: Request) -> VerifiedSignature:
    """For endpoints servers call (usage, revocation): the caller must sign
    under the ``jwks_uri`` scheme (-11 §11.3.2); the body is covered. A
    failure is ``401`` + ``Signature-Error``."""
    verifier = _verifier_of(request)
    body = await request.body()
    outcome = await verifier.verify_server(
        request.method, _public_url(request), dict(request.headers), body,
    )
    if isinstance(outcome, VerifiedSignature):
        return outcome
    raise HTTPException(status_code=401, headers=outcome.headers(),
                        detail={**outcome.problem(401), "code": "SIGNATURE_INVALID"})


SignatureDep = Depends(get_signature)
SignatureErrorDep = Depends(get_signature_error)
RequiredSignatureDep = Depends(require_signature)
RequiredServerSignatureDep = Depends(require_server_signature)


# ── AAuth Budgets enforcement (draft-hardt-aauth-budgets) ────────────────────

PriceFn = Callable[[Request], "int | None | Awaitable[int | None]"]
ResourceTokenProvider = Callable[
    [MeterKey, "dict[str, Any] | None"], "str | None | Awaitable[str | None]"
]


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class BudgetMiddleware(BaseHTTPMiddleware):
    """Meter budget-carrying requests: reserve the maximum cost atomically,
    serve, commit the actual cost, answer with ``AAuth-Budget``.

    ::

        app.add_middleware(
            BudgetMiddleware,
            verifier=HttpsigVerifier(HttpsigConfig(
                resource_url="https://api.example",
                trusted_ps={"https://ps.example": "https://ps.example/jwks.json"},
            )),
            meter=InMemoryMeter(),
            price_fn=lambda request: PRICES.get(request.url.path),
        )

    - ``price_fn(request)`` returns the request's MAXIMUM cost in the envelope's
      minor units, or ``None`` for routes outside budget enforcement.
    - A handler that knows the actual cost sets ``request.state.budget_cost``
      before returning; otherwise the full reservation is committed.
    - ``require=False`` (default) lets requests without a budget envelope pass
      through untouched — run per-decision authorization for them instead.
      ``require=True`` refuses them with 401 + ``AAuth-Requirement``.
    - A *signed* request that does not verify is refused with ``401`` +
      ``Signature-Error`` (-11 §11.3.4) whatever ``require`` says. A revoked or
      expired auth token is ``revoked_jwt`` / ``expired_jwt`` plus
      ``AAuth-Requirement: requirement=person-token`` (-11 §11.12.5) — no
      resource token, no ``AAuth-Budget``; its final consumption record reaches
      the issuer through the usage endpoint.
    - Error responses (4xx/5xx) release the reservation — nothing was served,
      the envelope is not charged.
    - ``resource_token_provider(key, record)`` (optional) mints the resource
      token embedded in budget-refusal responses so the agent can carry
      ``budget_consumed`` back to its PS for re-authorization. ``record`` is
      the PRESENTED token's ``{"jti", "consumed"}`` (draft §The Consumption
      Record — one record, two members) or ``None`` when nothing was metered
      against it yet.
    - Wire the verifier to the meter's revocation record
      (``HttpsigVerifier(..., is_revoked=meter.is_revoked)``) so a revoked
      token is named as revoked before it is metered; the middleware checks the
      meter too, for verifiers wired otherwise.
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

        outcome = await _run_verifier(self._verifier, request)
        if isinstance(outcome, VerificationError):
            return self._signature_error(outcome)
        sig = outcome
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
        is_revoked = getattr(self._meter, "is_revoked", None)
        if is_revoked is not None and await is_revoked(key[0], jti):
            return self._revoked()
        try:
            # sig.keyid is the RFC 7638 thumbprint of the token's cnf key (jkt) —
            # recorded so refusal-time consumption records are scoped to the
            # presenting agent and never disclose its siblings' spending.
            await self._meter.observe_grant(key, jti, envelope,
                                            float(sig.claims.get("exp", 0)),
                                            jkt=sig.keyid)
        except UnitMismatch as exc:
            logger.warning("budget unit mismatch for %s: %s", key, exc)
            return self._refusal(reason="insufficient-budget", envelope=envelope,
                                 remaining=0, key=key)

        outcome_r = await self._meter.reserve(key, jti, int(max_cost))
        if isinstance(outcome_r, TokenRevoked):
            # §Token Scope / -11 §11.12.5: say it was revoked, ask for a person
            # token, carry no resource token. The final record (once nothing is
            # in flight, AAuth #151) is the usage endpoint's to report.
            return self._revoked()
        if isinstance(outcome_r, InsufficientBudget):
            reason = "budget-exhausted" if outcome_r.exhausted else "insufficient-budget"
            return await self._refusal_with_token(
                reason=reason, envelope=envelope, remaining=outcome_r.remaining,
                key=key, jti=jti,
                # `required` rides only on insufficient-budget: what THIS
                # request needed, so the agent can lower its bound and retry.
                required=int(max_cost) if reason == "insufficient-budget" else None,
            )

        reservation: Reservation = outcome_r
        try:
            response = await call_next(request)
        except Exception:
            await self._meter.release(reservation)
            raise

        if response.status_code >= 400:
            # Nothing was served — the envelope is not charged for errors.
            remaining = await self._meter.release(reservation)
            cost = 0
        elif self._is_streamed(request, response):
            # Cost-omitted mode (draft §cost-omitted): a streamed response's
            # actual cost is known only when the stream ends, and this runtime
            # sends no trailers. We state what we HOLD — `reserved`, REQUIRED
            # when `cost` is omitted — with `remaining` already net of the
            # hold, and commit when the stream completes. The agent recovers
            # the exact figure from the next response's `remaining`.
            remaining = await self._meter.remaining(key, jti)
            response.headers["AAuth-Budget"] = build_aauth_budget_header(
                remaining=remaining, reserved=int(max_cost),
                unit=envelope.unit, decimals=envelope.decimals,
            )
            self._commit_after_stream(request, response, reservation,
                                      int(max_cost))
            return response
        else:
            actual = getattr(request.state, "budget_cost", None)
            cost = int(actual) if actual is not None else int(max_cost)
            remaining = await self._meter.commit(reservation, cost)
        response.headers["AAuth-Budget"] = build_aauth_budget_header(
            remaining=remaining, cost=cost,
            unit=envelope.unit, decimals=envelope.decimals,
        )
        return response

    @staticmethod
    def _is_streamed(request: Request, response: Response) -> bool:
        """A handler opts in with ``request.state.budget_streaming = True``;
        SSE responses are recognized on their own."""
        if getattr(request.state, "budget_streaming", False):
            return True
        ctype = response.headers.get("content-type", "")
        return ctype.startswith("text/event-stream")

    def _commit_after_stream(self, request: Request, response: Response,
                             reservation: Reservation, max_cost: int) -> None:
        """Wrap the body iterator so the reservation is committed (at the
        handler's actual cost if it set one mid-stream, else the full hold)
        when the stream ends, and released if it breaks before a byte is sent."""
        meter = self._meter
        original = response.body_iterator  # type: ignore[attr-defined]

        async def metered() -> Any:
            sent = False
            try:
                async for chunk in original:
                    sent = True
                    yield chunk
            except BaseException:
                await (meter.commit(reservation, max_cost) if sent
                       else meter.release(reservation))
                raise
            actual = getattr(request.state, "budget_cost", None)
            await meter.commit(reservation,
                               int(actual) if actual is not None else max_cost)

        response.body_iterator = metered()  # type: ignore[attr-defined]

    # ── helpers ──────────────────────────────────────────────────────────────

    def _signature_error(self, error: VerificationError) -> Response:
        code = {"revoked_jwt": "AUTH_TOKEN_REVOKED", "expired_jwt": "AUTH_TOKEN_EXPIRED"}.get(
            error.code, "SIGNATURE_INVALID")
        return signature_error_response(error, code=code,
                                        requirement=_repair_requirement(error))

    def _revoked(self) -> Response:
        """The meter knows the token is revoked (the verifier was not wired to
        it, or learned out of band): the same -11 §11.12.5 answer."""
        error = VerificationError("revoked_jwt", "the issuer has withdrawn this token",
                                  token_typ=AAUTH_AUTH_TYP)
        return self._signature_error(error)

    async def _refusal_with_token(
        self, *, reason: str, envelope: BudgetClaim,
        remaining: int, key: MeterKey, jti: str,
        required: int | None = None,
    ) -> Response:
        token: str | None = None
        if self._resource_token is not None:
            try:
                # One record, the presented token's (§The Consumption Record):
                # what THIS jti has cost so far. Siblings' spend never rides
                # home with this agent — the usage endpoint reports that.
                record = await self._meter.consumed_record(key, jti)
                token = await _maybe_await(self._resource_token(key, record))
            except Exception:  # noqa: BLE001 — refusal must not fail on the extras
                logger.warning("resource_token_provider failed", exc_info=True)
        return self._refusal(reason=reason, envelope=envelope,
                             remaining=remaining, resource_token=token,
                             required=required)

    def _refusal(
        self, *, reason: str | None, envelope: BudgetClaim | None,
        remaining: int | None, key: MeterKey | None = None,
        resource_token: str | None = None, required: int | None = None,
    ) -> Response:
        headers = {
            "AAuth-Requirement": build_aauth_requirement(
                reason=reason or "insufficient-budget",
                resource_token=resource_token,
            )
        }
        if remaining is not None and envelope is not None:
            headers["AAuth-Budget"] = build_aauth_budget_header(
                remaining=remaining, required=required,
                unit=envelope.unit, decimals=envelope.decimals,
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
