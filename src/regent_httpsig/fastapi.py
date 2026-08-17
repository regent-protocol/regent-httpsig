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

from fastapi import Depends, FastAPI, HTTPException, Request

from regent_httpsig.verify import HttpsigVerifier, VerifiedSignature

__all__ = ["RequiredSignatureDep", "SignatureDep", "VerifiedSignature", "attach"]

_STATE_ATTR = "regent_httpsig_verifier"


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
