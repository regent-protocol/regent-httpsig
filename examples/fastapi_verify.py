"""Minimal FastAPI service that knows which AI agent is calling.

Run:  pip install 'regent-httpsig[fastapi]' uvicorn
      uvicorn examples.fastapi_verify:app
"""

from fastapi import FastAPI

from regent_httpsig import HttpsigConfig, HttpsigVerifier
from regent_httpsig.fastapi import RequiredSignatureDep, SignatureDep, VerifiedSignature, attach

app = FastAPI()
attach(app, HttpsigVerifier(HttpsigConfig(
    trusted_agents=frozenset({"https://chatgpt.com", "https://operator.openai.com"}),
)))


@app.get("/whoami")
async def whoami(sig: VerifiedSignature | None = SignatureDep) -> dict:
    """Enrichment: works for everyone, tells signed agents apart."""
    if sig is None:
        return {"agent": None, "note": "unsigned request"}
    return {"agent": sig.agent, "keyid": sig.keyid, "trusted": sig.trusted}


@app.post("/agents-only")
async def agents_only(sig: VerifiedSignature = RequiredSignatureDep) -> dict:
    """Authentication: unsigned callers get a 401 explaining how to sign."""
    return {"welcome": sig.agent}
