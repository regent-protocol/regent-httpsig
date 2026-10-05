"""regent-httpsig — verify and sign AI agent HTTP traffic (RFC 9421).

Web Bot Auth (what OpenAI ships, what Cloudflare/AWS/Google verify) and AAuth
(draft-hardt), in plain Python. See https://github.com/regent-protocol/regent-httpsig
"""

from regent_httpsig.budget import (
    BudgetClaim,
    InMemoryMeter,
    InsufficientBudget,
    InvalidBudgetClaim,
    TokenRevoked,
    UnitMismatch,
)
from regent_httpsig.config import HttpsigConfig
from regent_httpsig.jwk import b64url, jwk_thumbprint, load_ed25519_jwk
from regent_httpsig.netguard import NotPublicURL, assert_public_url
from regent_httpsig.sfv import (
    build_aauth_budget_header,
    build_aauth_requirement,
    build_person_token_requirement,
    parse_signature_agent,
    parse_signature_input,
    parse_signature_key,
)
from regent_httpsig.sign import (
    DIRECTORY_MEDIA_TYPE,
    EgressSigner,
    ServerSigner,
    content_digest,
    generate_seed,
    sign_request,
)
from regent_httpsig.usage import (
    ResponseSigner,
    UsageQueryError,
    build_usage_response,
    make_revocation_endpoint,
    make_usage_endpoint,
    parse_usage_request,
    validate_budget_grant,
)
from regent_httpsig.verify import (
    WBA_TAG,
    HttpsigVerifier,
    VerificationError,
    VerifiedSignature,
)

__version__ = "0.7.0"

__all__ = [
    "DIRECTORY_MEDIA_TYPE",
    "BudgetClaim",
    "EgressSigner",
    "HttpsigConfig",
    "HttpsigVerifier",
    "InMemoryMeter",
    "InsufficientBudget",
    "TokenRevoked",
    "InvalidBudgetClaim",
    "NotPublicURL",
    "UnitMismatch",
    "VerificationError",
    "VerifiedSignature",
    "ServerSigner",
    "content_digest",
    "sign_request",
    "build_person_token_requirement",
    "parse_signature_input",
    "parse_signature_key",
    "WBA_TAG",
    "__version__",
    "assert_public_url",
    "b64url",
    "ResponseSigner",
    "UsageQueryError",
    "build_usage_response",
    "make_revocation_endpoint",
    "make_usage_endpoint",
    "parse_usage_request",
    "validate_budget_grant",
    "build_aauth_budget_header",
    "build_aauth_requirement",
    "generate_seed",
    "jwk_thumbprint",
    "load_ed25519_jwk",
    "parse_signature_agent",
]
