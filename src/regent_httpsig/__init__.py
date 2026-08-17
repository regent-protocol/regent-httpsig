"""regent-httpsig — verify and sign AI agent HTTP traffic (RFC 9421).

Web Bot Auth (what OpenAI ships, what Cloudflare/AWS/Google verify) and AAuth
(draft-hardt), in plain Python. See https://github.com/regent-protocol/regent-httpsig
"""

from regent_httpsig.config import HttpsigConfig
from regent_httpsig.jwk import b64url, jwk_thumbprint, load_ed25519_jwk
from regent_httpsig.netguard import NotPublicURL, assert_public_url
from regent_httpsig.sfv import parse_signature_agent
from regent_httpsig.sign import DIRECTORY_MEDIA_TYPE, EgressSigner, generate_seed
from regent_httpsig.verify import WBA_TAG, HttpsigVerifier, VerifiedSignature

__version__ = "0.1.1"

__all__ = [
    "DIRECTORY_MEDIA_TYPE",
    "EgressSigner",
    "HttpsigConfig",
    "HttpsigVerifier",
    "NotPublicURL",
    "VerifiedSignature",
    "WBA_TAG",
    "__version__",
    "assert_public_url",
    "b64url",
    "generate_seed",
    "jwk_thumbprint",
    "load_ed25519_jwk",
    "parse_signature_agent",
]
