"""SSRF guard — the property that makes fetching attacker-named URLs safe."""

from __future__ import annotations

import pytest

from regent_httpsig import NotPublicURL, assert_public_url


async def test_loopback_rejected() -> None:
    with pytest.raises(NotPublicURL):
        await assert_public_url("https://127.0.0.1/keys")


async def test_metadata_ip_rejected() -> None:
    with pytest.raises(NotPublicURL):
        await assert_public_url("http://169.254.169.254/latest/meta-data/")


async def test_private_range_rejected() -> None:
    with pytest.raises(NotPublicURL):
        await assert_public_url("https://10.0.0.5:6379/")


async def test_non_http_scheme_rejected() -> None:
    with pytest.raises(NotPublicURL):
        await assert_public_url("ftp://example.com/x")


async def test_public_ip_allowed() -> None:
    await assert_public_url("https://1.1.1.1/keys")  # numeric → no DNS needed


async def test_allowlisted_host_bypasses() -> None:
    await assert_public_url("http://localhost:8000/x", frozenset({"localhost"}))
