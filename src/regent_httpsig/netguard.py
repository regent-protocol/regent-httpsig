"""SSRF guard for identity-document fetching.

The verifier fetches key directories from attacker-nameable origins (whoever
signs a request chooses its ``Signature-Agent`` / ``iss``). Without a guard,
a malicious signer could point the verifier at internal services
(``http://redis:6379``, the cloud metadata IP ``169.254.169.254``, loopback,
other containers) and use your API as a proxy into your private network.

Every resolved address must be public; the check resolves (not just parses),
which also catches DNS names that map to private IPs."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

__all__ = ["NotPublicURL", "assert_public_url"]


class NotPublicURL(ValueError):
    """The URL does not resolve to an exclusively-public address."""


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


async def assert_public_url(url: str, allow_hosts: frozenset[str] = frozenset()) -> None:
    """Raise :class:`NotPublicURL` unless ``url`` is http(s) to an allow-listed
    host or a host whose EVERY resolved address is public."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise NotPublicURL(f"unsupported scheme {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise NotPublicURL("URL has no host")
    if host in allow_hosts:
        return
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, host, parsed.port or None, 0, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise NotPublicURL(f"cannot resolve host {host!r}") from exc
    ips = {str(info[4][0]) for info in infos}
    if not ips or any(not _is_public(ip) for ip in ips):
        raise NotPublicURL(
            f"host {host!r} resolves to a private/loopback/link-local address"
        )
