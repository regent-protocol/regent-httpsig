"""AAuth Budgets (draft-hardt-aauth-budgets, editor's copy) — resource-side core.

The auth token carries a spending envelope::

    "budget": { "amount": 2000000, "unit": "USD", "decimals": 6 }   # = $2.00

and the resource meters every request against it: reserve the request's maximum
cost atomically, serve, commit the actual cost, release the difference. The
draft requires consumption to be aggregated atomically across all live auth
tokens for the key ``(iss, sub, aud)`` (§14.4), so the meter pools the grants
of a principal's live tokens and counts reservations + consumption against
that pool.

Everything here is framework-free; the FastAPI glue lives in
:mod:`regent_httpsig.fastapi` (``BudgetMiddleware``).
"""

from __future__ import annotations

import asyncio
import itertools
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "BudgetClaim",
    "InMemoryMeter",
    "InsufficientBudget",
    "InvalidBudgetClaim",
    "Reservation",
    "UnitMismatch",
]

MeterKey = tuple[str, str, str]  # (iss, sub, aud) — the draft's aggregation key


class InvalidBudgetClaim(ValueError):
    """A ``budget`` member is present but malformed (issuer bug — not spendable)."""


class UnitMismatch(ValueError):
    """A grant's unit/decimals differ from the pool's — one envelope, one unit."""


@dataclass(frozen=True)
class BudgetClaim:
    """The ``budget`` claim: integer amount in ``unit`` scaled by ``decimals``.

    ``amount=5000000, unit="USD", decimals=6`` is $5.00 — all arithmetic stays
    in integers; the scale only matters at display time.
    """

    amount: int
    unit: str
    decimals: int

    @staticmethod
    def parse(claims: Mapping[str, Any]) -> BudgetClaim | None:
        """Extract the claim from a token's claim set. ``None`` when absent;
        :class:`InvalidBudgetClaim` when present but malformed (all three
        members are REQUIRED, integers must be non-negative, bools are not
        integers here)."""
        raw = claims.get("budget")
        if raw is None:
            return None
        if not isinstance(raw, Mapping):
            raise InvalidBudgetClaim("budget claim must be an object")
        amount, unit, decimals = raw.get("amount"), raw.get("unit"), raw.get("decimals")
        if (
            isinstance(amount, bool) or not isinstance(amount, int) or amount < 0
            or not isinstance(unit, str) or not unit
            or isinstance(decimals, bool) or not isinstance(decimals, int) or decimals < 0
        ):
            raise InvalidBudgetClaim("budget claim requires amount/unit/decimals")
        return BudgetClaim(amount=amount, unit=unit, decimals=decimals)


@dataclass(frozen=True)
class Reservation:
    """An atomic hold on the pool for one in-flight request. Never revised —
    committed (with the actual cost) or released, exactly once."""

    rid: int
    key: MeterKey
    jti: str
    amount: int


@dataclass(frozen=True)
class InsufficientBudget:
    """Refusal: the request's maximum cost exceeds the pool's remaining balance.
    ``exhausted`` distinguishes the draft's two reason tokens: an empty envelope
    (``budget-exhausted``) vs a too-expensive request (``insufficient-budget``)."""

    remaining: int
    exhausted: bool


@dataclass
class _Pool:
    unit: str
    decimals: int
    grants: dict[str, tuple[int, float]] = field(default_factory=dict)  # jti -> (amount, exp)
    consumed: dict[str, int] = field(default_factory=dict)  # jti -> total committed
    reservations: dict[int, tuple[str, int, float]] = field(default_factory=dict)
    last_activity: float = 0.0


class InMemoryMeter:
    """Single-process meter (asyncio-safe). Right for a single-instance service;
    multi-replica deployments need a shared backend behind the same interface.

    Crash-safety is conservative: a reservation not committed or released within
    ``reservation_ttl`` seconds is treated as fully consumed — the owner's
    envelope is never silently under-counted by a crashed handler.
    """

    def __init__(self, *, reservation_ttl: float = 120.0,
                 retention_seconds: float = 7200.0) -> None:
        self._pools: dict[MeterKey, _Pool] = {}
        self._lock = asyncio.Lock()
        self._rids = itertools.count(1)
        self._reservation_ttl = reservation_ttl
        self._retention = retention_seconds

    # ── internals (call under lock) ──────────────────────────────────────────

    def _purge(self, key: MeterKey, now: float) -> _Pool | None:
        pool = self._pools.get(key)
        if pool is None:
            return None
        # Expired, unresolved reservations count as consumed (conservative).
        for rid, (jti, amount, deadline) in list(pool.reservations.items()):
            if deadline <= now:
                pool.consumed[jti] = pool.consumed.get(jti, 0) + amount
                del pool.reservations[rid]
        # Expired grants leave the pool; their consumption records remain for
        # budget_consumed reporting until the retention window passes.
        for jti, (_, exp) in list(pool.grants.items()):
            if exp <= now:
                del pool.grants[jti]
        if (not pool.grants and not pool.reservations
                and now - pool.last_activity > self._retention):
            del self._pools[key]
            return None
        return pool

    @staticmethod
    def _remaining(pool: _Pool) -> int:
        live = sum(a for a, _ in pool.grants.values())
        spent = sum(pool.consumed.get(jti, 0) for jti in pool.grants)
        held = sum(a for _, a, _ in pool.reservations.values())
        return max(0, live - spent - held)

    # ── public interface (the BudgetMeter contract) ──────────────────────────

    async def observe_grant(self, key: MeterKey, jti: str, claim: BudgetClaim,
                            exp: float) -> None:
        """Register a token's envelope in the principal's pool (idempotent per
        ``jti``). Raises :class:`UnitMismatch` if the pool already runs in a
        different unit — one envelope, one unit, no FX at the meter."""
        async with self._lock:
            now = time.monotonic()
            wall_delta = exp - time.time()
            pool = self._purge(key, now)
            if pool is None:
                pool = self._pools.setdefault(
                    key, _Pool(unit=claim.unit, decimals=claim.decimals))
            if (pool.unit, pool.decimals) != (claim.unit, claim.decimals):
                raise UnitMismatch(
                    f"pool runs in {pool.unit}/{pool.decimals}, "
                    f"grant is {claim.unit}/{claim.decimals}")
            pool.last_activity = now
            if jti not in pool.grants and wall_delta > 0:
                pool.grants[jti] = (claim.amount, now + wall_delta)

    async def reserve(self, key: MeterKey, jti: str,
                      max_cost: int) -> Reservation | InsufficientBudget:
        async with self._lock:
            now = time.monotonic()
            pool = self._purge(key, now)
            if pool is None or jti not in pool.grants:
                return InsufficientBudget(remaining=0, exhausted=True)
            remaining = self._remaining(pool)
            if max_cost > remaining:
                return InsufficientBudget(remaining=remaining,
                                          exhausted=remaining == 0)
            rid = next(self._rids)
            pool.reservations[rid] = (jti, max_cost, now + self._reservation_ttl)
            pool.last_activity = now
            return Reservation(rid=rid, key=key, jti=jti, amount=max_cost)

    async def commit(self, res: Reservation, actual: int) -> int:
        """Commit the actual cost (clamped to the reserved amount — reservations
        are never revised upward) and return the pool's remaining balance."""
        async with self._lock:
            now = time.monotonic()
            pool = self._purge(res.key, now)
            if pool is None:
                return 0
            held = pool.reservations.pop(res.rid, None)
            cost = min(max(actual, 0), held[1] if held else res.amount)
            pool.consumed[res.jti] = pool.consumed.get(res.jti, 0) + cost
            pool.last_activity = now
            return self._remaining(pool)

    async def release(self, res: Reservation) -> int:
        async with self._lock:
            pool = self._purge(res.key, time.monotonic())
            if pool is None:
                return 0
            pool.reservations.pop(res.rid, None)
            return self._remaining(pool)

    async def remaining(self, key: MeterKey) -> int:
        async with self._lock:
            pool = self._purge(key, time.monotonic())
            return 0 if pool is None else self._remaining(pool)

    async def consumed_records(self, key: MeterKey) -> list[dict[str, Any]]:
        """Per-token consumption for the resource token's ``budget_consumed``
        claim: ``[{"jti": ..., "consumed": ...}, ...]``. Non-destructive — the
        PS deduplicates by ``jti``, so reporting the same record twice is safe."""
        async with self._lock:
            pool = self._purge(key, time.monotonic())
            if pool is None:
                return []
            return [
                {"jti": jti, "consumed": total}
                for jti, total in sorted(pool.consumed.items())
                if total > 0
            ]
