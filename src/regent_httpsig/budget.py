"""AAuth Budgets (draft-hardt-aauth-budgets, editor's copy) — resource-side core.

The auth token carries a spending envelope::

    "budget": { "amount": 2000000, "unit": "USD", "decimals": 6 }   # = $2.00

and the resource meters every request against it: reserve the request's maximum
cost atomically, serve, commit the actual cost, release the difference.

Two things are counted, against different keys (draft §Aggregation):

* the **cap** is per auth token — committed consumption plus outstanding
  reservations against the presented ``jti`` never exceed *its* ``budget``;
  no cross-token arithmetic, one token never draws on a sibling's grant;
* the **ledger** is per person — consumption is posted to ``(iss, sub, aud)``
  for the consumption record and the usage counters. It is not a second
  ceiling: a request that fits its token's budget is never refused because
  of a per-person total.

(0.4 and earlier pooled a principal's live grants into one purse. That let a
jti spend past its own grant, so the figure recorded against it could exceed
what its issuer granted and the overflow — spent from a sibling's allocation —
was never attributed. Dropped in 0.5.0; the ``required`` member makes a
fragmented agent's re-authorization a calculation instead.)

Everything here is framework-free; the FastAPI glue lives in
:mod:`regent_httpsig.fastapi` (``BudgetMiddleware``).
"""

from __future__ import annotations

import asyncio
import itertools
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
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
    """A grant's unit/decimals differ from the ledger's — one envelope, one unit."""


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
    """An atomic hold on one token's budget for one in-flight request. Never
    revised — committed (with the actual cost) or released, exactly once."""

    rid: int
    key: MeterKey
    jti: str
    amount: int


@dataclass(frozen=True)
class InsufficientBudget:
    """Refusal: the request's maximum cost exceeds the presented token's
    remaining balance.
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
    jkt_of: dict[str, str] = field(default_factory=dict)  # jti -> presenting key thumbprint
    reservations: dict[int, tuple[str, int, float]] = field(default_factory=dict)
    last_activity: float = 0.0


@dataclass
class _ScopeCounters:
    """Calendar counters for one usage scope (draft §calendar-counters): running
    integers bucketed on UTC boundaries — no per-record history is kept."""

    all_time: int = 0
    day: int = 0
    week: int = 0
    month: int = 0
    year: int = 0
    day_start: float = 0.0
    week_start: float = 0.0
    month_start: float = 0.0
    year_start: float = 0.0

    def add(self, amount: int, wall: float) -> None:
        self._roll(wall)
        self.all_time += amount
        self.day += amount
        self.week += amount
        self.month += amount
        self.year += amount

    def snapshot(self, wall: float) -> dict[str, int]:
        self._roll(wall)
        return {"day": self.day, "week": self.week, "month": self.month,
                "year": self.year, "all_time": self.all_time}

    def _roll(self, wall: float) -> None:
        dt = datetime.fromtimestamp(wall, tz=UTC)
        day = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        week = day - timedelta(days=dt.weekday())  # Monday 00:00 UTC (ISO 8601)
        month = day.replace(day=1)
        year = month.replace(month=1)
        for name, start in (("day", day), ("week", week),
                            ("month", month), ("year", year)):
            ts = start.timestamp()
            if getattr(self, f"{name}_start") < ts:
                setattr(self, name, 0)
                setattr(self, f"{name}_start", ts)


class InMemoryMeter:
    """Single-process meter (asyncio-safe). Right for a single-instance service;
    multi-replica deployments need a shared backend behind the same interface.

    Crash-safety is conservative: a reservation not committed or released within
    ``reservation_ttl`` seconds is treated as fully consumed — the owner's
    envelope is never silently under-counted by a crashed handler.
    """

    def __init__(self, *, reservation_ttl: float = 120.0,
                 retention_seconds: float = 7200.0,
                 usage_key_retention: float = 86400.0) -> None:
        self._pools: dict[MeterKey, _Pool] = {}
        self._lock = asyncio.Lock()
        self._rids = itertools.count(1)
        self._reservation_ttl = reservation_ttl
        self._retention = retention_seconds
        # Usage counters (draft §usage-counters) — wall-clock, keyed by the
        # issuing PS so the endpoint only answers the party whose tokens we
        # accepted. Scope counters never expire (all_time reaches as far back
        # as the resource retains); per-key figures are pruned on IDLE time —
        # "SHOULD retain … at least 24 hours after that key's last metered
        # request" — so a key in continuous use is never pruned.
        self._usage_key_retention = usage_key_retention
        self._scope_usage: dict[tuple[str, str], _ScopeCounters] = {}  # (iss, sub)
        self._key_usage: dict[tuple[str, str], tuple[int, float]] = {}  # (iss, jkt) -> (total, last_wall)
        self._metering_unit: tuple[str, int] | None = None

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
                self._record_usage(key, pool, jti, amount)
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
    def _remaining(pool: _Pool, jti: str) -> int:
        """The presented token's balance: its grant minus what was committed
        against it minus what is held for it. Sibling tokens of the same
        person do not enter — the cap is per token (§Aggregation)."""
        grant = pool.grants.get(jti)
        if grant is None:
            return 0
        held = sum(a for j, a, _ in pool.reservations.values() if j == jti)
        return max(0, grant[0] - pool.consumed.get(jti, 0) - held)

    # ── public interface (the BudgetMeter contract) ──────────────────────────

    async def observe_grant(self, key: MeterKey, jti: str, claim: BudgetClaim,
                            exp: float, jkt: str = "") -> None:
        """Register a token's envelope under the person's ledger key (idempotent
        per ``jti``). ``jkt`` is the RFC 7638 thumbprint of the token's ``cnf`` key —
        recorded so consumption records can be scoped to the presenting agent
        (one agent must not learn about its siblings). Raises
        :class:`UnitMismatch` if the ledger already runs in a different unit —
        one envelope, one unit, no FX at the meter."""
        async with self._lock:
            now = time.monotonic()
            wall_delta = exp - time.time()
            pool = self._purge(key, now)
            if pool is None:
                pool = self._pools.setdefault(
                    key, _Pool(unit=claim.unit, decimals=claim.decimals))
            if (pool.unit, pool.decimals) != (claim.unit, claim.decimals):
                raise UnitMismatch(
                    f"ledger runs in {pool.unit}/{pool.decimals}, "
                    f"grant is {claim.unit}/{claim.decimals}")
            pool.last_activity = now
            if jkt:
                pool.jkt_of.setdefault(jti, jkt)
            if jti not in pool.grants and wall_delta > 0:
                pool.grants[jti] = (claim.amount, now + wall_delta)

    async def reserve(self, key: MeterKey, jti: str,
                      max_cost: int) -> Reservation | InsufficientBudget:
        async with self._lock:
            now = time.monotonic()
            pool = self._purge(key, now)
            if pool is None or jti not in pool.grants:
                return InsufficientBudget(remaining=0, exhausted=True)
            remaining = self._remaining(pool, jti)
            if max_cost > remaining:
                return InsufficientBudget(remaining=remaining,
                                          exhausted=remaining == 0)
            rid = next(self._rids)
            pool.reservations[rid] = (jti, max_cost, now + self._reservation_ttl)
            pool.last_activity = now
            return Reservation(rid=rid, key=key, jti=jti, amount=max_cost)

    async def commit(self, res: Reservation, actual: int) -> int:
        """Commit the actual cost (clamped to the reserved amount — reservations
        are never revised upward) and return the token's remaining balance."""
        async with self._lock:
            now = time.monotonic()
            pool = self._purge(res.key, now)
            if pool is None:
                return 0
            held = pool.reservations.pop(res.rid, None)
            cost = min(max(actual, 0), held[1] if held else res.amount)
            pool.consumed[res.jti] = pool.consumed.get(res.jti, 0) + cost
            pool.last_activity = now
            if cost > 0:
                self._record_usage(res.key, pool, res.jti, cost)
            return self._remaining(pool, res.jti)

    async def release(self, res: Reservation) -> int:
        async with self._lock:
            pool = self._purge(res.key, time.monotonic())
            if pool is None:
                return 0
            pool.reservations.pop(res.rid, None)
            return self._remaining(pool, res.jti)

    async def remaining(self, key: MeterKey, jti: str) -> int:
        """The presented token's remaining balance (0 for an unknown or
        expired ``jti``)."""
        async with self._lock:
            pool = self._purge(key, time.monotonic())
            return 0 if pool is None else self._remaining(pool, jti)

    def _record_usage(self, key: MeterKey, pool: _Pool, jti: str,
                      amount: int) -> None:
        """Post a committed cost to the usage counters (call under lock).
        Wall-clock, because calendar boundaries are UTC by definition."""
        if amount <= 0:
            return
        wall = time.time()
        iss, sub, _aud = key
        self._metering_unit = self._metering_unit or (pool.unit, pool.decimals)
        self._scope_usage.setdefault((iss, sub), _ScopeCounters()).add(amount, wall)
        jkt = pool.jkt_of.get(jti)
        if jkt:
            total, _ = self._key_usage.get((iss, jkt), (0, 0.0))
            self._key_usage[(iss, jkt)] = (total + amount, wall)

    async def usage_scope(self, iss: str, sub: str) -> dict[str, int] | None:
        """Calendar counters for a ``sub`` scope query, or ``None`` when the
        resource holds no figure — the endpoint then omits ``usage``, keeping
        "never seen" indistinguishable from "nothing consumed"."""
        async with self._lock:
            counters = self._scope_usage.get((iss, sub))
            return None if counters is None else counters.snapshot(time.time())

    async def usage_keys(self, iss: str, jkts: list[str]) -> dict[str, int]:
        """Per-key totals for a ``jkts`` query. Unrecognized or pruned keys are
        OMITTED, never reported as zero — absence means "cannot answer", a
        present zero would be a wrong answer to an allocation decision."""
        async with self._lock:
            wall = time.time()
            for pair, (_, last) in list(self._key_usage.items()):
                if wall - last > self._usage_key_retention:
                    del self._key_usage[pair]
            return {jkt: self._key_usage[(iss, jkt)][0]
                    for jkt in jkts if (iss, jkt) in self._key_usage}

    def metering_unit(self) -> tuple[str, int] | None:
        """The one unit every usage figure is denominated in (draft §one-unit),
        or ``None`` before the first commit."""
        return self._metering_unit

    async def consumed_record(self, key: MeterKey, jti: str) -> dict[str, Any] | None:
        """The consumption record for the resource token's ``budget_consumed``
        claim (draft §The Consumption Record): ``{"jti", "consumed"}`` for the
        PRESENTED token — its total metered so far — or ``None`` when nothing
        was metered against it. One record, the presented token's; the spend
        under a person's other tokens is the usage endpoint's to report."""
        async with self._lock:
            pool = self._purge(key, time.monotonic())
            if pool is None:
                return None
            total = pool.consumed.get(jti, 0)
            return {"jti": jti, "consumed": total} if total > 0 else None

    async def consumed_records(self, key: MeterKey,
                               jkt: str | None = None) -> list[dict[str, Any]]:
        """Audit view: per-token consumption under this ledger key,
        ``[{"jti": ..., "consumed": ...}, ...]``. Not what goes on the wire —
        the resource token carries :meth:`consumed_record` — but the figures a
        PS-side reconciliation or an operator wants to see.

        When ``jkt`` is given, records are scoped to tokens bound to that key:
        the agent carrying the resource token sees only its OWN spending, never
        its siblings' (privacy between a principal's agents, and no extra
        figures to infer the ceiling from). Consequence: an abandoned agent's
        records are never carried home by siblings — the PS-side conservative
        rule (unreported expired allocation = fully consumed) is the backstop."""
        async with self._lock:
            pool = self._purge(key, time.monotonic())
            if pool is None:
                return []
            return [
                {"jti": jti, "consumed": total}
                for jti, total in sorted(pool.consumed.items())
                if total > 0 and (jkt is None or pool.jkt_of.get(jti) == jkt)
            ]
