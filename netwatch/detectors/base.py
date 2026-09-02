"""
Detector framework: shared state primitives and the Detector contract.

Detectors are stateful but bounded. Every per-key structure here prunes on
access and is swept by `expire()` so a long-running engine does not grow
without limit.
"""

import datetime as _dt
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

UTC = _dt.UTC

SEVERITY_ORDER = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


@dataclass
class Finding:
    """A single detection. Carries everything needed to build an alert row."""
    threat_type: str
    severity: str
    confidence: float
    reason: str
    techniques: tuple
    src_ip: str = None
    dst_ip: str = None
    src_port: int = None
    dst_port: int = None
    protocol: str = None
    detector: str = None
    ts: float = None
    evidence: dict = field(default_factory=dict)

    @property
    def dt(self):
        """Event time as a timezone-aware datetime, for the persistence layer.

        Detectors reason in epoch floats because sliding-window arithmetic is
        cheaper that way; the database stores TIMESTAMPTZ because that is the
        correct type for a point in time. This property is the one conversion
        point between the two.
        """
        return _dt.datetime.fromtimestamp(self.ts, UTC)

    def __post_init__(self):
        if self.severity not in SEVERITY_ORDER:
            raise ValueError('invalid severity %r' % self.severity)
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError('confidence must be in [0,1]')
        if not self.techniques:
            raise ValueError('every finding must map to >=1 ATT&CK technique')


#: Memoised results for is_internal(). A capture sees the same few thousand
#: addresses over and over, and the check was 10% of rule-evaluation time when
#: recomputed per packet. Bounded so a scan across a large address space
#: cannot grow it without limit.
_INTERNAL_CACHE = {}
_INTERNAL_CACHE_LIMIT = 65536


def is_internal(ip):
    """RFC1918 / loopback / link-local check without the ipaddress overhead."""
    cached = _INTERNAL_CACHE.get(ip)
    if cached is not None:
        return cached
    result = _is_internal_uncached(ip)
    if len(_INTERNAL_CACHE) >= _INTERNAL_CACHE_LIMIT:
        _INTERNAL_CACHE.clear()
    _INTERNAL_CACHE[ip] = result
    return result


def _is_internal_uncached(ip):
    if not ip or ':' in ip:
        return False
    try:
        a, b, _c, _d = (int(p) for p in ip.split('.'))
    except (ValueError, TypeError):
        return False
    if a in (10, 127):
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return a == 169 and b == 254


class TimedCounter:
    """Per-key deque of event timestamps, pruned to a sliding window."""

    def __init__(self, window_s):
        self.window = window_s
        self._events = defaultdict(deque)

    def add(self, key, ts):
        dq = self._events[key]
        dq.append(ts)
        cutoff = ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def count(self, key, now):
        dq = self._events.get(key)
        if not dq:
            return 0
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def timestamps(self, key):
        return self._events.get(key, ())

    def expire(self, now):
        cutoff = now - self.window
        for key in [k for k, dq in self._events.items()
                    if not dq or dq[-1] < cutoff]:
            del self._events[key]

    def __len__(self):
        return len(self._events)


class TimedSet:
    """Per-key set of distinct items, each with a last-seen timestamp."""

    def __init__(self, window_s):
        self.window = window_s
        self._items = defaultdict(dict)

    def add(self, key, item, ts):
        items = self._items[key]
        items[item] = ts
        cutoff = ts - self.window
        if len(items) > 8:  # prune lazily; scanning a tiny dict is wasted work
            for stale in [i for i, t in items.items() if t < cutoff]:
                del items[stale]
        return len(items)

    def size(self, key, now):
        items = self._items.get(key)
        if not items:
            return 0
        cutoff = now - self.window
        for stale in [i for i, t in items.items() if t < cutoff]:
            del items[stale]
        return len(items)

    def members(self, key):
        return list(self._items.get(key, {}))

    def expire(self, now):
        cutoff = now - self.window
        for key in [k for k, items in self._items.items()
                    if not items or max(items.values()) < cutoff]:
            del self._items[key]

    def __len__(self):
        return len(self._items)


class TimedSum:
    """Per-key running total over a sliding window of (ts, amount) samples."""

    def __init__(self, window_s):
        self.window = window_s
        self._samples = defaultdict(deque)
        self._totals = defaultdict(int)

    def add(self, key, amount, ts):
        dq = self._samples[key]
        dq.append((ts, amount))
        self._totals[key] += amount
        cutoff = ts - self.window
        while dq and dq[0][0] < cutoff:
            self._totals[key] -= dq.popleft()[1]
        return self._totals[key], len(dq)

    def total(self, key):
        return self._totals.get(key, 0)

    def count(self, key):
        return len(self._samples.get(key, ()))

    def reset(self, key):
        self._samples.pop(key, None)
        self._totals.pop(key, None)

    def expire(self, now):
        cutoff = now - self.window
        for key in [k for k, dq in self._samples.items()
                    if not dq or dq[-1][0] < cutoff]:
            del self._samples[key]
            self._totals.pop(key, None)

    def __len__(self):
        return len(self._samples)


class Detector:
    """Base class. Subclasses implement inspect() and declare their metadata.

    `techniques` is the full set of ATT&CK technique IDs this detector can
    emit; individual findings may map to a subset.
    """

    name = 'base'
    threat_type = 'base'
    description = ''
    techniques = ()
    # The highest severity this detector can emit. Seeded into
    # `threat_types.default_severity` so the severity band of a rule is a
    # property of the schema, not a constant buried in a branch.
    default_severity = 'MEDIUM'
    #: Protocols this detector can possibly fire on, or None for "any".
    #: This is a dispatch hint, not the guard: `inspect()` still checks for
    #: itself, so a wrong value here can only cost work, never change a
    #: verdict. The engine uses it to skip calls that would return [] on
    #: their first line, which is most calls for most detectors.
    protocols = None

    def __init__(self, cfg):
        self.cfg = cfg
        self._last_alert = {}
        self.findings_emitted = 0
        self.packets_seen = 0

    # ── contract ─────────────────────────────────────────────────────────────

    def inspect(self, pkt):
        """Return a list of Finding objects for this packet (usually empty)."""
        raise NotImplementedError

    def expire(self, now):
        """Drop state older than the detector's window. Override as needed."""
        cutoff = now - max(self.cfg.get('window_s', 300) * 4, 900)
        for key in [k for k, t in self._last_alert.items() if t < cutoff]:
            del self._last_alert[key]

    # ── helpers ──────────────────────────────────────────────────────────────

    def _cooled_down(self, key, ts, cooldown=None):
        """True if this key has not alerted within its cooldown period.

        Prevents one sustained attack from producing thousands of duplicate
        alerts while still re-alerting if the behaviour persists.
        """
        cooldown = cooldown if cooldown is not None else self.cfg.get(
            'cooldown_s', 300)
        last = self._last_alert.get(key)
        if last is not None and ts - last < cooldown:
            return False
        self._last_alert[key] = ts
        return True

    def _finding(self, pkt, severity, confidence, reason, techniques,
                 src_ip=None, dst_ip=None, **evidence):
        """Build a Finding from a packet.

        `src_ip`/`dst_ip` override the packet's own addresses for detectors
        that attribute an alert to a party other than the packet's sender —
        e.g. a server's "530 Login incorrect" is evidence against the client
        it was sent to.
        """
        self.findings_emitted += 1
        return Finding(
            threat_type=self.threat_type,
            severity=severity,
            confidence=round(confidence, 3),
            reason=reason,
            techniques=tuple(techniques),
            src_ip=src_ip or pkt.get('src_ip'),
            dst_ip=dst_ip or pkt.get('dst_ip'),
            src_port=pkt.get('src_port'),
            dst_port=pkt.get('dst_port'),
            protocol=pkt.get('protocol'),
            detector=self.name,
            ts=pkt.get('ts') or time.time(),
            evidence=evidence,
        )
