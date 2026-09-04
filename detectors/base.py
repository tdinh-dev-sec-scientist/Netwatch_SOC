"""
Detector framework: shared state primitives and the Detector contract.

Detectors are stateful but bounded. Every per-key structure here prunes on
access and is swept by `expire()` so a long-running engine does not grow
without limit.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

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

    def __post_init__(self):
        if self.severity not in SEVERITY_ORDER:
            raise ValueError('invalid severity %r' % self.severity)
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError('confidence must be in [0,1]')
        if not self.techniques:
            raise ValueError('every finding must map to >=1 ATT&CK technique')


def is_internal(ip):
    """RFC1918 / loopback / link-local check without the ipaddress overhead."""
    if not ip or ':' in ip:
        return False
    try:
        a, b, _c, _d = (int(p) for p in ip.split('.'))
    except (ValueError, TypeError):
        return False
    if a == 10 or a == 127:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    return False


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
        """Record `item` under `key` and return the live count in the window.

        The count is what every caller thresholds on, so it has to exclude
        members that have aged out — pruning only above some size, as an
        earlier version did, let a detector with a threshold of 3 fire on three
        events hours apart and then describe them as "3 hosts in 300s". The
        dicts here are bounded by the thresholds that read them (tens of
        entries), so the scan is cheap next to the per-packet parse cost.
        """
        items = self._items[key]
        items[item] = ts
        cutoff = ts - self.window
        if any(t < cutoff for t in items.values()):
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
