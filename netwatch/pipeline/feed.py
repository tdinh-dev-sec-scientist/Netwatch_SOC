"""
LiveFeed — the in-memory view stage 5 maintains for the REST API.

Everything here is a convenience over PostgreSQL, never a substitute for it:
the durable copy of every alert is already committed by the time a summary
reaches this stage. The feed exists so ``/api/pipeline/metrics`` and
``/api/live/alerts`` can answer in microseconds without a query, which is what
you want a dashboard polling every second to be doing.

Bounded by construction. The ring holds `capacity` alerts and evicts the
oldest beyond that; the eviction counter makes the loss explicit rather than
letting a reader assume the feed is complete.
"""

import threading
import time
from collections import deque

from netwatch.pipeline.metrics import RateWindow


class LiveFeed:
    def __init__(self, capacity=500, rate_window_s=10.0):
        self.capacity = capacity
        self._alerts = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self.packet_rate = RateWindow(rate_window_s)
        self.alert_rate = RateWindow(rate_window_s)
        self.batches_seen = 0
        self.packets_seen = 0
        self.alerts_seen = 0
        self.feed_evictions = 0
        self.last_commit_at = None

    def publish(self, summary):
        now = summary.get('committed_at') or time.time()
        self.packet_rate.record(summary.get('packets', 0), now)
        self.alert_rate.record(summary.get('alerts', 0), now)
        with self._lock:
            self.batches_seen += 1
            self.packets_seen += summary.get('packets', 0)
            self.alerts_seen += summary.get('alerts', 0)
            self.last_commit_at = now
            for finding in summary.get('findings') or ():
                if len(self._alerts) == self.capacity:
                    self.feed_evictions += 1
                self._alerts.append({
                    'ts': finding.ts,
                    'severity': finding.severity,
                    'threat_type': finding.threat_type,
                    'detector': finding.detector,
                    'src_ip': finding.src_ip,
                    'dst_ip': finding.dst_ip,
                    'protocol': finding.protocol,
                    'confidence': finding.confidence,
                    'description': finding.reason,
                    'techniques': list(finding.techniques),
                })

    def recent_alerts(self, limit=50, severity=None, threat_type=None):
        with self._lock:
            items = list(self._alerts)
        items.reverse()
        if severity:
            items = [a for a in items if a['severity'] == severity]
        if threat_type:
            items = [a for a in items if a['threat_type'] == threat_type]
        return items[:limit]

    def snapshot(self):
        with self._lock:
            return {
                'feed_capacity': self.capacity,
                'feed_size': len(self._alerts),
                'feed_evictions': self.feed_evictions,
                'batches_seen': self.batches_seen,
                'packets_seen': self.packets_seen,
                'alerts_seen': self.alerts_seen,
                'last_commit_at': self.last_commit_at,
                'packets_per_s_10s': self.packet_rate.rate(),
                'alerts_per_s_10s': self.alert_rate.rate(),
            }
