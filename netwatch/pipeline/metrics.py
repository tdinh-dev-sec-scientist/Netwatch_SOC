"""
Measurement primitives for the pipeline.

Two rules shaped this module:

1. **Counters are single-writer.** Every counter belongs to exactly one
   thread, and the aggregator sums them when a snapshot is taken. ``+=`` on a
   Python int is not atomic, so shared counters would need a lock on the hot
   path; giving each worker its own removes both the lock and the doubt.

2. **Latency is histogrammed, not listed.** A ten-minute soak at several
   thousand packets/sec produces millions of samples. Keeping them all would
   make the measurement apparatus the memory hog the pipeline is designed not
   to be, so samples land in a fixed log-linear histogram: bounded memory,
   percentile error bounded by the bucket width (<= 5% by construction).
"""

import math
import threading
import time

# 0.01 ms .. ~60 s, 20 buckets per power of two. Bucket width grows with the
# value, so relative error is constant rather than blowing up in the tail.
_MIN_MS = 0.01
_SUB_BUCKETS = 20
_MAX_MS = 60_000.0
_LOG_MIN = math.log2(_MIN_MS)
_N_BUCKETS = int((math.log2(_MAX_MS) - _LOG_MIN) * _SUB_BUCKETS) + 2


class Histogram:
    """Fixed-memory log-linear latency histogram in milliseconds."""

    __slots__ = ('_buckets', 'count', 'total', 'min_ms', 'max_ms')

    def __init__(self):
        self._buckets = [0] * _N_BUCKETS
        self.count = 0
        self.total = 0.0
        self.min_ms = float('inf')
        self.max_ms = 0.0

    def record(self, value_ms):
        self.count += 1
        self.total += value_ms
        self.min_ms = min(self.min_ms, value_ms)
        self.max_ms = max(self.max_ms, value_ms)
        if value_ms <= _MIN_MS:
            idx = 0
        else:
            idx = int((math.log2(value_ms) - _LOG_MIN) * _SUB_BUCKETS) + 1
            if idx >= _N_BUCKETS:
                idx = _N_BUCKETS - 1
        self._buckets[idx] += 1

    @staticmethod
    def _bucket_value(idx):
        if idx == 0:
            return _MIN_MS
        return 2.0 ** (_LOG_MIN + (idx - 0.5) / _SUB_BUCKETS)

    def merge(self, other):
        for i, n in enumerate(other._buckets):
            if n:
                self._buckets[i] += n
        self.count += other.count
        self.total += other.total
        self.min_ms = min(self.min_ms, other.min_ms)
        self.max_ms = max(self.max_ms, other.max_ms)
        return self

    def percentile(self, pct):
        if not self.count:
            return 0.0
        target = self.count * pct / 100.0
        seen = 0
        for idx, n in enumerate(self._buckets):
            seen += n
            if seen >= target:
                return round(self._bucket_value(idx), 4)
        return round(self.max_ms, 4)

    def summary(self):
        return {
            'samples': self.count,
            'mean_ms': round(self.total / self.count, 4) if self.count else 0.0,
            'min_ms': round(self.min_ms, 4) if self.count else 0.0,
            'p50_ms': self.percentile(50),
            'p95_ms': self.percentile(95),
            'p99_ms': self.percentile(99),
            'max_ms': round(self.max_ms, 4),
        }


class StageMetrics:
    """Per-worker counters plus a service-time histogram.

    Owned by exactly one worker thread. ``Pipeline.snapshot()`` reads these
    without a lock: each field is written by a single thread, and a snapshot
    that catches a counter one increment behind is fine for a rate gauge.
    Values used in the loss-accounting identity are only read after the
    pipeline has drained and every writer thread has joined.
    """

    __slots__ = ('stage', 'worker', 'items_in', 'items_out', 'errors',
                 'service', 'wait_ns', 'busy_ns')

    def __init__(self, stage, worker=0):
        self.stage = stage
        self.worker = worker
        self.items_in = 0
        self.items_out = 0
        self.errors = 0
        self.service = Histogram()
        self.wait_ns = 0
        self.busy_ns = 0

    def snapshot(self):
        return {
            'stage': self.stage,
            'worker': self.worker,
            'items_in': self.items_in,
            'items_out': self.items_out,
            'errors': self.errors,
            'busy_s': round(self.busy_ns / 1e9, 4),
            'queue_wait_s': round(self.wait_ns / 1e9, 4),
            'service_ms': self.service.summary(),
        }


def merge_stage_metrics(stage, metrics):
    """Fold every worker's metrics for one stage into a single view."""
    hist = Histogram()
    items_in = items_out = errors = 0
    wait_ns = busy_ns = 0
    for m in metrics:
        hist.merge(m.service)
        items_in += m.items_in
        items_out += m.items_out
        errors += m.errors
        wait_ns += m.wait_ns
        busy_ns += m.busy_ns
    return {
        'stage': stage,
        'workers': len(metrics),
        'items_in': items_in,
        'items_out': items_out,
        'errors': errors,
        'busy_s': round(busy_ns / 1e9, 4),
        'queue_wait_s': round(wait_ns / 1e9, 4),
        'service_ms': hist.summary(),
    }


class ResourceSampler:
    """Background sampler for process CPU and RSS.

    Optional: if psutil is not installed the pipeline still runs and the
    resource fields report as unavailable rather than the process failing.
    """

    def __init__(self, interval_s=1.0):
        self.interval_s = interval_s
        self.peak_rss_mb = 0.0
        self.mean_cpu_percent = 0.0
        self.samples = 0
        self.available = False
        self._cpu_total = 0.0
        self._thread = None
        self._stop = threading.Event()
        try:
            import psutil
            self._proc = psutil.Process()
            self.available = True
        except Exception:      # noqa: BLE001 - psutil is genuinely optional
            self._proc = None

    def start(self):
        if not self.available:
            return self
        self._proc.cpu_percent(None)      # prime the delta
        self._thread = threading.Thread(target=self._run, name='resource',
                                        daemon=True)
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.wait(self.interval_s):
            try:
                rss = self._proc.memory_info().rss / (1024 * 1024)
                cpu = self._proc.cpu_percent(None)
            except Exception:      # noqa: BLE001 - process may be exiting
                return
            self.peak_rss_mb = max(self.peak_rss_mb, rss)
            self._cpu_total += cpu
            self.samples += 1
            self.mean_cpu_percent = self._cpu_total / self.samples

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        return self

    def snapshot(self):
        if not self.available:
            return {'available': False}
        return {
            'available': True,
            'peak_rss_mb': round(self.peak_rss_mb, 2),
            'mean_cpu_percent': round(self.mean_cpu_percent, 2),
            'samples': self.samples,
            'cpu_count': _cpu_count(),
        }


def _cpu_count():
    import os
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


class RateWindow:
    """Rolling throughput over a short window, for the live metrics endpoint."""

    def __init__(self, window_s=10.0):
        self.window_s = window_s
        self._samples = []
        self._lock = threading.Lock()

    def record(self, count, now=None):
        now = now or time.time()
        with self._lock:
            self._samples.append((now, count))
            cutoff = now - self.window_s
            while self._samples and self._samples[0][0] < cutoff:
                self._samples.pop(0)

    def rate(self, now=None):
        now = now or time.time()
        with self._lock:
            cutoff = now - self.window_s
            while self._samples and self._samples[0][0] < cutoff:
                self._samples.pop(0)
            if len(self._samples) < 2:
                return 0.0
            span = self._samples[-1][0] - self._samples[0][0]
            if span <= 0:
                return 0.0
            return round(sum(c for _t, c in self._samples[1:]) / span, 1)
