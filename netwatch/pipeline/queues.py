"""
BoundedStageQueue — the seam between two pipeline stages.

A bounded queue is the whole reason this pipeline cannot be pushed into
swap. With an unbounded ``queue.Queue`` a capture stage faster than the
persistence stage does not fail; it grows, silently, until the process is
killed. With a bound, one of two things must happen instead, and the operator
chooses which:

    OverflowPolicy.BLOCK  the producer waits. Slowness propagates backwards
                          to the source, which is backpressure. No packet is
                          ever lost; the offered rate falls to the rate the
                          slowest stage can sustain.

    OverflowPolicy.DROP   the producer gives up after `put_timeout_s` and the
                          frame is counted in `dropped`. Loss is bounded,
                          visible and attributable to a specific queue —
                          which is what you want when the capture side is a
                          real NIC that will not wait for you.

Every drop is counted. Nothing in this module discards an item without
incrementing a counter that the pipeline's accounting identity checks.
"""

import queue
import threading
import time


class OverflowPolicy:
    BLOCK = 'block'
    DROP = 'drop'


class Closed(Exception):
    """Raised by ``get()`` when the queue is closed and drained."""


_SENTINEL = object()


class BoundedStageQueue:
    """A fixed-capacity queue that measures its own pressure.

    Metrics collected:
        depth / capacity / utilization   how full it is right now
        high_water                       the deepest it has ever been
        enqueued / dequeued / dropped    flow accounting
        block_events / blocked_s         how much backpressure actually bit
    """

    def __init__(self, name, capacity, policy=OverflowPolicy.BLOCK,
                 put_timeout_s=1.0):
        if capacity < 1:
            raise ValueError('queue capacity must be >= 1')
        self.name = name
        self.capacity = capacity
        self.policy = policy
        self.put_timeout_s = put_timeout_s
        self._q = queue.Queue(maxsize=capacity)
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self.enqueued = 0
        self.dequeued = 0
        self.dropped = 0
        self.block_events = 0
        self.blocked_ns = 0
        self.high_water = 0

    # ── producer side ────────────────────────────────────────────────────────

    def put(self, item):
        """Enqueue `item`. Returns True if accepted, False if dropped.

        Under BLOCK this waits as long as it takes, retrying around the
        timeout so a closing pipeline can still interrupt it. Under DROP it
        waits at most `put_timeout_s` before counting a loss.
        """
        try:
            self._q.put_nowait(item)
        except queue.Full:
            return self._put_slow(item)
        self._after_put()
        return True

    def _put_slow(self, item):
        started = time.perf_counter_ns()
        with self._lock:
            self.block_events += 1
        try:
            if self.policy == OverflowPolicy.DROP:
                self._q.put(item, timeout=self.put_timeout_s)
            else:
                while True:
                    if self._closed.is_set():
                        # A closed queue will never drain further; refusing
                        # here is what lets a shutdown interrupt backpressure
                        # instead of deadlocking on it.
                        with self._lock:
                            self.dropped += 1
                        return False
                    try:
                        self._q.put(item, timeout=self.put_timeout_s)
                        break
                    except queue.Full:
                        continue
        except queue.Full:
            with self._lock:
                self.dropped += 1
                self.blocked_ns += time.perf_counter_ns() - started
            return False
        with self._lock:
            self.blocked_ns += time.perf_counter_ns() - started
        self._after_put()
        return True

    def _after_put(self):
        with self._lock:
            self.enqueued += 1
            depth = self._q.qsize()
            if depth > self.high_water:
                self.high_water = depth

    # ── consumer side ────────────────────────────────────────────────────────

    def get(self, timeout=0.25):
        """Return the next item, or raise ``Closed`` once drained.

        Returns ``None`` on timeout so a worker can check its own stop flag
        between attempts rather than parking forever on a dead pipeline.
        """
        try:
            item = self._q.get(timeout=timeout)
        except queue.Empty:
            if self._closed.is_set() and self._q.empty():
                raise Closed from None
            return None
        if item is _SENTINEL:
            raise Closed
        with self._lock:
            self.dequeued += 1
        return item

    # ── lifecycle ────────────────────────────────────────────────────────────

    def close(self, consumers=1):
        """Signal end-of-stream to `consumers` waiting workers."""
        self._closed.set()
        for _ in range(consumers):
            try:
                self._q.put(_SENTINEL, timeout=2.0)
            except queue.Full:
                # Consumers also exit on the closed flag once drained, so a
                # full queue at shutdown is survivable, not a hang.
                pass

    @property
    def closed(self):
        return self._closed.is_set()

    def depth(self):
        return self._q.qsize()

    def utilization(self):
        return round(self._q.qsize() / self.capacity, 4)

    def snapshot(self):
        return {
            'name': self.name,
            'capacity': self.capacity,
            'policy': self.policy,
            'depth': self.depth(),
            'utilization': self.utilization(),
            'high_water': self.high_water,
            'high_water_utilization': round(self.high_water / self.capacity, 4),
            'enqueued': self.enqueued,
            'dequeued': self.dequeued,
            'dropped': self.dropped,
            'block_events': self.block_events,
            'blocked_s': round(self.blocked_ns / 1e9, 4),
        }
