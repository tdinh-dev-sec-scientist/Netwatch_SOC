"""
Pipeline — wiring, lifecycle and accounting for the five stages.

    source -> [q_parse] -> parse -> [q_rules] -> rules -> [q_persist]
           -> persist -> [q_serve] -> serve -> live feed / REST API

Shutdown is a drain, not a kill. ``stop()`` tells the capture stage to stop
pulling from its source; once capture exits it closes the parse queue, which
ends the parse workers, which close the rules queue, and so on down the chain.
Every stage finishes the work already in front of it, and the persistence
stage commits its partially-filled batch on the way out. That is why the loss
identity holds exactly at the end of a run:

    frames_captured == packets_persisted + dropped + parse_failed + failed

``verify_accounting()`` asserts it, and the soak test fails if it does not.
"""

import logging
import threading
import time

from netwatch.pipeline.feed import LiveFeed
from netwatch.pipeline.metrics import Histogram, ResourceSampler
from netwatch.pipeline.queues import BoundedStageQueue, OverflowPolicy
from netwatch.pipeline.stages import (
    CaptureStage,
    ParseStage,
    PersistStage,
    RulesStage,
    ServeStage,
)

log = logging.getLogger('netwatch.pipeline')

STAGE_NAMES = ('capture', 'parse', 'rules', 'persist', 'serve')


class PipelineConfig:
    """Every knob in one place, so a benchmark can sweep them.

    Queue capacities are counted in **chunks**, not packets: a capacity of 64
    with a chunk size of 256 holds up to 16,384 packets in flight. They are
    sized so a stalled stage is felt within a second at the rates this
    pipeline runs, and so the memory a full pipeline can hold is a number you
    can work out rather than a hope. The persist queue is the deepest because
    it absorbs batch-boundary jitter: a writer committing a thousand rows is
    not reading its queue for the duration of that commit.

    `chunk_size` trades synchronisation cost against latency. Larger chunks
    make the per-packet queue overhead disappear; they also mean a packet
    waits for its chunk-mates. `chunk_max_age_s` bounds that wait, so at low
    offered rates a partial chunk still moves.
    """

    def __init__(self, parse_workers=1, rules_workers=1, persist_workers=2,
                 capture_queue=16, rules_queue=16, persist_queue=24,
                 serve_queue=256, batch_size=2000, flush_interval_s=0.5,
                 overflow_policy=OverflowPolicy.BLOCK, put_timeout_s=1.0,
                 feed_capacity=500, sample_resources=True, chunk_size=256,
                 chunk_max_age_s=0.05):
        self.chunk_size = chunk_size
        self.chunk_max_age_s = chunk_max_age_s
        self.parse_workers = parse_workers
        self.rules_workers = rules_workers
        self.persist_workers = persist_workers
        self.capture_queue = capture_queue
        self.rules_queue = rules_queue
        self.persist_queue = persist_queue
        self.serve_queue = serve_queue
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.overflow_policy = overflow_policy
        self.put_timeout_s = put_timeout_s
        self.feed_capacity = feed_capacity
        self.sample_resources = sample_resources

    def as_dict(self):
        return dict(vars(self))


class Pipeline:
    """Owns the stages, the queues between them and the run's measurements."""

    def __init__(self, source, rules_engine, writer_factory, config=None,
                 analyzer_factory=None, feed=None):
        self.config = config or PipelineConfig()
        cfg = self.config
        policy, timeout = cfg.overflow_policy, cfg.put_timeout_s

        self.q_parse = BoundedStageQueue('capture->parse', cfg.capture_queue,
                                         policy, timeout)
        self.q_rules = BoundedStageQueue('parse->rules', cfg.rules_queue,
                                         policy, timeout)
        self.q_persist = BoundedStageQueue('rules->persist',
                                           cfg.persist_queue, policy, timeout)
        # The serve queue never applies backpressure to persistence: a slow
        # dashboard must not be able to stall the write path. It drops, and
        # counts what it drops.
        self.q_serve = BoundedStageQueue('persist->serve', cfg.serve_queue,
                                         OverflowPolicy.DROP, 0.05)

        self.latency = Histogram()
        self.feed = feed or LiveFeed(capacity=cfg.feed_capacity)

        self.capture = CaptureStage(source, self.q_parse,
                                    chunk_size=cfg.chunk_size,
                                    chunk_max_age_s=cfg.chunk_max_age_s)
        self.parse = ParseStage(self.q_parse, self.q_rules,
                                workers=cfg.parse_workers,
                                analyzer_factory=analyzer_factory)
        self.rules = RulesStage(self.q_rules, self.q_persist, rules_engine,
                                workers=cfg.rules_workers)
        self.persist = PersistStage(self.q_persist, self.q_serve,
                                    writer_factory,
                                    workers=cfg.persist_workers,
                                    batch_size=cfg.batch_size,
                                    flush_interval_s=cfg.flush_interval_s,
                                    latency=self.latency)
        self.serve = ServeStage(self.q_serve, self.feed)

        self.stages = (self.capture, self.parse, self.rules, self.persist,
                       self.serve)
        self.queues = (self.q_parse, self.q_rules, self.q_persist,
                       self.q_serve)
        self.resources = ResourceSampler() if cfg.sample_resources else None

        self.started_at = None
        self.finished_at = None
        self._shutdown_thread = None
        self._done = threading.Event()

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self):
        self.started_at = time.time()
        if self.resources:
            self.resources.start()
        # Start downstream first so nothing is ever produced into a stage
        # whose consumers are not yet running.
        for stage in reversed(self.stages):
            stage.start()
        # The capture stage ends on its own when its source is exhausted;
        # this watcher turns that into an orderly drain of the whole chain.
        self._shutdown_thread = threading.Thread(
            target=self._watch_for_drain, name='pipeline-drain', daemon=True)
        self._shutdown_thread.start()
        return self

    def _watch_for_drain(self):
        self.capture.exhausted.wait()
        self._cascade_close()

    def _cascade_close(self):
        """Close each queue only once the stage feeding it has fully stopped.

        Doing this in order is what guarantees no in-flight item is stranded:
        a stage never sees end-of-stream before the last real item its
        producer sent.
        """
        self.capture.join()
        self.q_parse.close(consumers=self.parse.workers)
        self.parse.join()
        self.q_rules.close(consumers=self.rules.workers)
        self.rules.join()
        self.q_persist.close(consumers=self.persist.workers)
        self.persist.join()
        self.q_serve.close(consumers=self.serve.workers)
        self.serve.join()
        self.finished_at = time.time()
        if self.resources:
            self.resources.stop()
        self._done.set()

    def stop(self):
        """Ask the source to stop. Work already accepted still gets written."""
        self.capture.stop()
        return self

    def wait(self, timeout=None):
        """Block until the pipeline has fully drained."""
        return self._done.wait(timeout)

    def run_to_completion(self, timeout=None):
        """Start, wait for the source to run out, and drain. Returns a report."""
        self.start()
        if not self.wait(timeout):
            log.warning('pipeline did not drain within %ss; forcing stop',
                        timeout)
            self.stop()
            self.wait(30)
        return self.report()

    def shutdown(self, timeout=30.0):
        """Graceful stop for a long-running engine (SIGTERM handler calls it)."""
        self.stop()
        if not self.wait(timeout):
            log.warning('pipeline drain exceeded %.1fs', timeout)
        return self.report()

    # ── measurement ──────────────────────────────────────────────────────────

    @property
    def elapsed_s(self):
        if self.started_at is None:
            return 0.0
        return (self.finished_at or time.time()) - self.started_at

    def accounting(self):
        """The loss ledger. Every frame is in exactly one of these buckets."""
        captured = self.capture.frames_captured
        dropped = (self.capture.frames_dropped + self.q_rules.dropped
                   + self.q_persist.dropped)
        parse_failed = self.parse.parse_failures
        persisted = self.persist.packets_persisted
        failed = self.persist.packets_failed
        return {
            'frames_captured': captured,
            'frames_enqueued': self.capture.frames_enqueued,
            'packets_parsed': sum(m.items_out for m in self.parse.metrics),
            'packets_persisted': persisted,
            'packets_dropped': dropped,
            'packets_parse_failed': parse_failed,
            'packets_write_failed': failed,
            'alerts_persisted': self.persist.alerts_persisted,
            'in_flight': captured - persisted - dropped - parse_failed - failed,
        }

    def verify_accounting(self):
        """True when nothing is unaccounted for. Only meaningful after drain."""
        return self.accounting()['in_flight'] == 0

    def snapshot(self):
        """Live view: safe to call while running, used by the API."""
        elapsed = self.elapsed_s or 1e-9
        acct = self.accounting()
        return {
            'running': self.capture.alive() or self.persist.alive(),
            'elapsed_s': round(elapsed, 3),
            'config': self.config.as_dict(),
            'accounting': acct,
            'throughput': {
                'captured_per_s': round(acct['frames_captured'] / elapsed, 1),
                'persisted_per_s': round(acct['packets_persisted'] / elapsed,
                                         1),
                'alerts_per_s': round(acct['alerts_persisted'] / elapsed, 3),
            },
            'latency_end_to_end_ms': self.latency.summary(),
            'chunk_size': self.config.chunk_size,
            'queues': [q.snapshot() for q in self.queues],
            'stages': [s.snapshot() for s in self.stages],
            'resources': self.resources.snapshot() if self.resources
            else {'available': False},
        }

    def report(self):
        """Final report for a completed run. Adds the accounting verdict."""
        snap = self.snapshot()
        acct = snap['accounting']
        snap['accounting_balanced'] = acct['in_flight'] == 0
        snap['zero_loss'] = (acct['packets_dropped'] == 0
                             and acct['packets_write_failed'] == 0)
        snap['protocols_seen'] = self.parse.protocol_counts()
        return snap
