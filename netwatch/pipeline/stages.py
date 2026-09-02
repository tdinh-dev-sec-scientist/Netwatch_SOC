"""
The five stages.

    CaptureStage      raw frames in from a FrameSource
    ParseStage        Ethernet/IP/L4/L7 decode into a parsed packet dict
    RulesStage        every detector evaluated against every packet
    PersistStage      batched writes to PostgreSQL
    ServeStage        feeds the live view the REST API reads

Each stage owns a worker pool, an input queue and an output queue, and does
the same three things in its loop: take an item, do real work, hand the result
on. The base class handles the parts that are identical and easy to get
subtly wrong — measuring service time separately from queue wait, propagating
end-of-stream exactly once per downstream consumer, and never letting one bad
item kill a worker.

**Stages exchange chunks of packets, never single packets.** The queue
handshake costs more than the work at these rates — see the note in
``queues.py`` — so the capture stage groups frames into chunks and every stage
downstream takes a list in and returns a list out. Chunks are closed on size
or on a short age deadline, so a quiet pipeline still moves packets promptly
instead of holding a half-full chunk indefinitely.

Threads, not processes, and the reason matters. The persistence stage spends
much of its time inside psycopg waiting on a socket, and psycopg releases the
GIL for that wait, so persistence overlaps with parsing and rule evaluation.
The parse and rules stages are pure-Python CPU work and do **not** get faster
with more threads — their worker counts are configurable because the right
value is 1 and it is better to be able to measure that than to assert it.
Horizontal scale for the CPU stages is more pipeline processes, not more
threads.
"""

import datetime as dt
import logging
import threading
import time

from netwatch.pipeline.metrics import StageMetrics
from netwatch.pipeline.queues import Closed

log = logging.getLogger('netwatch.pipeline')

UTC = dt.UTC


class Stage:
    """Base class: a worker pool between two bounded queues."""

    name = 'stage'

    def __init__(self, in_queue=None, out_queue=None, workers=1):
        if workers < 1:
            raise ValueError('%s needs at least one worker' % self.name)
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.workers = workers
        self.metrics = [StageMetrics(self.name, i) for i in range(workers)]
        self._threads = []
        self._stop = threading.Event()
        self._started = threading.Event()

    # ── contract for subclasses ──────────────────────────────────────────────

    def setup(self, worker_id):
        """Per-worker initialisation (a DB connection, an analyzer, ...)."""
        return

    def handle(self, chunk, ctx, metrics):
        """Process one chunk (a list). Return a chunk to forward, or None."""
        raise NotImplementedError

    def finish(self, ctx, metrics):
        """Called once per worker after the input queue is drained."""
        return

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self):
        for i in range(self.workers):
            thread = threading.Thread(target=self._run, args=(i,),
                                      name='%s-%d' % (self.name, i),
                                      daemon=True)
            thread.start()
            self._threads.append(thread)
        self._started.set()
        return self

    def stop(self):
        self._stop.set()

    @property
    def stopping(self):
        return self._stop.is_set()

    def join(self, timeout=None):
        deadline = None if timeout is None else time.time() + timeout
        for thread in self._threads:
            thread.join(None if deadline is None
                        else max(0.0, deadline - time.time()))
        return all(not t.is_alive() for t in self._threads)

    def alive(self):
        return any(t.is_alive() for t in self._threads)

    def _run(self, worker_id):
        metrics = self.metrics[worker_id]
        ctx = self.setup(worker_id)
        try:
            self._loop(ctx, metrics)
        finally:
            try:
                trailing = self.finish(ctx, metrics)
            except Exception:      # noqa: BLE001 - logged, never re-raised
                log.exception('%s worker %d failed while draining',
                              self.name, worker_id)
                trailing = None
            if trailing and self.out_queue is not None:
                for item in trailing:
                    if isinstance(item, list):
                        weight = len(item)
                    elif isinstance(item, dict):
                        weight = item.get('packets', 1)
                    else:
                        weight = 1
                    self.out_queue.put(item, weight)
                    metrics.items_out += weight

    def _loop(self, ctx, metrics):
        while True:
            if self._stop.is_set() and self.in_queue.depth() == 0:
                return
            waited = time.perf_counter_ns()
            try:
                item = self.in_queue.get()
            except Closed:
                return
            if item is None:                      # poll timeout
                metrics.wait_ns += time.perf_counter_ns() - waited
                continue
            metrics.wait_ns += time.perf_counter_ns() - waited

            count = len(item)
            metrics.items_in += count
            t0 = time.perf_counter_ns()
            try:
                result = self.handle(item, ctx, metrics)
            except Exception:      # noqa: BLE001 - one bad chunk is not fatal
                metrics.errors += 1
                log.exception('%s: dropping chunk of %d after handler error',
                              self.name, count)
                continue
            finally:
                elapsed = time.perf_counter_ns() - t0
                metrics.busy_ns += elapsed
                # Service time is recorded per packet, not per chunk, so the
                # histogram means the same thing whatever the chunk size is.
                if count:
                    metrics.service.record(elapsed / 1e6 / count)

            if result:
                if self.out_queue is not None:
                    self.out_queue.put(result, len(result))
                metrics.items_out += len(result)

    def close_output(self, consumers):
        if self.out_queue is not None:
            self.out_queue.close(consumers=consumers)

    def snapshot(self):
        from netwatch.pipeline.metrics import merge_stage_metrics
        return merge_stage_metrics(self.name, self.metrics)


# ── stage 1: capture ─────────────────────────────────────────────────────────

class CaptureStage(Stage):
    """Pulls frames from a ``FrameSource`` and pushes them into the pipeline.

    This is the only stage that is a producer rather than a transformer, so it
    does not inherit the base loop. It is also where every packet that will
    ever be accounted for is first counted: ``frames_captured`` is the left
    side of the loss identity.
    """

    name = 'capture'

    def __init__(self, source, out_queue, chunk_size=256,
                 chunk_max_age_s=0.05, **_kwargs):
        super().__init__(in_queue=None, out_queue=out_queue, workers=1)
        self.source = source
        self.chunk_size = max(1, chunk_size)
        self.chunk_max_age_s = chunk_max_age_s
        self.frames_captured = 0
        self.frames_enqueued = 0
        self.frames_dropped = 0
        self.chunks_emitted = 0
        self.exhausted = threading.Event()

    def _emit(self, chunk, metrics):
        t0 = time.perf_counter_ns()
        accepted = self.out_queue.put(chunk, len(chunk))
        if accepted:
            self.frames_enqueued += len(chunk)
            self.chunks_emitted += 1
            metrics.items_out += len(chunk)
        else:
            # A refused chunk is a refused chunk of packets: every frame in it
            # is counted as dropped, never quietly forgotten.
            self.frames_dropped += len(chunk)
        metrics.busy_ns += time.perf_counter_ns() - t0

    def _run(self, worker_id):
        metrics = self.metrics[worker_id]
        chunk = []
        opened = time.monotonic()
        size = self.chunk_size
        max_age = self.chunk_max_age_s
        try:
            for capture_ts, frame in self.source.frames():
                if self._stop.is_set():
                    break
                self.frames_captured += 1
                # The ingress stamp travels with the frame all the way to the
                # commit, which is what makes the end-to-end latency figure an
                # actual measurement rather than a stage-local one.
                chunk.append((capture_ts, time.perf_counter_ns(), frame))
                if (len(chunk) >= size
                        or time.monotonic() - opened >= max_age):
                    self._emit(chunk, metrics)
                    chunk = []
                    opened = time.monotonic()
        except Exception:      # noqa: BLE001 - a dead source ends the run
            metrics.errors += 1
            log.exception('capture source failed')
        finally:
            if chunk:
                self._emit(chunk, metrics)
            self.exhausted.set()

    def stop(self):
        super().stop()
        stop = getattr(self.source, 'stop', None)
        if callable(stop):
            stop()

    def snapshot(self):
        snap = super().snapshot()
        snap.update(frames_captured=self.frames_captured,
                    frames_enqueued=self.frames_enqueued,
                    frames_dropped=self.frames_dropped,
                    chunks_emitted=self.chunks_emitted,
                    chunk_size=self.chunk_size)
        return snap


# ── stage 2: protocol parsing ────────────────────────────────────────────────

class ParseStage(Stage):
    """Decodes wire bytes into a flat dict of protocol fields.

    A frame the analyzer cannot decode is a *failure*, not a drop: it was
    accepted by the pipeline and then could not be used. Keeping the two
    apart is the difference between "we are overloaded" and "we are being sent
    something we do not understand", which are different incidents.
    """

    name = 'parse'

    def __init__(self, in_queue, out_queue, workers=1, analyzer_factory=None):
        super().__init__(in_queue, out_queue, workers)
        if analyzer_factory is None:
            from netwatch.analysis.protocol import ProtocolAnalyzer
            analyzer_factory = ProtocolAnalyzer
        self.analyzer_factory = analyzer_factory
        self.analyzers = []
        self.parse_failures = 0

    def setup(self, worker_id):
        analyzer = self.analyzer_factory()
        self.analyzers.append(analyzer)
        return analyzer

    def handle(self, chunk, analyzer, metrics):
        parse = analyzer.safe_parse
        from_timestamp = dt.datetime.fromtimestamp
        out = []
        failures = 0
        for capture_ts, ingress_ns, frame in chunk:
            pkt = parse(frame, capture_ts)
            if pkt is None:
                failures += 1
                continue
            # Stamp the datetime forms the persistence layer needs exactly
            # once, here, rather than repeating the conversion per row per
            # table.
            when = from_timestamp(pkt['ts'], UTC)
            pkt['dt'] = when
            pkt['minute'] = when.replace(second=0, microsecond=0)
            pkt['_ingress_ns'] = ingress_ns
            out.append(pkt)
        if failures:
            self.parse_failures += failures
        return out

    def protocol_counts(self):
        merged = {}
        for analyzer in self.analyzers:
            for name, count in analyzer.stats.items():
                merged[name] = merged.get(name, 0) + count
        return merged

    def snapshot(self):
        snap = super().snapshot()
        snap['parse_failures'] = self.parse_failures
        snap['parse_errors'] = sum(a.parse_errors for a in self.analyzers)
        return snap


# ── stage 3: rules evaluation ────────────────────────────────────────────────

class RulesStage(Stage):
    """Runs every detector over every parsed packet.

    Single worker on purpose. Detector state is a set of sliding windows keyed
    on source, destination and flow; sharding it across threads would either
    need a lock per window (slower than the detection itself) or split one
    attacker's traffic across independent state, which changes what the
    detectors see and therefore what they find. The stage is configurable to
    more workers so that claim can be measured rather than asserted, but the
    default is the correct value.
    """

    name = 'rules'

    def __init__(self, in_queue, out_queue, engine, workers=1):
        super().__init__(in_queue, out_queue, workers)
        self.engine = engine
        self.findings_total = 0
        self._lock = threading.Lock() if workers > 1 else None

    def handle(self, chunk, _ctx, _metrics):
        analyze = self.engine.analyze
        out = []
        found = 0
        if self._lock is None:
            for pkt in chunk:
                findings = analyze(pkt)
                if findings:
                    found += len(findings)
                out.append((pkt, findings))
        else:
            with self._lock:
                for pkt in chunk:
                    findings = analyze(pkt)
                    if findings:
                        found += len(findings)
                    out.append((pkt, findings))
        if found:
            self.findings_total += found
        return out

    def snapshot(self):
        snap = super().snapshot()
        snap['findings_total'] = self.findings_total
        snap['packets_analyzed'] = self.engine.packets_analyzed
        snap['detector_errors'] = self.engine.detector_errors
        return snap


# ── stage 4: persistence ─────────────────────────────────────────────────────

class PersistStage(Stage):
    """Batches packets and findings, then commits them to PostgreSQL.

    Batching is the whole game. A transaction per packet is roughly two orders
    of magnitude slower than a transaction per few hundred packets, because
    the cost is dominated by round trips and WAL flushes rather than by the
    rows themselves. The batcher closes a batch on whichever comes first:
    `batch_size` packets, or `flush_interval_s` since the batch opened — so a
    quiet pipeline still has bounded write latency.

    Each worker holds its own BatchWriter and its own pooled connection.
    """

    name = 'persist'

    def __init__(self, in_queue, out_queue, writer_factory, workers=2,
                 batch_size=500, flush_interval_s=0.5, latency=None):
        super().__init__(in_queue, out_queue, workers)
        self.writer_factory = writer_factory
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.writers = []
        self.packets_persisted = 0
        self.alerts_persisted = 0
        self.packets_failed = 0
        self.batches_committed = 0
        self.batches_failed = 0
        self.latency = latency          # end-to-end Histogram, shared

    def setup(self, worker_id):
        writer = self.writer_factory()
        self.writers.append(writer)
        return {'writer': writer, 'packets': [], 'findings': [],
                'opened': time.monotonic()}

    def _flush(self, ctx, metrics):
        packets, findings = ctx['packets'], ctx['findings']
        if not packets and not findings:
            ctx['opened'] = time.monotonic()
            return None
        ctx['packets'], ctx['findings'] = [], []
        ctx['opened'] = time.monotonic()
        try:
            n_packets, n_alerts = ctx['writer'].write_batch(packets, findings)
        except Exception:      # noqa: BLE001 - counted, then reported
            self.packets_failed += len(packets)
            self.batches_failed += 1
            metrics.errors += 1
            log.exception('persist: batch of %d packets failed to commit',
                          len(packets))
            return None
        done_ns = time.perf_counter_ns()
        if self.latency is not None:
            for pkt in packets:
                ingress = pkt.get('_ingress_ns')
                if ingress:
                    self.latency.record((done_ns - ingress) / 1e6)
        self.packets_persisted += n_packets
        self.alerts_persisted += n_alerts
        self.batches_committed += 1
        return {'packets': n_packets, 'alerts': n_alerts,
                'findings': findings, 'committed_at': time.time()}

    def handle(self, chunk, ctx, metrics):
        packets = ctx['packets']
        for pkt, findings in chunk:
            packets.append(pkt)
            if findings:
                ctx['findings'].extend(findings)
        if (len(packets) >= self.batch_size
                or time.monotonic() - ctx['opened'] >= self.flush_interval_s):
            return self._flush(ctx, metrics)
        return None

    def finish(self, ctx, metrics):
        """Drain the open batch on shutdown. Nothing buffered is discarded."""
        if ctx is None:
            return None
        summary = self._flush(ctx, metrics)
        close = getattr(ctx['writer'], 'close', None)
        if callable(close):
            close()
        return [summary] if summary else None

    def _loop(self, ctx, metrics):
        """Same as the base loop, but a poll timeout also ages out a batch.

        Without this an idle pipeline holding 3 packets would never write them
        until the 4th arrived.
        """
        while True:
            if self._stop.is_set() and self.in_queue.depth() == 0:
                return
            waited = time.perf_counter_ns()
            try:
                item = self.in_queue.get()
            except Closed:
                return
            metrics.wait_ns += time.perf_counter_ns() - waited
            t0 = time.perf_counter_ns()
            count = 0
            if item is None:
                if (ctx['packets'] and
                        time.monotonic() - ctx['opened'] >=
                        self.flush_interval_s):
                    result = self._flush(ctx, metrics)
                else:
                    result = None
            else:
                count = len(item)
                metrics.items_in += count
                try:
                    result = self.handle(item, ctx, metrics)
                except Exception:      # noqa: BLE001
                    metrics.errors += 1
                    log.exception('persist: handler error')
                    result = None
            elapsed = time.perf_counter_ns() - t0
            metrics.busy_ns += elapsed
            if count:
                metrics.service.record(elapsed / 1e6 / count)
            if result is not None:
                metrics.items_out += result.get('packets', 0)
                if self.out_queue is not None:
                    self.out_queue.put(result)

    def snapshot(self):
        snap = super().snapshot()
        snap.update(packets_persisted=self.packets_persisted,
                    alerts_persisted=self.alerts_persisted,
                    packets_failed=self.packets_failed,
                    batches_committed=self.batches_committed,
                    batches_failed=self.batches_failed,
                    batch_size=self.batch_size,
                    writer_stats=[w.stats() for w in self.writers])
        return snap


# ── stage 5: serve ───────────────────────────────────────────────────────────

class ServeStage(Stage):
    """The API-facing end of the pipeline.

    Committed batches arrive here and update the live view that
    ``/api/pipeline/*`` and ``/api/live/alerts`` serve: a rolling throughput
    gauge and a bounded ring of the most recent alerts. The ring deliberately
    evicts its oldest entry when full — a live feed is allowed to forget, and
    every alert is durable in PostgreSQL regardless. Evictions are counted as
    `feed_evictions` and are never conflated with packet loss.
    """

    name = 'serve'

    def __init__(self, in_queue, feed, workers=1):
        super().__init__(in_queue, None, workers)
        self.feed = feed

    def _loop(self, ctx, metrics):
        """Summaries are single dicts rather than chunks, so this stage keeps
        its own loop instead of the chunk-shaped one in the base class."""
        while True:
            if self._stop.is_set() and self.in_queue.depth() == 0:
                return
            waited = time.perf_counter_ns()
            try:
                summary = self.in_queue.get()
            except Closed:
                return
            metrics.wait_ns += time.perf_counter_ns() - waited
            if summary is None:
                continue
            metrics.items_in += 1
            t0 = time.perf_counter_ns()
            try:
                self.feed.publish(summary)
            except Exception:      # noqa: BLE001 - a live view is not critical
                metrics.errors += 1
                log.exception('serve: failed to publish batch summary')
            elapsed = time.perf_counter_ns() - t0
            metrics.busy_ns += elapsed
            metrics.service.record(elapsed / 1e6)

    def handle(self, summary, _ctx, _metrics):
        self.feed.publish(summary)

    def snapshot(self):
        snap = super().snapshot()
        snap.update(self.feed.snapshot())
        return snap
