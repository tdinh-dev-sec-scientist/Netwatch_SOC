"""The five-stage pipeline: wiring, accounting, backpressure, shutdown.

The properties asserted here are the ones the résumé claims rest on, so they
are checked rather than assumed: every frame ends up in exactly one accounting
bucket, a full queue applies backpressure instead of growing, a drop is
counted and attributable, and a stop drains rather than discards.
"""

import time

import pytest
from conftest import SEED, build_workload, run_pipeline
from sqlalchemy import text

from netwatch.analysis.rules import RulesEngine
from netwatch.capture.generator import TrafficGenerator
from netwatch.capture.source import FrameSource, ListSource, SyntheticSource
from netwatch.pipeline import Pipeline, PipelineConfig
from netwatch.pipeline.queues import OverflowPolicy
from netwatch.pipeline.stages import (
    ParseStage,
)

STAGE_ORDER = ('capture', 'parse', 'rules', 'persist', 'serve')


class CountingWriter:
    """A writer that records what it was asked to persist."""

    def __init__(self):
        self.batches = []
        self.packets = 0
        self.alerts = 0

    def write_batch(self, packets, findings):
        self.batches.append((len(packets), len(findings)))
        self.packets += len(packets)
        self.alerts += len(findings)
        return len(packets), len(findings)

    def stats(self):
        return {'packets_written': self.packets}


class ExplodingWriter(CountingWriter):
    def __init__(self, fail_first=1):
        super().__init__()
        self.remaining_failures = fail_first

    def write_batch(self, packets, findings):
        if self.remaining_failures > 0:
            self.remaining_failures -= 1
            raise RuntimeError('database unavailable')
        return super().write_batch(packets, findings)


class SlowWriter(CountingWriter):
    def __init__(self, delay_s=0.05):
        super().__init__()
        self.delay_s = delay_s

    def write_batch(self, packets, findings):
        time.sleep(self.delay_s)
        return super().write_batch(packets, findings)


@pytest.fixture
def frames(gen):
    return gen.background(600, start_ts=time.time() - 60)


def build(source, writer_factory, cfg, **kwargs):
    return Pipeline(source, RulesEngine(cfg=cfg), writer_factory,
                    config=PipelineConfig(sample_resources=False, **kwargs))


# ── structure ────────────────────────────────────────────────────────────────

def test_pipeline_has_five_named_stages(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    assert tuple(s.name for s in pipeline.stages) == STAGE_ORDER


def test_stages_are_joined_by_four_bounded_queues(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    assert len(pipeline.queues) == 4
    assert [q.name for q in pipeline.queues] == [
        'capture->parse', 'parse->rules', 'rules->persist', 'persist->serve']
    for queue in pipeline.queues:
        assert queue.capacity > 0


def test_every_queue_is_bounded_and_none_grows_without_limit(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg,
                     capture_queue=2, rules_queue=2, persist_queue=2,
                     chunk_size=16)
    pipeline.run_to_completion(timeout=60)
    for queue in pipeline.queues:
        assert queue.high_water <= queue.capacity


# ── the loss ledger ──────────────────────────────────────────────────────────

def test_every_frame_lands_in_exactly_one_bucket(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    report = pipeline.run_to_completion(timeout=60)
    acct = report['accounting']
    assert acct['frames_captured'] == len(frames)
    assert acct['in_flight'] == 0
    assert report['accounting_balanced'] is True
    assert (acct['packets_persisted'] + acct['packets_dropped']
            + acct['packets_parse_failed'] + acct['packets_write_failed']
            == acct['frames_captured'])


def test_clean_run_loses_nothing(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    report = pipeline.run_to_completion(timeout=60)
    assert report['zero_loss'] is True
    assert report['accounting']['packets_dropped'] == 0
    assert report['accounting']['packets_persisted'] == len(frames)


def test_unparseable_frames_count_as_failed_not_dropped(cfg):
    """Garbage in is a parse failure — a different incident from overload."""
    junk = [(time.time(), b'\x00' * 8) for _ in range(20)]
    good = TrafficGenerator(seed=SEED).background(20, start_ts=time.time())
    pipeline = build(ListSource(junk + good), CountingWriter, cfg)
    report = pipeline.run_to_completion(timeout=60)
    acct = report['accounting']
    assert acct['packets_parse_failed'] == 20
    assert acct['packets_dropped'] == 0
    assert acct['packets_persisted'] == 20
    assert report['accounting_balanced'] is True


def test_a_failing_writer_produces_failed_packets_not_silent_loss(frames, cfg):
    writer = ExplodingWriter(fail_first=1)
    pipeline = build(ListSource(frames), lambda: writer, cfg,
                     persist_workers=1, batch_size=100, chunk_size=50)
    report = pipeline.run_to_completion(timeout=60)
    acct = report['accounting']
    assert acct['packets_write_failed'] > 0
    assert report['zero_loss'] is False
    assert report['accounting_balanced'] is True


# ── backpressure and drop policy ─────────────────────────────────────────────

def test_a_slow_sink_applies_backpressure_rather_than_dropping(frames, cfg):
    pipeline = build(ListSource(frames), lambda: SlowWriter(0.02), cfg,
                     capture_queue=1, rules_queue=1, persist_queue=1,
                     chunk_size=32, batch_size=32, persist_workers=1)
    report = pipeline.run_to_completion(timeout=120)
    assert report['accounting']['packets_dropped'] == 0
    assert report['accounting']['packets_persisted'] == len(frames)
    blocked = sum(q['blocked_s'] for q in report['queues'])
    assert blocked > 0, 'no queue ever blocked, so nothing was backpressured'


def test_drop_policy_drops_and_counts_when_the_sink_cannot_keep_up(frames,
                                                                  cfg):
    pipeline = build(ListSource(frames), lambda: SlowWriter(0.05), cfg,
                     capture_queue=1, rules_queue=1, persist_queue=1,
                     chunk_size=16, batch_size=16, persist_workers=1,
                     overflow_policy=OverflowPolicy.DROP, put_timeout_s=0.02)
    report = pipeline.run_to_completion(timeout=120)
    acct = report['accounting']
    assert acct['packets_dropped'] > 0, 'DROP policy dropped nothing'
    assert report['accounting_balanced'] is True
    # The loss must be attributable to a specific queue, not just a total.
    dropping = [q for q in report['queues'] if q['dropped']]
    assert dropping, 'drops were counted but no queue owns them'


def test_the_serve_queue_never_backpressures_the_write_path(frames, cfg):
    """A stalled dashboard must not be able to stall persistence."""
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    serve_queue = pipeline.q_serve
    assert serve_queue.policy == OverflowPolicy.DROP


# ── shutdown ─────────────────────────────────────────────────────────────────

def test_stop_drains_instead_of_discarding(cfg):
    source = SyntheticSource(seed=SEED, rate_pps=2000)
    writer = CountingWriter()
    pipeline = build(source, lambda: writer, cfg, chunk_size=32,
                     batch_size=64, persist_workers=1)
    pipeline.start()
    time.sleep(0.6)
    pipeline.stop()
    assert pipeline.wait(timeout=60), 'pipeline did not drain'
    report = pipeline.report()
    acct = report['accounting']
    assert acct['frames_captured'] > 0
    assert acct['in_flight'] == 0
    assert acct['packets_dropped'] == 0
    assert writer.packets == acct['packets_persisted']


def test_a_partially_filled_batch_is_committed_on_shutdown(cfg):
    """37 packets with a batch size of 1000 must still reach the writer."""
    frames = TrafficGenerator(seed=SEED).background(37, start_ts=time.time())
    writer = CountingWriter()
    pipeline = build(ListSource(frames), lambda: writer, cfg, batch_size=1000,
                     chunk_size=1000, persist_workers=1)
    report = pipeline.run_to_completion(timeout=60)
    assert writer.packets == 37
    assert report['accounting']['packets_persisted'] == 37


def test_exhausted_source_drains_the_whole_chain_without_being_told(frames,
                                                                   cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    pipeline.start()
    assert pipeline.wait(timeout=60)
    assert not any(stage.alive() for stage in pipeline.stages)


def test_shutdown_is_idempotent(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    pipeline.run_to_completion(timeout=60)
    pipeline.shutdown(timeout=5)
    pipeline.shutdown(timeout=5)
    assert pipeline.verify_accounting()


def test_a_source_that_raises_ends_the_run_cleanly(cfg):
    class BrokenSource(FrameSource):
        def frames(self):
            yield time.time(), TrafficGenerator(seed=SEED).background_frame(0)
            raise RuntimeError('NIC went away')

    pipeline = build(BrokenSource(), CountingWriter, cfg)
    report = pipeline.run_to_completion(timeout=60)
    assert report['accounting_balanced'] is True
    assert report['stages'][0]['errors'] == 1


# ── measurement ──────────────────────────────────────────────────────────────

def test_snapshot_answers_the_observability_questions(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    report = pipeline.run_to_completion(timeout=60)
    assert set(report) >= {'accounting', 'throughput', 'latency_end_to_end_ms',
                           'queues', 'stages', 'resources', 'config'}
    assert report['throughput']['persisted_per_s'] > 0
    assert report['latency_end_to_end_ms']['samples'] == len(frames)
    for stage in report['stages']:
        assert 'service_ms' in stage
    for queue in report['queues']:
        assert {'depth', 'high_water', 'utilization'} <= set(queue)


def test_end_to_end_latency_is_measured_per_packet(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    report = pipeline.run_to_completion(timeout=60)
    latency = report['latency_end_to_end_ms']
    assert latency['samples'] == len(frames)
    assert latency['p50_ms'] > 0
    assert latency['p99_ms'] >= latency['p50_ms']


def test_protocol_counts_come_from_the_parse_stage(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    report = pipeline.run_to_completion(timeout=60)
    seen = report['protocols_seen']
    assert sum(seen.values()) >= len(frames)
    assert 'DNS' in seen or 'TLS' in seen


def test_worker_counts_are_configurable_and_honoured(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg, parse_workers=3,
                     persist_workers=2)
    assert len(pipeline.parse.metrics) == 3
    assert len(pipeline.persist.metrics) == 2
    report = pipeline.run_to_completion(timeout=60)
    assert report['accounting_balanced'] is True
    assert report['accounting']['packets_persisted'] == len(frames)


def test_multiple_rules_workers_serialise_detector_state(frames, cfg):
    """More than one rules worker must take the lock, not race the state."""
    pipeline = build(ListSource(frames), CountingWriter, cfg, rules_workers=2)
    assert pipeline.rules._lock is not None
    report = pipeline.run_to_completion(timeout=60)
    assert report['accounting_balanced'] is True


def test_stage_workers_must_be_at_least_one():
    with pytest.raises(ValueError):
        ParseStage(None, None, workers=0)


# ── against PostgreSQL ───────────────────────────────────────────────────────

@pytest.mark.slow
def test_full_pipeline_writes_every_table(db_engine, repo, cfg, gen):
    frames = build_workload(gen, background=1200)
    report = run_pipeline(db_engine, frames, cfg=cfg)
    assert report['accounting_balanced'] is True
    assert report['accounting']['packets_dropped'] == 0
    counts = repo.health()['tables']
    for table in ('packets', 'hosts', 'flows', 'alerts', 'alert_techniques',
                  'protocol_stats'):
        assert counts[table] > 0, '%s was never written' % table


@pytest.mark.slow
def test_persisted_packet_count_matches_the_ledger(db_engine, repo, cfg, gen):
    frames = gen.background(800, start_ts=time.time() - 30)
    report = run_pipeline(db_engine, frames, cfg=cfg)
    with db_engine.connect() as conn:
        stored = conn.execute(text('SELECT COUNT(*) FROM packets')).scalar()
    assert stored == report['accounting']['packets_persisted'] == len(frames)


@pytest.mark.slow
def test_pipeline_survives_concurrent_persist_workers(db_engine, cfg, gen):
    frames = gen.background(2000, start_ts=time.time() - 30)
    report = run_pipeline(db_engine, frames, cfg=cfg, persist_workers=3,
                          batch_size=200, chunk_size=100)
    assert report['accounting_balanced'] is True
    assert report['accounting']['packets_write_failed'] == 0
    assert report['accounting']['packets_persisted'] == len(frames)


def test_live_feed_receives_committed_batches(frames, cfg):
    pipeline = build(ListSource(frames), CountingWriter, cfg)
    report = pipeline.run_to_completion(timeout=60)
    feed = pipeline.feed.snapshot()
    assert feed['batches_seen'] > 0
    assert feed['packets_seen'] == report['accounting']['packets_persisted']


def test_live_feed_is_bounded_and_counts_its_evictions(cfg):
    from netwatch.detectors.base import Finding
    from netwatch.pipeline.feed import LiveFeed

    feed = LiveFeed(capacity=10)
    for i in range(25):
        feed.publish({'packets': 1, 'alerts': 1, 'committed_at': time.time(),
                      'findings': [Finding(
                          threat_type='port_scan', severity='HIGH',
                          confidence=0.9, reason='r', techniques=('T1046',),
                          src_ip='10.0.0.%d' % (i % 250), ts=time.time())]})
    snapshot = feed.snapshot()
    assert snapshot['feed_size'] == 10
    assert snapshot['feed_evictions'] == 15
    assert len(feed.recent_alerts(limit=100)) == 10
