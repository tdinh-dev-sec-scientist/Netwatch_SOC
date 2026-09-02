"""Measurement primitives: histogram accuracy, rate window, stage rollups."""

import random

import pytest

from netwatch.pipeline.metrics import (
    Histogram,
    RateWindow,
    ResourceSampler,
    StageMetrics,
    merge_stage_metrics,
)


def exact_percentile(values, pct):
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def test_empty_histogram_reports_zeroes():
    summary = Histogram().summary()
    assert summary['samples'] == 0
    assert summary['p95_ms'] == 0.0


def test_histogram_counts_and_extremes():
    hist = Histogram()
    for value in (1.0, 2.0, 3.0):
        hist.record(value)
    summary = hist.summary()
    assert summary['samples'] == 3
    assert summary['mean_ms'] == pytest.approx(2.0)
    assert summary['min_ms'] == pytest.approx(1.0)
    assert summary['max_ms'] == pytest.approx(3.0)


@pytest.mark.parametrize('pct', [50, 95, 99])
def test_histogram_percentiles_are_within_five_percent(pct):
    """Bucket width bounds the error; the claim is <=5% and it is checked."""
    rng = random.Random(17)
    values = [rng.expovariate(1 / 8.0) + 0.05 for _ in range(50_000)]
    hist = Histogram()
    for value in values:
        hist.record(value)
    expected = exact_percentile(values, pct)
    assert hist.percentile(pct) == pytest.approx(expected, rel=0.05)


def test_histogram_handles_values_below_and_above_its_range():
    hist = Histogram()
    hist.record(0.0001)
    hist.record(500_000.0)
    assert hist.summary()['samples'] == 2
    assert hist.percentile(99) > 0


def test_histogram_memory_is_fixed_regardless_of_sample_count():
    small, large = Histogram(), Histogram()
    for _ in range(10):
        small.record(1.0)
    for _ in range(200_000):
        large.record(1.0)
    assert len(small._buckets) == len(large._buckets)


def test_histograms_merge():
    left, right = Histogram(), Histogram()
    for _ in range(100):
        left.record(1.0)
    for _ in range(100):
        right.record(10.0)
    left.merge(right)
    assert left.count == 200
    assert left.max_ms == pytest.approx(10.0)
    assert left.percentile(50) == pytest.approx(1.0, rel=0.05)


def test_stage_metrics_snapshot_shape():
    metrics = StageMetrics('parse', worker=2)
    metrics.items_in = 10
    metrics.items_out = 9
    metrics.errors = 1
    metrics.service.record(2.0)
    snap = metrics.snapshot()
    assert snap['stage'] == 'parse'
    assert snap['worker'] == 2
    assert snap['items_in'] == 10
    assert snap['service_ms']['samples'] == 1


def test_merge_stage_metrics_sums_across_workers():
    workers = []
    for i in range(3):
        metrics = StageMetrics('persist', i)
        metrics.items_in = 100
        metrics.items_out = 100
        metrics.busy_ns = 1_000_000_000
        metrics.service.record(5.0)
        workers.append(metrics)
    merged = merge_stage_metrics('persist', workers)
    assert merged['workers'] == 3
    assert merged['items_in'] == 300
    assert merged['busy_s'] == pytest.approx(3.0)
    assert merged['service_ms']['samples'] == 3


def test_rate_window_reports_zero_without_enough_samples():
    assert RateWindow(window_s=5).rate() == 0.0


def test_rate_window_measures_recent_throughput():
    window = RateWindow(window_s=10.0)
    base = 1_000_000.0
    for i in range(11):
        window.record(100, now=base + i)
    # 1000 packets recorded after the first sample, over a 10 second span.
    assert window.rate(now=base + 10) == pytest.approx(100.0, rel=0.05)


def test_rate_window_forgets_samples_outside_the_window():
    window = RateWindow(window_s=2.0)
    base = 1_000_000.0
    window.record(1000, now=base)
    window.record(1000, now=base + 1)
    assert window.rate(now=base + 60) == 0.0


def test_resource_sampler_is_optional_but_reports_when_available():
    sampler = ResourceSampler(interval_s=0.01).start()
    try:
        snap = sampler.snapshot()
        assert 'available' in snap
        if snap['available']:
            assert snap['cpu_count'] >= 1
    finally:
        sampler.stop()
