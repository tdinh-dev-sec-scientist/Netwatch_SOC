"""Benchmark reproducibility and target-verification tests."""

import json

import pytest

import benchmark
import pcap_io
from PacketSimulator import TrafficGenerator


def test_percentile_helper():
    values = list(range(1, 101))
    assert benchmark.percentile(values, 50) == 50.5
    assert benchmark.percentile(values, 100) == 100
    assert benchmark.percentile([], 95) == 0.0
    assert benchmark.percentile([7.0], 95) == 7.0


def test_summarize_shape():
    stats = benchmark.summarize([1.0, 2.0, 3.0, 4.0])
    assert stats['samples'] == 4
    assert stats['mean_ms'] == 2.5
    assert stats['max_ms'] == 4.0
    assert stats['p50_ms'] <= stats['p95_ms'] <= stats['p99_ms']


def test_workload_is_deterministic_for_a_seed():
    """Same seed must give byte-identical traffic, or nothing is reproducible."""
    a = benchmark.build_workload(300, seed=7, start_ts=1000.0)
    b = benchmark.build_workload(300, seed=7, start_ts=1000.0)
    assert len(a) == len(b)
    assert [frame for _ts, frame in a] == [frame for _ts, frame in b]

    c = benchmark.build_workload(300, seed=8, start_ts=1000.0)
    assert [f for _t, f in a] != [f for _t, f in c]


def test_workload_is_time_ordered_and_includes_attacks():
    frames = benchmark.build_workload(500, seed=7, start_ts=1000.0)
    timestamps = [ts for ts, _f in frames]
    assert timestamps == sorted(timestamps)
    assert len(frames) > 500  # background plus scenario frames
    assert set(benchmark.WORKLOAD_SCENARIOS) <= set(TrafficGenerator.SCENARIOS)


def test_capture_is_written_once_and_replayed_identically(tmp_path):
    """Every run must consume the same bytes, or the runs are incomparable."""
    path = str(tmp_path / 'bench.pcap')
    written, summary = benchmark.build_capture(path, 300, seed=7,
                                               start_ts=1000.0)
    assert written == summary['packets']

    again = str(tmp_path / 'bench2.pcap')
    benchmark.build_capture(again, 300, seed=7, start_ts=1000.0)
    assert pcap_io.pcap_summary(again)['sha256'] == summary['sha256']


def test_describe_reports_the_median_first():
    stats = benchmark.describe([100.0, 200.0, 300.0, 400.0, 500.0])
    assert stats['median'] == 300.0
    assert stats['runs'] == 5
    assert stats['min'] == 100.0 and stats['max'] == 500.0
    assert stats['stdev'] > 0


def test_describe_handles_a_single_run():
    stats = benchmark.describe([42.0])
    assert stats['median'] == stats['mean'] == 42.0
    assert stats['stdev'] == 0.0


def test_runs_must_exceed_warmup():
    """Discarding every run would leave nothing measured."""
    with pytest.raises(SystemExit):
        benchmark.main(['--runs', '1', '--warmup', '1'])


def test_benchmark_runs_end_to_end_and_meets_targets(tmp_path):
    """A small but complete run, asserting on the measured numbers."""
    out = tmp_path / 'results.json'
    exit_code = benchmark.main([
        '--runs', '3', '--warmup', '1', '--packets', '3000',
        '--query-repeats', '10',
        '--db', str(tmp_path / 'bench.db'), '--json', str(out),
    ])

    results = json.loads(out.read_text())
    throughput = results['throughput']
    latency = results['query_latency_overall']
    pipeline = throughput['pipeline_packets_per_s']

    assert throughput['measured_runs'] == 2
    assert throughput['warmup_runs'] == 1
    assert len(throughput['per_run_pipeline_packets_per_s']) == 2
    assert throughput['total_parse_errors'] == 0

    # The reported figure is the median of the measured runs, and it must
    # actually be that — not the mean, not the best run.
    assert pipeline['median'] == pytest.approx(
        sorted(throughput['per_run_pipeline_packets_per_s'])[
            len(throughput['per_run_pipeline_packets_per_s']) // 2]
        if len(throughput['per_run_pipeline_packets_per_s']) % 2
        else sum(throughput['per_run_pipeline_packets_per_s']) / 2, rel=0.01)
    assert pipeline['min'] <= pipeline['median'] <= pipeline['max']

    # Reading the capture off disk costs something, so replay must be the
    # slower of the two figures.
    assert throughput['replay_packets_per_s']['median'] <= pipeline['median']

    assert pipeline['median'] >= 1000, \
        'measured %.1f pkt/s' % pipeline['median']
    assert latency['p95_ms'] < 50, 'measured p95 %.3f ms' % latency['p95_ms']
    assert results['targets']['throughput_met'] is True
    assert results['targets']['query_latency_met'] is True
    assert exit_code == 0


def test_benchmark_records_methodology_with_its_numbers(tmp_path):
    """A figure without its method is not reproducible."""
    out = tmp_path / 'm.json'
    benchmark.main([
        '--runs', '2', '--warmup', '1', '--packets', '1500',
        '--query-repeats', '5', '--db', str(tmp_path / 'm.db'),
        '--json', str(out)])
    results = json.loads(out.read_text())
    method = results['methodology']
    assert method['reported_statistic'] == 'median across measured runs'
    assert method['warmup_runs_discarded'] == 1
    assert results['capture']['sha256']
    assert results['capture']['packets'] > 0
    assert results['python'] and results['scapy']
    assert results['cpu_count']


def test_benchmark_records_its_run_to_the_database(tmp_path):
    from DB_Manager import DatabaseManager
    db_path = tmp_path / 'bench2.db'
    benchmark.main([
        '--runs', '2', '--warmup', '1', '--packets', '1500',
        '--query-repeats', '5', '--db', str(db_path),
    ])
    db = DatabaseManager(str(db_path))
    try:
        rows = db.get_performance(limit=10, source='benchmark')
        assert rows, 'benchmark did not persist its measurements'
        assert rows[0]['packets_per_min'] > 0
        assert rows[0]['query_p95_ms'] > 0
    finally:
        db.close()


def test_every_api_backing_query_is_benchmarked():
    """The latency claim must cover the queries the API actually issues."""
    names = {name for name, _fn in benchmark.QUERIES}
    required = {
        'overview', 'alerts_recent_50', 'alert_detail', 'mitre_techniques',
        'mitre_technique_detail', 'mitre_coverage', 'top_hosts',
        'host_detail', 'geo_distribution', 'connections_recent',
        'packets_recent', 'performance_history', 'threat_summary',
        'protocol_distribution',
    }
    assert required <= names
    assert len(names) >= 14
