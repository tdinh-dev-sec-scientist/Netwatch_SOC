"""Benchmark reproducibility and target-verification tests."""

import json

import pytest

import benchmark
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


def test_undeduplicated_baseline_only_disables_cooldowns():
    """The reduction ratio is only honest if the baseline keeps every threshold."""
    import config

    tuned = config.load()
    baseline = benchmark.undeduplicated_config(tuned)

    for section, values in tuned.items():
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            if key == 'cooldown_s':
                assert baseline[section][key] == 0, section
            else:
                assert baseline[section][key] == value, \
                    'baseline changed %s.%s — that inflates the reduction' % (
                        section, key)
    assert tuned == config.load(), 'baseline mutated the tuned config'


def test_alert_reduction_suppresses_duplicates_without_losing_incidents(tmp_path):
    """The headline reduction claim, measured end to end."""
    from DB_Manager import DatabaseManager
    import config

    db = DatabaseManager(str(tmp_path / 'reduction.db'))
    try:
        result = benchmark.run_alert_reduction(
            db,
            benchmark.build_workload(4000, seed=21, start_ts=1000.0),
            TrafficGenerator(9021).background(4000, start_ts=1000.0),
            config.load())
    finally:
        db.close()

    assert result['undeduplicated_alerts'] > result['tuned_alerts'] > 0
    assert result['reduction_pct'] > 50
    # Suppression must be lossless: same incidents, fewer alerts.
    assert result['incidents_lost'] == [], result['incidents_lost']
    assert result['distinct_incidents_tuned'] == \
        result['distinct_incidents_undeduplicated']
    assert result['benign_alerts'] == 0
    assert sum(result['tuned_severity_mix'].values()) == result['tuned_alerts']


def test_reduction_results_are_reproducible_for_a_seed(tmp_path):
    from DB_Manager import DatabaseManager
    import config

    def run(name):
        db = DatabaseManager(str(tmp_path / name))
        try:
            return benchmark.run_alert_reduction(
                db,
                benchmark.build_workload(2000, seed=5, start_ts=1000.0),
                TrafficGenerator(9005).background(2000, start_ts=1000.0),
                config.load())
        finally:
            db.close()

    assert run('a.db') == run('b.db')


def test_detection_rate_scores_every_scenario_against_its_label():
    """The detection claim: every labelled attack, at every seed, is caught."""
    import config

    result = benchmark.run_detection_rate(config.load(), [11, 22], 1000)

    assert result['scenarios'] == len(TrafficGenerator.SCENARIOS)
    assert result['captures'] == result['scenarios'] * 2
    assert result['misses'] == [], result['misses']
    assert result['detection_rate_pct'] == 100.0
    for name, counts in result['per_scenario'].items():
        assert counts['detected'] == counts['captures'], name


def test_detection_rate_reports_a_scenario_it_cannot_catch():
    """A rate nothing can fail is not a measurement — prove a miss is caught."""
    import config

    cfg = config.load()
    cfg['port_scan']['distinct_ports'] = 100000  # unreachable threshold

    result = benchmark.run_detection_rate(cfg, [11], 1000)

    assert result['detection_rate_pct'] < 100.0
    missed = {miss['scenario'] for miss in result['misses']}
    assert 'port_scan' in missed
    assert result['per_scenario']['port_scan']['detected'] == 0
    # Only the sabotaged detector goes quiet; the rest still score.
    assert result['detected'] == result['captures'] - len(result['misses'])


def test_detection_counts_only_the_labelled_threat_type():
    """Firing *some* alert must not count as detecting the attack."""
    import config

    cfg = config.load()
    cfg['brute_force']['failures'] = 100000

    result = benchmark.run_detection_rate(cfg, [11], 1000)
    brute = result['per_scenario']['brute_force']
    misses = [m for m in result['misses'] if m['scenario'] == 'brute_force']

    assert brute['detected'] == 0, \
        'brute_force scored as detected despite its detector being disabled'
    # The scenario still raises credential_attack; that must not rescue it.
    assert misses and 'brute_force' not in misses[0]['fired']


def test_benchmark_runs_end_to_end_and_meets_targets(tmp_path):
    """A small but complete run, asserting on the measured numbers."""
    out = tmp_path / 'results.json'
    exit_code = benchmark.main([
        '--iterations', '2', '--packets', '4000', '--query-repeats', '10',
        '--detection-seeds', '2', '--detection-background', '800',
        '--db', str(tmp_path / 'bench.db'), '--json', str(out),
    ])

    results = json.loads(out.read_text())
    throughput = results['throughput']
    latency = results['query_latency_overall']

    assert throughput['iterations'] == 2
    assert throughput['total_packets'] > 8000
    assert throughput['total_parse_errors'] == 0
    assert throughput['mean_packets_per_min'] > 0

    # Targets from the project's performance claims.
    assert throughput['mean_packets_per_min'] >= 5000, \
        'measured %.1f pkt/min' % throughput['mean_packets_per_min']
    assert latency['p95_ms'] < 50, 'measured p95 %.3f ms' % latency['p95_ms']
    assert results['targets']['throughput_met'] is True
    assert results['targets']['query_latency_met'] is True
    assert exit_code == 0

    # packets/s is reported alongside packets/min and agrees with it
    # (each is rounded independently, so compare relatively).
    assert throughput['median_packets_per_s'] > 0
    assert throughput['mean_packets_per_s'] * 60 == pytest.approx(
        throughput['mean_packets_per_min'], rel=1e-4)
    for run in results['throughput_runs']:
        assert run['packets_per_s'] * 60 == pytest.approx(
            run['packets_per_min'], rel=1e-4)

    # The alert-reduction phase ran and is recorded in the JSON.
    reduction = results['alert_reduction']
    assert reduction['tuned_alerts'] > 0
    assert reduction['reduction_pct'] > 0
    assert reduction['incidents_lost'] == []
    assert results['targets']['no_incident_lost_to_suppression'] is True

    # The detection phase ran and is recorded in the JSON.
    detection = results['detection']
    assert detection['captures'] == detection['scenarios'] * 2
    assert detection['detection_rate_pct'] == 100.0
    assert results['targets']['every_labelled_attack_detected'] is True


def test_reduction_phase_can_be_skipped(tmp_path):
    out = tmp_path / 'skipped.json'
    exit_code = benchmark.main([
        '--iterations', '1', '--packets', '2000', '--query-repeats', '5',
        '--skip-reduction', '--skip-detection',
        '--db', str(tmp_path / 'skip.db'),
        '--json', str(out),
    ])
    results = json.loads(out.read_text())
    assert results['alert_reduction'] is None
    assert results['targets']['no_incident_lost_to_suppression'] is None
    assert exit_code == 0


def test_detection_phase_can_be_skipped(tmp_path):
    out = tmp_path / 'nodetect.json'
    exit_code = benchmark.main([
        '--iterations', '1', '--packets', '2000', '--query-repeats', '5',
        '--skip-detection', '--db', str(tmp_path / 'nodetect.db'),
        '--json', str(out),
    ])
    results = json.loads(out.read_text())
    assert results['detection'] is None
    assert results['targets']['every_labelled_attack_detected'] is None
    assert exit_code == 0


def test_benchmark_records_its_run_to_the_database(tmp_path):
    from DB_Manager import DatabaseManager
    db_path = tmp_path / 'bench2.db'
    benchmark.main([
        '--iterations', '1', '--packets', '2000', '--query-repeats', '5',
        '--skip-detection', '--db', str(db_path),
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
