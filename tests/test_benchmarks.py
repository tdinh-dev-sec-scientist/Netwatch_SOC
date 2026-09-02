"""The benchmark harness itself.

If the tools that produce the numbers are wrong, the numbers are wrong. These
run each benchmark at a size small enough for CI and assert on the shape and
the invariants of what comes back — not on the values, which are properties of
the machine.
"""

import json
import os

import pytest

from benchmarks import common, pipeline_benchmark, query_benchmark, soak_test


def test_percentile_matches_a_hand_worked_example():
    values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    assert common.percentile(values, 50) == pytest.approx(5.5)
    assert common.percentile(values, 100) == 10
    assert common.percentile(values, 0) == 1


def test_percentile_of_nothing_is_zero():
    assert common.percentile([], 95) == 0.0


def test_percentile_of_one_sample_is_that_sample():
    assert common.percentile([42.0], 95) == 42.0


def test_summarize_reports_the_expected_keys():
    summary = common.summarize([1.0, 2.0, 3.0, 4.0])
    assert set(summary) == {'samples', 'mean_ms', 'p50_ms', 'p95_ms',
                            'p99_ms', 'min_ms', 'max_ms', 'stdev_ms'}
    assert summary['samples'] == 4
    assert summary['mean_ms'] == pytest.approx(2.5)


def test_summarize_of_nothing_is_safe():
    assert common.summarize([])['samples'] == 0


def test_environment_records_what_a_rerun_would_need(db_engine):
    env = common.environment(db_engine)
    for key in ('generated_at', 'python', 'platform', 'cpu_count',
                'postgres_version', 'pg_synchronous_commit'):
        assert env[key] is not None


def test_results_are_written_as_valid_json(tmp_path):
    path = common.write_results('unit', {'a': 1},
                                str(tmp_path / 'result.json'))
    with open(path, encoding='utf-8') as handle:
        assert json.load(handle) == {'a': 1}


def test_query_benchmark_targets_are_all_real_queries():
    names = {name for name, _fn in query_benchmark.QUERIES}
    assert set(query_benchmark.INDEX_TARGETED) <= names
    assert set(query_benchmark.EXPLAIN_SQL) <= names


def test_plan_kind_classifies_the_plans_it_reports_on():
    assert query_benchmark._plan_kind(['Seq Scan on alerts']) == 'seq scan'
    assert query_benchmark._plan_kind(
        ['Index Scan using ix_alerts_ts on alerts']) == 'index scan'
    assert query_benchmark._plan_kind(
        ['Index Only Scan using x on alerts']) == 'index-only scan'


@pytest.mark.slow
def test_pipeline_benchmark_runs_end_to_end(scratch_url, tmp_path):
    output = str(tmp_path / 'pipeline.json')
    code = pipeline_benchmark.main([
        '--packets', '400', '--repeats', '1', '--chunk-size', '64',
        '--batch-size', '128', '--persist-workers', '1', '--no-reset',
        '--database-url', scratch_url, '--json', output])
    assert code == 0
    with open(output, encoding='utf-8') as handle:
        payload = json.load(handle)
    assert payload['benchmark'] == 'pipeline_throughput'
    assert payload['accounting_balanced'] is True
    assert payload['total_dropped'] == 0
    assert payload['throughput_pps']['p50_pps'] > 0
    assert payload['best_run']['latency_end_to_end_ms']['samples'] > 0
    assert payload['environment']['postgres_version']


@pytest.mark.slow
def test_soak_test_reports_and_verifies_the_loss_ledger(scratch_url,
                                                        tmp_path):
    output = str(tmp_path / 'soak.json')
    code = soak_test.main([
        '--minutes', '0.12', '--rate', '600', '--batch-size', '128',
        '--chunk-size', '32', '--persist-workers', '1',
        '--sample-interval-s', '0.05',
        '--database-url', scratch_url, '--json', output])
    with open(output, encoding='utf-8') as handle:
        payload = json.load(handle)
    acct = payload['accounting']
    assert acct['frames_captured'] > 0
    assert (acct['packets_persisted'] + acct['packets_dropped']
            + acct['packets_parse_failed'] + acct['packets_write_failed']
            == acct['frames_captured'])
    assert payload['accounting_balanced'] is True
    assert payload['zero_dropped_frames'] is True
    assert payload['samples'], 'no resource samples were taken'
    assert code == 0, payload['failures']


@pytest.mark.slow
def test_soak_test_drop_policy_counts_and_attributes_its_losses(scratch_url,
                                                               tmp_path):
    """The DROP path must lose packets *visibly*, or the accounting is a lie."""
    output = str(tmp_path / 'soak_drop.json')
    soak_test.main([
        '--minutes', '0.1', '--rate', '0', '--drop-on-overflow',
        '--queue-size', '1', '--chunk-size', '16', '--batch-size', '16',
        '--persist-workers', '1', '--sample-interval-s', '0.05',
        '--database-url', scratch_url, '--json', output])
    with open(output, encoding='utf-8') as handle:
        payload = json.load(handle)
    acct = payload['accounting']
    assert payload['accounting_balanced'] is True
    if acct['packets_dropped']:
        assert any(q['dropped'] for q in payload['queues']), \
            'drops were counted but no queue owns them'


@pytest.mark.slow
def test_query_benchmark_compares_before_and_after(scratch_url, tmp_path):
    output = str(tmp_path / 'query.json')
    code = query_benchmark.main([
        '--alerts', '4000', '--packets', '4000', '--hosts', '120',
        '--repeats', '3', '--database-url', scratch_url,
        '--json', output])
    assert code == 0
    with open(output, encoding='utf-8') as handle:
        payload = json.load(handle)
    assert payload['dataset']['alerts'] >= 4000
    assert set(payload['before']) >= {'pooled', 'targeted', 'per_query',
                                      'plans'}
    assert payload['before']['pooled']['samples'] > 0
    assert payload['after']['pooled']['samples'] > 0
    assert len(payload['composite_indexes']) >= 10
    # Every query must appear in both passes so the comparison is like-for-like
    assert set(payload['before']['per_query']) == set(
        payload['after']['per_query'])


def test_results_directory_is_where_the_readme_says_it_is():
    assert os.path.basename(common.RESULTS_DIR) == 'results'
    assert os.path.isdir(os.path.dirname(common.RESULTS_DIR))
