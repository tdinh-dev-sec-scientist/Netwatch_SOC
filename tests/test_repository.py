"""The read layer: pagination, filtering, sorting, aggregates and plans.

Two kinds of assertion here. Most check *what* a query returns. A few check
*how* PostgreSQL executes it, because "this endpoint is indexed" is a claim
about the plan, and a plan can regress silently while the result stays right.
"""

import time

import pytest
from sqlalchemy import text

from netwatch.db.repository import (
    ALERT_SORTS,
    FLOW_SORTS,
    HOST_SORTS,
    PACKET_SORTS,
)

PAGE_KEYS = {'total', 'count', 'limit', 'offset', 'has_more', 'next_offset'}


# ── empty database ───────────────────────────────────────────────────────────

def test_empty_database_returns_empty_collections_not_errors(repo):
    assert repo.get_alerts()['alerts'] == []
    assert repo.get_alerts()['total'] == 0
    assert repo.get_packets()['packets'] == []
    assert repo.get_flows()['flows'] == []
    assert repo.get_hosts()['hosts'] == []
    assert repo.get_geo_distribution() == []
    assert repo.get_throughput() == []
    assert repo.get_threat_summary() == []
    assert repo.get_alert(1) is None
    assert repo.get_host('10.0.0.1') is None
    assert repo.get_mitre_technique('T9999') is None


def test_overview_on_an_empty_database_is_all_zeroes(repo):
    overview = repo.get_overview()
    assert overview['total_alerts'] == 0
    assert overview['mean_confidence'] == 0.0
    assert overview['packets_last_hour'] == 0


def test_reference_data_is_present_even_when_empty_of_observations(repo):
    assert len(repo.get_mitre_techniques()) >= 15
    assert len(repo.get_protocol_catalog()) >= 20
    assert len(repo.get_threat_types()) == 17


# ── populated: pagination ────────────────────────────────────────────────────

def test_alert_pagination_envelope(populated_repo):
    page = populated_repo.get_alerts(limit=3, offset=0)
    assert set(page) >= PAGE_KEYS
    assert page['count'] == len(page['alerts']) <= 3
    assert page['limit'] == 3
    assert page['offset'] == 0
    if page['total'] > 3:
        assert page['has_more'] is True
        assert page['next_offset'] == 3


def test_pages_do_not_overlap_and_cover_the_set(populated_repo):
    total = populated_repo.get_alerts(limit=1)['total']
    seen = []
    offset = 0
    while offset < total:
        page = populated_repo.get_alerts(limit=5, offset=offset)
        seen.extend(a['id'] for a in page['alerts'])
        offset += 5
    assert len(seen) == total
    assert len(set(seen)) == total


def test_last_page_reports_no_more(populated_repo):
    total = populated_repo.get_alerts(limit=1)['total']
    page = populated_repo.get_alerts(limit=1000, offset=0)
    assert page['count'] == total
    assert page['has_more'] is False
    assert page['next_offset'] is None


def test_offset_beyond_the_end_returns_an_empty_page(populated_repo):
    page = populated_repo.get_alerts(limit=10, offset=1_000_000)
    assert page['alerts'] == []
    assert page['has_more'] is False


@pytest.mark.parametrize('getter,key', [
    ('get_packets', 'packets'), ('get_flows', 'flows'), ('get_hosts', 'hosts'),
    ('get_pipeline_runs', 'runs'),
])
def test_every_collection_returns_the_same_envelope(populated_repo, getter,
                                                    key):
    page = getattr(populated_repo, getter)(limit=2)
    assert set(page) >= PAGE_KEYS
    assert key in page


# ── populated: filtering and sorting ─────────────────────────────────────────

def test_alerts_filter_by_severity(populated_repo):
    for severity in ('CRITICAL', 'HIGH', 'MEDIUM'):
        page = populated_repo.get_alerts(limit=100, severity=severity)
        assert all(a['severity'] == severity for a in page['alerts'])


def test_alerts_filter_by_threat_type(populated_repo):
    kinds = {a['threat_type']
             for a in populated_repo.get_alerts(limit=200)['alerts']}
    assert kinds
    chosen = sorted(kinds)[0]
    page = populated_repo.get_alerts(limit=100, threat_type=chosen)
    assert page['total'] > 0
    assert all(a['threat_type'] == chosen for a in page['alerts'])


def test_alerts_filter_by_source_ip(populated_repo):
    first = populated_repo.get_alerts(limit=1)['alerts'][0]
    page = populated_repo.get_alerts(limit=100, src_ip=first['src_ip'])
    assert page['total'] > 0
    assert all(a['src_ip'] == first['src_ip'] for a in page['alerts'])


def test_alerts_filter_by_time_window(populated_repo):
    cutoff = time.time() - 600
    page = populated_repo.get_alerts(limit=200, since=cutoff)
    assert all(a['ts'] > cutoff for a in page['alerts'])


def test_alerts_filter_by_minimum_confidence(populated_repo):
    page = populated_repo.get_alerts(limit=200, min_confidence=0.9)
    assert all(a['confidence'] >= 0.9 for a in page['alerts'])


def test_filters_combine(populated_repo):
    page = populated_repo.get_alerts(limit=100, severity='HIGH',
                                     acknowledged=False)
    for alert in page['alerts']:
        assert alert['severity'] == 'HIGH'
        assert alert['acknowledged'] is False


def test_a_filter_matching_nothing_returns_an_empty_page(populated_repo):
    page = populated_repo.get_alerts(limit=10, src_ip='203.0.113.254')
    assert page['total'] == 0
    assert page['alerts'] == []


@pytest.mark.parametrize('sort', sorted(ALERT_SORTS))
def test_alerts_sort_keys_all_work(populated_repo, sort):
    for order in ('asc', 'desc'):
        page = populated_repo.get_alerts(limit=10, sort=sort, order=order)
        assert page['count'] <= 10


def test_alerts_default_sort_is_newest_first(populated_repo):
    stamps = [a['ts'] for a in populated_repo.get_alerts(limit=50)['alerts']]
    assert stamps == sorted(stamps, reverse=True)


def test_alerts_ascending_sort_reverses_the_order(populated_repo):
    stamps = [a['ts'] for a in populated_repo.get_alerts(
        limit=50, sort='ts', order='asc')['alerts']]
    assert stamps == sorted(stamps)


@pytest.mark.parametrize('order', sorted(HOST_SORTS))
def test_host_orderings_are_monotonic(populated_repo, order):
    values = [h[order] for h in
              populated_repo.get_hosts(limit=10, order=order)['hosts']]
    assert values == sorted(values, reverse=True)


@pytest.mark.parametrize('order', sorted(FLOW_SORTS))
def test_flow_orderings_all_work(populated_repo, order):
    page = populated_repo.get_flows(limit=5, order=order)
    assert page['count'] <= 5


@pytest.mark.parametrize('sort', sorted(PACKET_SORTS))
def test_packet_sorts_all_work(populated_repo, sort):
    page = populated_repo.get_packets(limit=5, sort=sort)
    assert page['count'] <= 5


def test_packets_filter_by_protocol_and_carry_decoded_l7(populated_repo):
    page = populated_repo.get_packets(limit=50, protocol='DNS')
    assert page['total'] > 0
    assert all(p['protocol'] == 'DNS' for p in page['packets'])
    assert any(p['l7'].get('dns_qname') for p in page['packets'])


def test_packets_filter_by_entropy(populated_repo):
    page = populated_repo.get_packets(limit=50, min_entropy=6.0)
    assert all(p['entropy'] >= 6.0 for p in page['packets'])


def test_malicious_only_filter(populated_repo):
    page = populated_repo.get_packets(limit=100, malicious_only=True)
    assert all(p['is_malicious'] for p in page['packets'])


# ── populated: detail and aggregates ─────────────────────────────────────────

def test_alert_detail_carries_techniques_and_context(populated_repo):
    alert_id = populated_repo.get_alerts(limit=1)['alerts'][0]['id']
    alert = populated_repo.get_alert(alert_id)
    assert alert['id'] == alert_id
    assert alert['techniques'], 'every alert must map to >=1 technique'
    for technique in alert['techniques']:
        assert technique['technique_id'].startswith('T')
        assert technique['tactic']
    assert isinstance(alert['related_packets'], list)
    assert isinstance(alert['evidence'], dict)


def test_timestamps_are_returned_as_both_epoch_and_iso(populated_repo):
    alert = populated_repo.get_alerts(limit=1)['alerts'][0]
    assert isinstance(alert['ts'], float)
    assert alert['ts_iso'].startswith('20')


def test_acknowledge_round_trip(populated_repo):
    target = populated_repo.get_alerts(limit=50, acknowledged=False)['alerts']
    assert target, 'fixture produced no unacknowledged alerts'
    alert_id = target[-1]['id']
    assert populated_repo.acknowledge_alert(alert_id) == 1
    assert populated_repo.get_alert(alert_id)['acknowledged'] is True
    assert populated_repo.get_alert(alert_id)['ack_ts'] is not None
    populated_repo.acknowledge_alert(alert_id, acknowledged=False)
    assert populated_repo.get_alert(alert_id)['acknowledged'] is False


def test_acknowledging_a_missing_alert_reports_zero_rows(populated_repo):
    assert populated_repo.acknowledge_alert(10_000_000) == 0


def test_bulk_acknowledge_updates_every_id_in_one_call(populated_repo):
    ids = [a['id'] for a in
           populated_repo.get_alerts(limit=3, acknowledged=False)['alerts']]
    if not ids:
        pytest.skip('no unacknowledged alerts in the fixture')
    assert populated_repo.acknowledge_alerts(ids) == len(ids)
    for alert_id in ids:
        assert populated_repo.get_alert(alert_id)['acknowledged'] is True
    populated_repo.acknowledge_alerts(ids, acknowledged=False)


def test_bulk_acknowledge_of_nothing_is_a_no_op(populated_repo):
    assert populated_repo.acknowledge_alerts([]) == 0


def test_host_detail_joins_protocols_peers_and_alerts(populated_repo):
    ip = populated_repo.get_hosts(limit=1)['hosts'][0]['ip']
    host = populated_repo.get_host(ip)
    assert host['ip'] == ip
    assert host['packets_sent'] + host['packets_recv'] > 0
    assert isinstance(host['top_protocols'], list)
    assert isinstance(host['top_peers'], list)
    assert isinstance(host['recent_alerts'], list)


def test_threat_summary_aggregates_by_source_and_type(populated_repo):
    rows = populated_repo.get_threat_summary(hours=24, limit=50)
    assert rows
    keys = [(r['src_ip'], r['threat_type']) for r in rows]
    assert len(keys) == len(set(keys)), 'summary rows are not distinct'
    for row in rows:
        assert row['alert_count'] >= 1
        assert row['open_alerts'] <= row['alert_count']


def test_alert_stats_by_type_matches_the_listing(populated_repo):
    stats = populated_repo.get_alert_stats_by_type(hours=24 * 365)
    total = sum(row['count'] for row in stats)
    assert total == populated_repo.get_alerts(limit=1)['total']


def test_severity_breakdown_sums_to_the_alert_total(populated_repo):
    rows = populated_repo.get_severity_breakdown(hours=24 * 365)
    assert sum(r['count'] for r in rows) == populated_repo.get_alerts(
        limit=1)['total']


def test_protocol_rollup_matches_packets_written(populated_repo):
    distribution = populated_repo.get_protocol_distribution(minutes=10080)
    rolled_up = sum(row['packets'] for row in distribution)
    assert rolled_up == populated_repo.get_packets(limit=1)['total']


def test_throughput_buckets_are_ordered(populated_repo):
    buckets = populated_repo.get_throughput(minutes=1440)
    assert buckets
    assert [b['bucket'] for b in buckets] == sorted(
        b['bucket'] for b in buckets)


def test_mitre_coverage_groups_by_tactic(populated_repo):
    coverage = populated_repo.get_mitre_coverage()
    assert coverage
    for tactic in coverage:
        assert tactic['catalogued'] == len(tactic['techniques'])
        assert tactic['observed'] <= tactic['catalogued']


def test_mitre_technique_detail_lists_its_detectors(populated_repo):
    observed = [t for t in populated_repo.get_mitre_techniques()
                if t['alert_count'] > 0]
    assert observed
    detail = populated_repo.get_mitre_technique(observed[0]['technique_id'])
    assert detail['alert_count'] > 0
    assert detail['detectors']
    assert detail['recent_alerts']


def test_geo_distribution_excludes_private_addresses(populated_repo):
    rows = populated_repo.get_geo_distribution()
    assert all(row['country'] != 'PRIVATE' for row in rows)


def test_pipeline_runs_round_trip(repo):
    run_id = repo.record_pipeline_run({
        'source': 'benchmark', 'window_s': 12.5, 'packets_received': 1000,
        'packets_persisted': 995, 'packets_dropped': 5, 'packets_per_s': 80.0,
        'latency_p95_ms': 3.5})
    assert run_id
    page = repo.get_pipeline_runs(source='benchmark')
    assert page['total'] == 1
    row = page['runs'][0]
    assert row['packets_received'] == 1000
    assert row['packets_dropped'] == 5


def test_pipeline_runs_filter_by_source(repo):
    repo.record_pipeline_run({'source': 'engine', 'window_s': 1.0})
    repo.record_pipeline_run({'source': 'soak', 'window_s': 1.0})
    assert repo.get_pipeline_runs(source='engine')['total'] == 1
    assert repo.get_pipeline_runs()['total'] == 2


# ── plans ────────────────────────────────────────────────────────────────────

def _plan(engine, sql):
    with engine.connect() as conn:
        return '\n'.join(r[0] for r in conn.execute(
            text('EXPLAIN ' + sql)))


@pytest.mark.parametrize('sql,acceptable', [
    ("SELECT id FROM alerts WHERE severity = 'CRITICAL' "
     "ORDER BY ts DESC LIMIT 50", ('ix_alerts_severity_ts',)),
    ('SELECT id FROM alerts WHERE src_host_id = 1 ORDER BY ts DESC LIMIT 50',
     ('ix_alerts_src_ts', 'ix_alerts_ts_src_type')),
    ('SELECT id FROM alerts WHERE threat_type_id = 1 ORDER BY ts DESC '
     'LIMIT 50', ('ix_alerts_type_ts', 'ix_alerts_ts_src_type')),
    ('SELECT id FROM packets WHERE src_host_id = 1 ORDER BY ts DESC LIMIT 50',
     ('ix_packets_src_ts', 'ix_packets_src_proto_len')),
    ('SELECT id FROM packets WHERE protocol_id = 1 ORDER BY ts DESC LIMIT 50',
     ('ix_packets_proto_ts',)),
])
def test_hot_queries_reach_their_rows_through_an_index(db_engine, sql,
                                                       acceptable):
    """No hot query may fall back to a sequential scan.

    Sequential scans are disabled for the statement so the planner cannot
    prefer one just because the fixture table is small; the point is that a
    usable index exists at all. Which of the candidate indexes it picks is the
    planner's business, so any of them passes.
    """
    with db_engine.begin() as conn:
        conn.execute(text('SET LOCAL enable_seqscan = off'))
        plan = '\n'.join(r[0] for r in conn.execute(text('EXPLAIN ' + sql)))
    assert 'Seq Scan' not in plan, plan
    assert any(name in plan for name in acceptable), plan


def test_explain_helper_returns_plan_lines(populated_repo):
    lines = populated_repo.explain('SELECT COUNT(*) FROM alerts')
    assert lines
    assert any('Aggregate' in line for line in lines)
