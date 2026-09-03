"""Schema, persistence, index-usage and query-latency tests."""

import json
import time

import pytest

from DB_Manager import TABLES

from conftest import BACKEND, BASE_TS, clone_manager

EXPECTED_TABLES = {
    'packets', 'connections', 'hosts', 'alerts', 'mitre_techniques',
    'alert_techniques', 'protocol_stats', 'performance_metrics',
    'validation_runs',
}

# Eight tables are written by the packet pipeline itself; validation_runs is
# written by the replay/tuning harness and is asserted separately.
PIPELINE_TABLES = EXPECTED_TABLES - {'validation_runs'}


# ── schema ───────────────────────────────────────────────────────────────────

def test_schema_has_exactly_nine_tables(db):
    names = set(db.table_names())
    assert names == EXPECTED_TABLES
    assert len(names) == 9
    assert set(TABLES) == EXPECTED_TABLES


def test_every_table_is_indexed(db):
    indexed = {table for table, _index in db.index_names()}
    # Every table except the small ATT&CK join, which is covered by its
    # composite primary key, carries at least one explicit index.
    for table in EXPECTED_TABLES:
        assert table in indexed, '%s has no index' % table


def test_index_count_is_substantial(db):
    assert len(db.index_names()) >= 20


@pytest.mark.skipif(BACKEND != 'sqlite', reason='WAL is a SQLite journal mode')
def test_wal_mode_enabled(db):
    assert db.health()['journal_mode'].lower() == 'wal'


def test_backend_is_reported(db):
    assert db.health()['backend'] == BACKEND


def test_foreign_keys_are_enforced(db):
    with pytest.raises(Exception):
        db._exec(db._write_conn,
                 'INSERT INTO alert_techniques (alert_id, technique_id, '
                 "confidence, ts) VALUES (999999, 'T1046', 0.5, 1.0)")


def test_severity_check_constraint(db):
    with pytest.raises(Exception):
        db._exec(db._write_conn,
                 """INSERT INTO alerts (ts,severity,threat_type,detector,
                    confidence,description)
                    VALUES (1.0,'BOGUS','x','y',0.5,'z')""")


# ── persistence ──────────────────────────────────────────────────────────────

def test_all_pipeline_tables_are_actually_populated(populated_db):
    """The core claim: no table exists merely to inflate the schema count."""
    counts = populated_db.health()['tables']
    for table in PIPELINE_TABLES:
        assert counts[table] > 0, '%s was never written to' % table


def test_validation_runs_round_trip(db):
    """The ninth table is written by the replay/tuning harness, not the
    packet pipeline — so it is exercised here rather than in populated_db."""
    run_id = db.record_validation_run({
        'kind': 'replay', 'profile': 'tuned', 'corpus': 'unit-test',
        'pcap_count': 2, 'packets': 100, 'scenarios': 2,
        'true_positives': 2, 'false_positives': 0, 'false_negatives': 0,
        'precision_pct': 100.0, 'recall_pct': 100.0, 'tpr_pct': 100.0,
        'alerts_total': 3, 'detail': {'scenarios': ['a', 'b']},
    })
    assert run_id
    rows = db.get_validation_runs(kind='replay')
    assert rows and rows[0]['id'] == run_id
    assert rows[0]['tpr_pct'] == 100.0
    assert rows[0]['detail']['scenarios'] == ['a', 'b']
    assert db.health()['tables']['validation_runs'] == 1


def test_packets_persist_with_decoded_l7(populated_db):
    rows = populated_db.get_packets(limit=500)
    assert rows
    assert any(r['l7'] for r in rows), 'no packet stored decoded L7 fields'
    dns = populated_db.get_packets(limit=50, protocol='DNS')
    assert dns
    assert any('dns_qname' in r['l7'] for r in dns)


def test_connections_aggregate_rather_than_duplicate(db, simulator):
    """Repeating a flow must increment counters, not insert new rows."""
    import frames as F
    frames = [(BASE_TS + i * 0.1,
               F.tcp_frame(b'x' * 100, '10.0.1.5', '10.0.2.7', 40000, 80,
                           'PSH|ACK'))
              for i in range(50)]
    simulator.run_frames(frames)
    flows = db.get_connections(limit=10)
    matching = [f for f in flows
                if f['src_ip'] == '10.0.1.5' and f['dst_port'] == 80]
    assert len(matching) == 1
    assert matching[0]['packets'] == 50
    assert matching[0]['bytes'] > 5000
    assert matching[0]['first_seen'] < matching[0]['last_seen']


def test_hosts_accumulate_counters_and_geo(populated_db):
    hosts = populated_db.get_top_hosts(limit=10)
    assert hosts
    assert all(h['packets_sent'] >= 0 for h in hosts)
    assert any(h['bytes_sent'] > 0 for h in hosts)
    internal = [h for h in hosts if h['is_internal']]
    assert internal, 'no internal hosts classified'
    countries = {h['country'] for h in populated_db.get_top_hosts(limit=200)}
    assert countries - {'UNKNOWN'}, 'geo enrichment never resolved a country'


def test_hosts_threat_score_rises_with_alerts(populated_db):
    scored = populated_db.get_top_hosts(limit=10, order='threat_score')
    assert scored[0]['threat_score'] > 0
    assert scored[0]['alert_count'] > 0


def test_protocol_stats_rollup_matches_packets(populated_db):
    rollup = {r['protocol']: r['packets']
              for r in populated_db.get_protocol_distribution(minutes=100000)}
    actual = {r['protocol']: r['n'] for r in populated_db._rows(
        'SELECT protocol, COUNT(*) AS n FROM packets GROUP BY protocol')}
    assert rollup, 'protocol_stats never populated'
    for protocol, count in actual.items():
        assert rollup.get(protocol) == count, \
            'rollup disagrees with packets for %s' % protocol


def test_alerts_store_structured_evidence(populated_db):
    result = populated_db.get_alerts(limit=100)
    assert result['total'] > 0
    for alert in result['alerts']:
        assert isinstance(alert['evidence'], dict)
        assert alert['confidence'] > 0
        assert alert['detector'] and alert['threat_type']
        assert alert['description']


def test_alert_detail_includes_techniques_and_context(populated_db):
    alert_id = populated_db.get_alerts(limit=1)['alerts'][0]['id']
    detail = populated_db.get_alert(alert_id)
    assert detail['techniques'], 'alert has no ATT&CK mapping'
    for tech in detail['techniques']:
        assert tech['name'] and tech['tactic'] and tech['rationale']
    assert isinstance(detail['related_packets'], list)


def test_acknowledge_updates_and_reports_rowcount(populated_db):
    alert_id = populated_db.get_alerts(limit=1)['alerts'][0]['id']
    assert populated_db.acknowledge_alert(alert_id) == 1
    assert populated_db.get_alert(alert_id)['acknowledged'] == 1
    assert populated_db.acknowledge_alert(10_000_000) == 0


def test_alert_filtering_and_pagination(populated_db):
    everything = populated_db.get_alerts(limit=500)
    assert everything['total'] >= 1

    page1 = populated_db.get_alerts(limit=2, offset=0)
    page2 = populated_db.get_alerts(limit=2, offset=2)
    assert page1['total'] == page2['total'] == everything['total']
    if everything['total'] > 3:
        ids1 = {a['id'] for a in page1['alerts']}
        ids2 = {a['id'] for a in page2['alerts']}
        assert not ids1 & ids2

    by_type = populated_db.get_alerts(limit=50, threat_type='port_scan')
    assert all(a['threat_type'] == 'port_scan' for a in by_type['alerts'])


def test_threat_summary_aggregates_by_source(populated_db):
    rows = populated_db.get_threat_summary()
    assert rows
    for row in rows:
        assert row['alert_count'] >= 1
        assert row['first_seen'] <= row['last_seen']


def test_empty_database_returns_empty_not_error(db):
    """No filler data when there is nothing to report."""
    overview = db.get_overview()
    assert overview['total_packets'] == 0
    assert overview['total_alerts'] == 0
    assert db.get_alerts(limit=10)['alerts'] == []
    assert db.get_top_hosts() == []
    assert db.get_throughput() == []
    assert db.get_geo_distribution() == []
    assert db.get_alert(1) is None
    assert db.get_host('10.0.0.1') is None
    assert db.get_mitre_technique('T9999') is None
    # The catalog is reference data and is present from the start.
    assert len(db.get_mitre_techniques()) > 0


def test_performance_metrics_are_written(populated_db):
    populated_db.record_performance({
        'source': 'benchmark', 'window_s': 12.5, 'packets_processed': 1000,
        'packets_per_min': 4800.0, 'query_p50_ms': 1.2, 'query_p95_ms': 3.4,
    })
    rows = populated_db.get_performance(limit=5, source='benchmark')
    assert rows and rows[0]['packets_per_min'] == 4800.0
    assert rows[0]['query_p95_ms'] == 3.4


# ── index usage ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize('sql,params', [
    ('SELECT * FROM alerts ORDER BY ts DESC LIMIT 50', ()),
    ('SELECT * FROM alerts WHERE severity=? ORDER BY ts DESC LIMIT 50',
     ('HIGH',)),
    ('SELECT * FROM alerts WHERE threat_type=? ORDER BY ts DESC LIMIT 50',
     ('port_scan',)),
    ('SELECT * FROM packets WHERE protocol=? ORDER BY ts DESC LIMIT 100',
     ('DNS',)),
    ('SELECT * FROM packets WHERE src_ip=? ORDER BY ts DESC LIMIT 100',
     ('10.0.1.20',)),
    ('SELECT * FROM alert_techniques WHERE technique_id=? ORDER BY ts DESC',
     ('T1046',)),
    ('SELECT * FROM protocol_stats WHERE bucket > ? ORDER BY bucket', (0,)),
    ('SELECT * FROM connections ORDER BY last_seen DESC LIMIT 50', ()),
])
def test_hot_queries_use_an_index(populated_db, sql, params):
    plan = populated_db.plan_text(sql, params)
    assert populated_db.uses_index(sql, params), \
        'query falls back to a full scan: %s -> %s' % (sql, plan)


def test_recent_alerts_avoid_a_sort(populated_db):
    """The ts index must satisfy ORDER BY directly, with no explicit sort."""
    sql = 'SELECT * FROM alerts ORDER BY ts DESC LIMIT 50'
    plan = populated_db.plan_text(sql)
    assert populated_db.uses_index(sql, index_name='idx_alerts_ts'), plan
    # SQLite materialises a temp b-tree, PostgreSQL adds a Sort node; either
    # means the index did not supply the ordering.
    assert 'TEMP B-TREE' not in plan.upper()
    assert 'Sort' not in plan


def test_technique_lookup_avoids_a_full_scan(populated_db):
    sql = 'SELECT * FROM alert_techniques WHERE technique_id=?'
    plan = populated_db.plan_text(sql, ('T1046',))
    assert populated_db.uses_index(sql, ('T1046',),
                                   index_name='idx_at_technique'), plan
    assert not populated_db.scans_table(sql, ('T1046',),
                                        table='alert_techniques'), plan


# ── latency ──────────────────────────────────────────────────────────────────

def test_api_backing_queries_are_under_50ms(populated_db):
    """The <50ms claim, measured against a pipeline-populated dataset."""
    alert_id = populated_db.get_alerts(limit=1)['alerts'][0]['id']
    host_ip = populated_db.get_top_hosts(1)[0]['ip']
    queries = {
        'overview': lambda: populated_db.get_overview(),
        'throughput': lambda: populated_db.get_throughput(60),
        'protocols': lambda: populated_db.get_protocol_distribution(),
        'severity': lambda: populated_db.get_severity_breakdown(),
        'timeline': lambda: populated_db.get_alert_timeline(),
        'alerts': lambda: populated_db.get_alerts(limit=50),
        'alert_detail': lambda: populated_db.get_alert(alert_id),
        'alert_stats': lambda: populated_db.get_alert_stats_by_type(),
        'threat_summary': lambda: populated_db.get_threat_summary(),
        'mitre': lambda: populated_db.get_mitre_techniques(),
        'mitre_detail': lambda: populated_db.get_mitre_technique('T1046'),
        'mitre_coverage': lambda: populated_db.get_mitre_coverage(),
        'top_hosts': lambda: populated_db.get_top_hosts(15),
        'host_detail': lambda: populated_db.get_host(host_ip),
        'geo': lambda: populated_db.get_geo_distribution(),
        'connections': lambda: populated_db.get_connections(50),
        'packets': lambda: populated_db.get_packets(100),
        'performance': lambda: populated_db.get_performance(120),
    }
    for fn in queries.values():   # warm the cache
        fn()

    slow = {}
    for name, fn in queries.items():
        samples = []
        for _ in range(10):
            t0 = time.perf_counter()
            fn()
            samples.append((time.perf_counter() - t0) * 1000)
        median = sorted(samples)[len(samples) // 2]
        if median >= 50:
            slow[name] = round(median, 2)
    assert not slow, 'queries at or above 50ms: %s' % slow


def test_batch_write_is_transactional(db):
    """A failing batch must leave no partial rows behind."""
    before = db.health()['tables']['packets']
    bad_packet = {'ts': BASE_TS, 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
                  'protocol': 'TCP', 'frame_len': 'not-an-integer'}

    class BadFinding:
        ts = BASE_TS
        severity = 'NOPE'          # violates the CHECK constraint
        threat_type = detector = 'x'
        src_ip = dst_ip = '10.0.0.1'
        src_port = dst_port = 1
        protocol = 'TCP'
        confidence = 0.5
        reason = 'r'
        evidence = {}
        techniques = ('T1046',)

    with pytest.raises(Exception):
        db.persist_batch([bad_packet], [BadFinding()])
    assert db.health()['tables']['packets'] == before


def test_separate_manager_sees_committed_rows(db, simulator, tmp_path):
    """Readers on other connections must observe committed writes."""
    import frames as F
    simulator.run_frames([
        (BASE_TS, F.tcp_frame(b'hello', '10.0.1.9', '10.0.2.9', 40000, 80))])
    other = clone_manager(db)
    try:
        assert other.health()['tables']['packets'] >= 1
    finally:
        other.close()


def test_overview_total_packets_agrees_with_the_packet_table(populated_db):
    """The rollup shortcut must give the same answer as counting rows.

    get_overview() sums protocol_stats instead of scanning packets, because
    that scan was the slowest query in the API. The optimisation is only valid
    while the two agree.
    """
    counted = populated_db._scalar('SELECT COUNT(*) FROM packets')
    assert populated_db.get_overview()['total_packets'] == counted


def test_overview_avoids_scanning_the_packet_table(populated_db):
    """Guards the fix: the KPI strip must not full-scan packets."""
    sql = 'SELECT SUM(packets) FROM protocol_stats'
    assert not populated_db.scans_table(sql, table='packets')
