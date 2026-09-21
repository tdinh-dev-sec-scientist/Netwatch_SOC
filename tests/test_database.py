"""Schema, persistence, index-usage and query-latency tests."""

import random
import time

import pytest

import mitre
from DB_Manager import TABLES
from db_backends import Json

from conftest import BASE_TS, requires_postgres

EXPECTED_TABLES = {
    'packets', 'connections', 'hosts', 'alerts', 'mitre_techniques',
    'alert_techniques', 'protocol_stats', 'performance_metrics',
}


# ── schema ───────────────────────────────────────────────────────────────────

def test_schema_has_exactly_eight_tables(db):
    names = set(db.table_names())
    assert names == EXPECTED_TABLES
    assert len(names) == 8
    assert set(TABLES) == EXPECTED_TABLES


def test_every_table_is_indexed(db):
    indexed = {table for table, _index in db.index_names()}
    # Every table except the small ATT&CK join, which is covered by its
    # composite primary key, carries at least one explicit index.
    for table in EXPECTED_TABLES:
        assert table in indexed, '%s has no index' % table


def test_index_count_is_substantial(db):
    assert len(db.index_names()) >= 20


def test_write_ahead_logging_is_in_use(db):
    """PostgreSQL is unconditionally WAL; SQLite has to be asked for it."""
    assert db.health()['journal_mode'].lower().startswith('wal')


def write(db, sql, params=()):
    """Run one statement on the writer, as the pipeline would."""
    backend = db._backend
    conn = backend.writer()
    backend.begin(conn)
    try:
        result = backend.execute(conn, sql, params)
        backend.commit(conn)
        return result
    except Exception:
        backend.rollback(conn)
        raise


def test_foreign_keys_are_enforced(db):
    with pytest.raises(Exception):
        write(db, 'INSERT INTO alert_techniques (alert_id, technique_id, '
                  'confidence, ts) VALUES (?,?,?,?)',
              (999999, 'T1046', 0.5, 1.0))


def test_technique_references_must_exist(db):
    """A link to a technique that is not in the catalog is rejected."""
    alert_id = write(
        db,
        """INSERT INTO alerts (ts,severity,threat_type,detector,confidence,
           description) VALUES (?,'HIGH','x','y',0.5,'z') RETURNING id""",
        (BASE_TS,)).scalar()
    with pytest.raises(Exception):
        write(db, 'INSERT INTO alert_techniques (alert_id, technique_id, '
                  'confidence, ts) VALUES (?,?,?,?)',
              (alert_id, 'T0000-not-real', 0.5, BASE_TS))


def test_severity_check_constraint(db):
    with pytest.raises(Exception):
        write(db, """INSERT INTO alerts (ts,severity,threat_type,detector,
                     confidence,description)
                     VALUES (1.0,'BOGUS','x','y',0.5,'z')""")


@requires_postgres
def test_column_types_are_enforced(db):
    """The point of PostgreSQL over SQLite: a wrong type is refused.

    Under SQLite's dynamic typing this insert succeeds and the string is
    stored in an INTEGER column.
    """
    with pytest.raises(Exception):
        write(db, """INSERT INTO packets (ts,src_ip,dst_ip,protocol,frame_len)
                     VALUES (?,?,?,?,?)""",
              (BASE_TS, '10.0.0.1', '10.0.0.2', 'TCP', 'not-an-integer'))


@requires_postgres
def test_json_columns_are_jsonb_not_text(db):
    """evidence is queryable by key, which is the reason for JSONB."""
    write(db,
          """INSERT INTO alerts (ts,severity,threat_type,detector,confidence,
             description,evidence)
             VALUES (?,'HIGH','port_scan','port_scan',0.9,'d',?)""",
          (BASE_TS, Json({'dst_port': 445, 'nested': {'a': 1}})))
    assert db._scalar(
        "SELECT COUNT(*) FROM alerts WHERE evidence @> ?",
        (Json({'dst_port': 445}),)) == 1
    assert db._scalar(
        "SELECT COUNT(*) FROM alerts WHERE evidence @> ?",
        (Json({'dst_port': 22}),)) == 0
    assert db.get_alerts(limit=1)['alerts'][0]['evidence']['nested'] == {'a': 1}


@requires_postgres
def test_counters_are_64_bit(db):
    """SQLite INTEGER is 64-bit; PostgreSQL INTEGER is not, so the byte and
    packet counters must be BIGINT or they overflow past 2.1 GB."""
    huge = 9_000_000_000            # ~9 GB, well past a 32-bit column
    write(db,
          """INSERT INTO hosts (ip,first_seen,last_seen,bytes_sent,bytes_recv,
             packets_sent) VALUES (?,?,?,?,?,?)""",
          ('10.9.9.9', BASE_TS, BASE_TS, huge, huge, huge))
    host = db.get_host('10.9.9.9')
    assert host['bytes_sent'] == huge and host['packets_sent'] == huge


@requires_postgres
def test_timestamps_are_available_as_timestamptz(db):
    """Epoch seconds stay the pipeline's representation; ts_utc is the same
    instant as a real timestamp, for SQL and reporting clients."""
    write(db,
          """INSERT INTO alerts (ts,severity,threat_type,detector,confidence,
             description) VALUES (?,'LOW','x','y',0.1,'z')""", (BASE_TS,))
    row = db._one('SELECT ts, ts_utc, '
                  'EXTRACT(EPOCH FROM ts_utc) AS epoch FROM alerts')
    assert row['ts_utc'].tzinfo is not None, 'ts_utc must be timezone-aware'
    assert float(row['epoch']) == pytest.approx(row['ts'], abs=1e-3)


# ── persistence ──────────────────────────────────────────────────────────────

def test_all_eight_tables_are_actually_populated(populated_db):
    """The core claim: no table exists merely to reach a count of eight."""
    counts = populated_db.health()['tables']
    for table in EXPECTED_TABLES:
        assert counts[table] > 0, '%s was never written to' % table


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
    actual = {r['protocol']: r['count'] for r in populated_db.rows(
        'SELECT protocol, COUNT(*) AS count FROM packets GROUP BY protocol')}
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
#
# These run against a deliberately large, bulk-loaded dataset rather than the
# pipeline fixture. PostgreSQL's planner is cost-based: on a few thousand rows a
# sequential scan genuinely is cheaper than an index, and asserting otherwise
# would only prove the planner had too little data to decide. The question worth
# asking is whether the dashboard's queries use their indexes at the volume a
# real deployment reaches, so the fixture reaches it.

PLAN_PACKETS = 40_000
PLAN_ALERTS = 12_000


@pytest.fixture(scope='module')
def plan_db(scratch):
    """A database large enough for the planner's choices to be meaningful."""
    manager = scratch.manager('plans')
    backend = manager._backend
    conn = backend.writer()
    rnd = random.Random(4242)
    now = time.time()
    ips = ['10.0.%d.%d' % (i // 254 + 1, i % 254 + 1) for i in range(500)]
    protocols = ['TCP', 'UDP', 'DNS', 'HTTP', 'TLS', 'ICMP', 'SSH', 'SMB']
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    threats = ['port_scan', 'c2_beacon', 'dns_tunnel', 'syn_flood',
               'brute_force', 'data_exfil']
    techniques = [t.id for t in mitre.all_techniques()]

    backend.begin(conn)
    backend.executemany(
        conn,
        """INSERT INTO packets (ts,src_ip,dst_ip,src_port,dst_port,protocol,
           frame_len,payload_len,flags,entropy,is_malicious,l7_summary)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        [(now - rnd.random() * 86400, rnd.choice(ips), rnd.choice(ips),
          rnd.randrange(1024, 65535), rnd.choice([80, 443, 53, 22, 445]),
          rnd.choice(protocols), rnd.randrange(60, 1500), 0, 'ACK',
          rnd.random() * 8, rnd.random() < 0.02, Json(None))
         for _ in range(PLAN_PACKETS)])
    backend.executemany(
        conn,
        """INSERT INTO connections (src_ip,dst_ip,src_port,dst_port,protocol,
           first_seen,last_seen,packets,bytes)
           VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
        [(rnd.choice(ips), rnd.choice(ips), rnd.randrange(1024, 65535),
          rnd.choice([80, 443, 53]), rnd.choice(protocols),
          now - 86400, now - rnd.random() * 86400, 10, 1000)
         for _ in range(8000)])
    backend.executemany(
        conn,
        """INSERT INTO alerts (ts,severity,threat_type,detector,src_ip,dst_ip,
           src_port,dst_port,protocol,confidence,description,evidence,
           acknowledged)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [(now - rnd.random() * 86400, rnd.choice(severities),
          (threat := rnd.choice(threats)), threat, rnd.choice(ips),
          rnd.choice(ips), 1, 2, rnd.choice(protocols), rnd.random(),
          'synthetic', Json({'k': 1}), rnd.random() < 0.5)
         for _ in range(PLAN_ALERTS)])
    backend.executemany(
        conn,
        """INSERT INTO protocol_stats (bucket,protocol,packets,bytes,alerts)
           VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING""",
        [(int((now - minute * 60) // 60 * 60), protocol, 10, 1000, 1)
         for minute in range(1440) for protocol in protocols])
    backend.commit(conn)

    alert_ids = [r['id'] for r in backend.execute(
        conn, 'SELECT id FROM alerts').rows]
    backend.begin(conn)
    backend.executemany(
        conn,
        """INSERT INTO alert_techniques (alert_id,technique_id,confidence,ts)
           VALUES (?,?,?,?) ON CONFLICT DO NOTHING""",
        [(alert_id, rnd.choice(techniques), 0.8, now - rnd.random() * 86400)
         for alert_id in alert_ids])
    backend.commit(conn)
    manager.analyze()
    yield manager
    manager.close()


def plan_text(db, sql, params=()):
    return ' | '.join(row['detail'] for row in db.explain(sql, params))


# Each case is a query the API issues, and the index(es) that may serve it. The
# index name is asserted rather than a backend-specific phrase like "USING
# INDEX" or "Index Scan", so one assertion covers both plan formats. Where two
# indexes are listed, either is a legitimate choice and the planner picks by
# cost — the assertion is that it uses one of them rather than scanning.
@pytest.mark.parametrize('sql,params,indexes', [
    ('SELECT * FROM alerts ORDER BY ts DESC LIMIT 50', (), ('idx_alerts_ts',)),
    ('SELECT * FROM alerts WHERE severity=? ORDER BY ts DESC LIMIT 50',
     ('HIGH',), ('idx_alerts_sev_ts',)),
    ('SELECT * FROM alerts WHERE threat_type=? ORDER BY ts DESC LIMIT 50',
     ('port_scan',), ('idx_alerts_type_ts',)),
    ('SELECT * FROM alerts WHERE src_ip=? ORDER BY ts DESC LIMIT 50',
     ('10.0.1.1',), ('idx_alerts_src_ts',)),
    ('SELECT * FROM packets ORDER BY ts DESC LIMIT 100', (),
     ('idx_packets_ts',)),
    ('SELECT * FROM packets WHERE protocol=? ORDER BY ts DESC LIMIT 100',
     ('DNS',), ('idx_packets_proto_ts',)),
    ('SELECT * FROM packets WHERE src_ip=? ORDER BY ts DESC LIMIT 100',
     ('10.0.1.20',), ('idx_packets_src_ts', 'idx_packets_src_proto')),
    ('SELECT * FROM alert_techniques WHERE technique_id=? ORDER BY ts DESC '
     'LIMIT 50', ('T1046',), ('idx_at_technique',)),
    ('SELECT * FROM protocol_stats WHERE bucket > ? ORDER BY bucket DESC '
     'LIMIT 100', (0,), ('idx_pstat_bucket',)),
    ('SELECT * FROM connections ORDER BY last_seen DESC LIMIT 50', (),
     ('idx_conn_last',)),
])
def test_hot_queries_use_their_index(plan_db, sql, params, indexes):
    plan = plan_text(plan_db, sql, params)
    assert any(index in plan for index in indexes), \
        'query uses none of %s: %s -> %s' % (', '.join(indexes), sql, plan)


PARTIAL_INDEX_QUERIES = [
    ('SELECT * FROM alerts WHERE NOT acknowledged ORDER BY ts DESC LIMIT 50',
     'alerts', 'idx_alerts_ack'),
    ('SELECT * FROM packets WHERE is_malicious ORDER BY ts DESC LIMIT 100',
     'packets', 'idx_packets_malicious'),
]


@pytest.mark.parametrize('sql,table,index', PARTIAL_INDEX_QUERIES)
def test_filtered_queries_never_scan_the_table(plan_db, sql, table, index):
    """Which index is the planner's call; that it uses one is not.

    Both backends name the index they chose in the plan, so the presence of an
    `idx_` name is the portable way to say "this is not a full table scan".
    """
    plan = plan_text(plan_db, sql)
    assert 'idx_' in plan, 'no index used: %s' % plan
    assert 'Seq Scan on %s' % table not in plan, plan


@requires_postgres
@pytest.mark.parametrize('sql,table,index', PARTIAL_INDEX_QUERIES)
def test_partial_indexes_serve_the_queries_they_were_built_for(plan_db, sql,
                                                              table, index):
    """These two indexes cover only the rows the dashboard ever asks for, so
    they stay small on a write path that sees every packet.

    PostgreSQL-only: the SQLite fallback declares the same partial indexes but
    its planner prefers the plain ts index here, to satisfy ORDER BY without a
    sort. Either is an index scan, which the test above asserts for both.
    """
    plan = plan_text(plan_db, sql)
    assert index in plan, '%s unused: %s' % (index, plan)


def test_recent_alerts_avoid_a_sort(plan_db):
    """The ts index must satisfy ORDER BY directly, with no sort step."""
    plan = plan_text(plan_db,
                     'SELECT * FROM alerts ORDER BY ts DESC LIMIT 50')
    assert 'idx_alerts_ts' in plan
    # PostgreSQL calls it Sort; SQLite calls it USE TEMP B-TREE FOR ORDER BY.
    assert 'SORT' not in plan.upper()
    assert 'B-TREE' not in plan.upper()


def test_technique_lookup_avoids_a_full_scan(plan_db):
    """Both halves of the technique detail page, as get_mitre_technique()
    issues them."""
    count_plan = plan_text(
        plan_db,
        'SELECT COUNT(*) FROM alert_techniques WHERE technique_id = ?',
        ('T1046',))
    assert 'idx_at_technique' in count_plan, count_plan

    # The join is free to reach the rows either way round — through the
    # technique index or through the alert timestamp index and the join's own
    # primary key — and the planner picks by cost. What must not happen is a
    # full scan of either table.
    join_plan = plan_text(
        plan_db,
        """SELECT a.id, a.ts, a.severity FROM alert_techniques at
           JOIN alerts a ON a.id = at.alert_id
           WHERE at.technique_id = ? ORDER BY a.ts DESC LIMIT 25""",
        ('T1046',))
    for table in ('alert_techniques', 'alerts'):
        # PostgreSQL: "Seq Scan on alerts". SQLite: "SCAN alerts".
        assert 'Seq Scan on %s' % table not in join_plan, join_plan
        assert 'SCAN %s' % table not in join_plan, join_plan


def test_host_protocol_breakdown_uses_the_covering_index(plan_db):
    """The slowest query in the API at scale; without its index it sorts every
    packet the host sent."""
    plan = plan_text(
        plan_db,
        """SELECT protocol, COUNT(*) AS packets, SUM(frame_len) AS bytes
           FROM packets WHERE src_ip = ? GROUP BY protocol""",
        ('10.0.1.20',))
    assert 'idx_packets_src' in plan, plan


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


def test_separate_manager_sees_committed_rows(db, simulator, second_manager):
    """Readers on other connections must observe committed writes."""
    import frames as F
    simulator.run_frames([
        (BASE_TS, F.tcp_frame(b'hello', '10.0.1.9', '10.0.2.9', 40000, 80))])
    other = second_manager(db)
    assert other.health()['tables']['packets'] >= 1


# ── migrations ───────────────────────────────────────────────────────────────

def test_migrations_are_recorded_and_idempotent(db):
    """A second run must be a no-op, which is what makes applying them on every
    process start safe."""
    import migrate
    recorded = migrate.applied(db._backend, db._backend.writer())
    assert recorded, 'no migration was recorded'
    assert '0001' in recorded
    assert db.migrate() == [], 'a second run applied something'


def test_editing_an_applied_migration_is_refused(db, monkeypatch):
    """The checksum guard: a migration that changed after being applied is
    reported rather than silently diverging from the database it created."""
    import migrate
    real = migrate.discover

    def tampered(directory):
        migrations = real(directory)
        migrations[0].checksum = 'deadbeefdeadbeef'
        return migrations

    monkeypatch.setattr(migrate, 'discover', tampered)
    with pytest.raises(migrate.MigrationError, match='never be edited'):
        db.migrate()


@requires_postgres
def test_concurrent_startups_do_not_race_to_migrate(scratch):
    """Two processes booting together must not both try to create the schema.

    Before the advisory lock one of them failed on a relation that already
    existed, which turned a routine restart into a crash loop.
    """
    from concurrent.futures import ThreadPoolExecutor
    from DB_Manager import DatabaseManager

    target = scratch.target('race')
    managers = []
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(DatabaseManager, target) for _ in range(4)]
            managers = [f.result() for f in futures]        # raises on a race
        assert set(managers[0].table_names()) == EXPECTED_TABLES
        # Exactly one of them did the work; the rest found nothing to do.
        assert sum(1 for m in managers if m.migrate() != []) == 0
    finally:
        for manager in managers:
            manager.close()


# ── boolean filters ──────────────────────────────────────────────────────────

def test_malicious_only_filter_selects_flagged_packets(db, simulator, gen):
    """is_malicious is a real BOOLEAN now, and the filter is a bare column
    reference rather than a comparison against 1."""
    frames = gen.background(400, start_ts=BASE_TS)
    frames.extend(gen.scenario('port_scan', start_ts=BASE_TS + 5))
    frames.sort(key=lambda pair: pair[0])
    simulator.run_frames(frames)

    flagged = db.get_packets(limit=500, malicious_only=True)
    assert flagged, 'the scan produced no packets flagged malicious'
    # Truthiness rather than `is True`: SQLite has no boolean type and hands
    # back 1/0. test_boolean_columns_read_back_as_python_bools covers the type.
    assert all(p['is_malicious'] for p in flagged)

    everything = db.get_packets(limit=1000)
    assert len(everything) > len(flagged), \
        'malicious_only did not narrow the result'
    assert any(not p['is_malicious'] for p in everything)


def test_acknowledged_filter_round_trips_as_a_boolean(db, simulator, gen):
    frames = gen.scenario('port_scan', start_ts=BASE_TS)
    simulator.run_frames(frames)
    alert_id = db.get_alerts(limit=1)['alerts'][0]['id']

    assert db.get_alerts(limit=50, acknowledged=True)['total'] == 0
    open_before = db.get_alerts(limit=50, acknowledged=False)['total']
    assert open_before > 0

    assert db.acknowledge_alert(alert_id) == 1
    assert db.get_alerts(limit=50, acknowledged=True)['total'] == 1
    assert db.get_alerts(limit=50, acknowledged=False)['total'] == \
        open_before - 1
    assert db.get_alert(alert_id)['acknowledged']
    assert db.get_alert(alert_id)['ack_ts'] is not None


@requires_postgres
def test_boolean_columns_read_back_as_python_bools(db, simulator, gen):
    """Native BOOLEAN columns, so the API emits JSON true/false rather than
    the 1/0 SQLite's dynamic typing produced."""
    frames = gen.background(300, start_ts=BASE_TS)
    frames.extend(gen.scenario('port_scan', start_ts=BASE_TS + 5))
    frames.sort(key=lambda pair: pair[0])
    simulator.run_frames(frames)

    packet = db.get_packets(limit=1)[0]
    assert isinstance(packet['is_malicious'], bool)
    alert = db.get_alerts(limit=1)['alerts'][0]
    assert isinstance(alert['acknowledged'], bool)
    host = db.get_top_hosts(limit=1)[0]
    assert isinstance(host['is_internal'], bool)
