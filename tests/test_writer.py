"""The persistence stage's write path.

What matters here is that a batch is atomic, that per-batch aggregation
happens before the database sees it, and that nothing is written twice when a
key repeats across batches.
"""

import datetime as dt
import time

import pytest
from sqlalchemy import text

from netwatch.capture import frames as F
from netwatch.db.writer import BatchWriter, l7_summary
from netwatch.detectors.base import Finding

UTC = dt.UTC


def parse(analyzer, frame, ts):
    pkt = analyzer.safe_parse(frame, ts)
    assert pkt is not None
    when = dt.datetime.fromtimestamp(pkt['ts'], UTC)
    pkt['dt'] = when
    pkt['minute'] = when.replace(second=0, microsecond=0)
    return pkt


@pytest.fixture
def now():
    return time.time()


def scalar(engine, sql, **params):
    with engine.connect() as conn:
        return conn.execute(text(sql), params).scalar()


def rows(engine, sql, **params):
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(text(sql), params).mappings()]


# ── l7 summary ───────────────────────────────────────────────────────────────

def test_l7_summary_keeps_application_fields_only():
    summary = l7_summary({'src_ip': '10.0.0.1', 'ttl': 64, 'protocol': 'DNS',
                          'dns_qname': 'a.example', 'dns_qtype': 'TXT',
                          'http_uri': '/x'})
    assert summary == {'dns_qname': 'a.example', 'dns_qtype': 'TXT',
                       'http_uri': '/x'}


def test_l7_summary_is_none_when_nothing_was_decoded():
    assert l7_summary({'src_ip': '10.0.0.1', 'frame_len': 60}) is None


def test_l7_summary_drops_non_scalar_values():
    assert l7_summary({'dns_answers': [1, 2, 3], 'dns_qname': 'a'}) == {
        'dns_qname': 'a'}


# ── writing ──────────────────────────────────────────────────────────────────

def test_write_batch_persists_packets_hosts_flows_and_rollups(
        db_engine, writer, analyzer, now):
    pkts = [parse(analyzer, F.tcp_frame(F.http_request('GET', '/a', 'h', 'ua'),
                                        '10.0.1.5', '93.184.216.34', 40000,
                                        80, 'PSH|ACK'), now)]
    written, alerts = writer.write_batch(pkts, [])
    assert (written, alerts) == (1, 0)
    assert scalar(db_engine, 'SELECT COUNT(*) FROM packets') == 1
    assert scalar(db_engine, 'SELECT COUNT(*) FROM hosts') == 2
    assert scalar(db_engine, 'SELECT COUNT(*) FROM flows') == 1
    assert scalar(db_engine, 'SELECT COUNT(*) FROM protocol_stats') == 1


def test_packets_reference_hosts_and_protocols_by_id(db_engine, writer,
                                                     analyzer, now):
    pkt = parse(analyzer, F.udp_frame(F.dns_query('a.example', 'A'),
                                      '10.0.1.7', '8.8.8.8', 5000, 53), now)
    writer.write_batch([pkt], [])
    row = rows(db_engine, """
        SELECT host(sh.ip) AS src, host(dh.ip) AS dst, pr.name AS protocol
        FROM packets p JOIN hosts sh ON sh.id = p.src_host_id
        JOIN hosts dh ON dh.id = p.dst_host_id
        JOIN protocols pr ON pr.id = p.protocol_id""")[0]
    assert row == {'src': '10.0.1.7', 'dst': '8.8.8.8', 'protocol': 'DNS'}


def test_flows_aggregate_rather_than_duplicate(db_engine, writer, analyzer,
                                               now):
    """Twenty packets on one 5-tuple must be one flow row with packets=20."""
    pkts = [parse(analyzer,
                  F.tcp_frame(F.tls_application_data(600), '10.0.1.9',
                              '104.16.12.5', 41000, 443, 'PSH|ACK'),
                  now + i * 0.01) for i in range(20)]
    writer.write_batch(pkts, [])
    flows = rows(db_engine, 'SELECT packets, bytes FROM flows')
    assert len(flows) == 1
    assert flows[0]['packets'] == 20
    assert flows[0]['bytes'] > 0


def test_flows_accumulate_across_batches(db_engine, writer, analyzer, now):
    def batch(count, offset):
        return [parse(analyzer,
                      F.tcp_frame(F.tls_application_data(400), '10.0.1.9',
                                  '104.16.12.5', 41000, 443, 'PSH|ACK'),
                      now + offset + i * 0.01) for i in range(count)]
    writer.write_batch(batch(5, 0), [])
    writer.write_batch(batch(7, 1), [])
    flows = rows(db_engine, 'SELECT packets FROM flows')
    assert len(flows) == 1
    assert flows[0]['packets'] == 12


def test_host_counters_accumulate_in_both_directions(db_engine, writer,
                                                     analyzer, now):
    sent = [parse(analyzer, F.tcp_frame(b'x' * 100, '10.0.1.11', '10.0.2.10',
                                        40000, 80, 'PSH|ACK'), now + i * 0.01)
            for i in range(3)]
    recv = [parse(analyzer, F.tcp_frame(b'y' * 100, '10.0.2.10', '10.0.1.11',
                                        80, 40000, 'PSH|ACK'), now + 1)]
    writer.write_batch(sent + recv, [])
    host = rows(db_engine, "SELECT packets_sent, packets_recv, bytes_sent, "
                           "bytes_recv FROM hosts WHERE ip = '10.0.1.11'")[0]
    assert host['packets_sent'] == 3
    assert host['packets_recv'] == 1
    assert host['bytes_sent'] > 0
    assert host['bytes_recv'] > 0


def test_geo_enrichment_marks_internal_hosts(db_engine, writer, analyzer, now):
    writer.write_batch([parse(analyzer,
                              F.tcp_frame(b'z', '10.0.1.12', '8.8.8.8', 40000,
                                          53, 'PSH|ACK'), now)], [])
    internal = rows(db_engine, "SELECT is_internal, country FROM hosts "
                               "WHERE ip = '10.0.1.12'")[0]
    external = rows(db_engine, "SELECT is_internal, country FROM hosts "
                               "WHERE ip = '8.8.8.8'")[0]
    assert internal['is_internal'] is True
    assert internal['country'] == 'PRIVATE'
    assert external['is_internal'] is False


def test_alerts_are_written_with_techniques_and_score_the_host(
        db_engine, writer, analyzer, now):
    pkt = parse(analyzer, F.tcp_frame(b'', '185.220.101.44', '10.0.2.10',
                                      40000, 22, 'SYN'), now)
    finding = Finding(threat_type='port_scan', severity='HIGH',
                      confidence=0.9, reason='synthetic',
                      techniques=('T1046',), src_ip='185.220.101.44',
                      dst_ip='10.0.2.10', protocol='TCP',
                      detector='port_scan', ts=now, evidence={'ports': 30})
    written, alerts = writer.write_batch([pkt], [finding])
    assert (written, alerts) == (1, 1)

    alert = rows(db_engine, """
        SELECT a.severity::text AS severity, tt.name AS threat_type,
               a.confidence, a.evidence, host(h.ip) AS src_ip
        FROM alerts a JOIN threat_types tt ON tt.id = a.threat_type_id
        JOIN hosts h ON h.id = a.src_host_id""")[0]
    assert alert['threat_type'] == 'port_scan'
    assert alert['severity'] == 'HIGH'
    assert alert['evidence'] == {'ports': 30}
    assert alert['src_ip'] == '185.220.101.44'

    assert scalar(db_engine, 'SELECT COUNT(*) FROM alert_techniques') == 1
    score = scalar(db_engine, "SELECT threat_score FROM hosts "
                              "WHERE ip = '185.220.101.44'")
    assert score == pytest.approx(6.0)


def test_alert_for_a_host_no_packet_mentioned_still_resolves(db_engine,
                                                             writer, now):
    """A detector may attribute an alert to a host absent from the batch."""
    finding = Finding(threat_type='brute_force', severity='CRITICAL',
                      confidence=0.95, reason='synthetic',
                      techniques=('T1110',), src_ip='45.33.32.156',
                      dst_ip='10.0.2.12', protocol='FTP',
                      detector='brute_force', ts=now)
    _written, alerts = writer.write_batch([], [finding])
    assert alerts == 1
    assert scalar(db_engine, "SELECT COUNT(*) FROM hosts "
                             "WHERE ip = '45.33.32.156'") == 1


def test_threat_score_is_capped_at_one_hundred(db_engine, writer, now):
    findings = [Finding(threat_type='syn_flood', severity='CRITICAL',
                        confidence=0.99, reason='flood', techniques=('T1498',),
                        src_ip='198.18.0.5', dst_ip='10.0.2.10',
                        detector='syn_flood', ts=now) for _ in range(50)]
    writer.write_batch([], findings)
    assert scalar(db_engine, "SELECT threat_score FROM hosts "
                             "WHERE ip = '198.18.0.5'") == 100.0


def test_unknown_threat_type_is_rejected_loudly(writer, now):
    finding = Finding(threat_type='not_a_registered_rule', severity='LOW',
                      confidence=0.5, reason='x', techniques=('T1046',),
                      src_ip='10.0.1.1', detector='ghost', ts=now)
    with pytest.raises(KeyError):
        writer.write_batch([], [finding])


def test_batch_is_atomic(db_engine, writer, analyzer, now, monkeypatch):
    """A failure part-way through must leave no rows from that batch."""
    pkts = [parse(analyzer, F.tcp_frame(b'a', '10.0.1.20', '10.0.2.20', 40000,
                                        80, 'PSH|ACK'), now + i)
            for i in range(5)]

    def boom(self, conn, packets, host_ids):
        raise RuntimeError('disk on fire')

    monkeypatch.setattr(BatchWriter, '_upsert_flows', boom)
    with pytest.raises(RuntimeError):
        writer.write_batch(pkts, [])
    assert scalar(db_engine, 'SELECT COUNT(*) FROM packets') == 0
    assert scalar(db_engine, 'SELECT COUNT(*) FROM hosts') == 0


def test_writer_recovers_after_a_failed_batch(db_engine, writer, analyzer,
                                              now, monkeypatch):
    pkts = [parse(analyzer, F.tcp_frame(b'a', '10.0.1.21', '10.0.2.21', 40000,
                                        80, 'PSH|ACK'), now)]

    def boom(self, conn, packets, host_ids):
        raise RuntimeError('transient')

    monkeypatch.setattr(BatchWriter, '_upsert_flows', boom)
    with pytest.raises(RuntimeError):
        writer.write_batch(pkts, [])
    monkeypatch.undo()
    assert writer.write_batch(pkts, []) == (1, 0)
    assert scalar(db_engine, 'SELECT COUNT(*) FROM packets') == 1


def test_writer_stats_track_what_was_written(db_engine, writer, analyzer, now):
    pkts = [parse(analyzer, F.tcp_frame(b'a', '10.0.1.22', '10.0.2.22', 40000,
                                        80, 'PSH|ACK'), now + i)
            for i in range(4)]
    writer.write_batch(pkts[:2], [])
    writer.write_batch(pkts[2:], [])
    stats = writer.stats()
    assert stats['batches_written'] == 2
    assert stats['packets_written'] == 4
    assert stats['mean_batch_ms'] > 0
    assert stats['deadlock_retries'] == 0


def test_empty_batch_is_a_no_op(writer):
    assert writer.write_batch([], []) == (0, 0)
    assert writer.stats()['batches_written'] == 0


def test_protocol_stats_bucket_by_minute(db_engine, writer, analyzer):
    base = (time.time() // 60) * 60          # aligned, so offsets are exact
    pkts = [parse(analyzer, F.udp_frame(F.dns_query('a.example', 'A'),
                                        '10.0.1.23', '8.8.8.8', 5000, 53),
                  base + offset) for offset in (0, 1, 61, 62, 121)]
    writer.write_batch(pkts, [])
    buckets = rows(db_engine, """
        SELECT ps.packets FROM protocol_stats ps
        JOIN protocols p ON p.id = ps.protocol_id
        WHERE p.name = 'DNS' ORDER BY ps.bucket""")
    assert len(buckets) == 3
    assert [b['packets'] for b in buckets] == [2, 2, 1]


def test_concurrent_writers_do_not_deadlock_on_shared_hosts(
        db_engine, lookups, analyzer):
    """Two writers touching overlapping hosts must both commit.

    This is the regression test for the lock-ordering fix: without sorting
    the upsert keys, concurrent batches over the same host population
    deadlock, and PostgreSQL aborts one of them.
    """
    import threading

    protocol_ids, threat_ids = lookups
    base = time.time()
    hosts = ['10.0.5.%d' % i for i in range(40)]

    def build(offset):
        return [parse(analyzer,
                      F.tcp_frame(b'p', hosts[i % len(hosts)],
                                  hosts[(i + 7) % len(hosts)], 40000 + i, 80,
                                  'PSH|ACK'), base + offset + i * 0.001)
                for i in range(300)]

    errors = []

    def run(offset):
        writer = BatchWriter(db_engine, protocol_ids, threat_ids)
        try:
            for round_ in range(4):
                writer.write_batch(build(offset + round_ * 10), [])
        except Exception as exc:      # noqa: BLE001 - recorded, then asserted
            errors.append(exc)
        finally:
            writer.close()

    threads = [threading.Thread(target=run, args=(i * 100,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert not errors, 'concurrent writers failed: %r' % errors
    assert scalar(db_engine, 'SELECT COUNT(*) FROM packets') == 4 * 4 * 300
