"""
Bulk data loader for the database-scale benchmark.

The pipeline produces alerts at the rate real detectors fire, which is
deliberately low — cooldowns exist so one sustained attack does not become ten
thousand duplicate rows. Measuring index behaviour on a hundreds-of-thousands
row event table therefore needs a loader, and this is it.

What it generates is synthetic but structurally faithful: the same host
population, the same threat-type and severity mix the detectors emit, the same
foreign keys, timestamps spread over a realistic window, and a skewed
distribution of alerts across hosts (a few noisy sources, a long tail) because
a uniform distribution would flatter every index equally and tell you nothing.

This is used by ``benchmarks/query_benchmark.py`` only. Nothing in the running
system calls it, and the benchmark reports the row counts it created so the
numbers can be read in context.
"""

import datetime as dt
import json
import random

from sqlalchemy import text

UTC = dt.UTC

# Weighted so CRITICAL and HIGH stay rare, as they do in the live pipeline —
# an index on severity is only interesting when the values are skewed.
SEVERITY_WEIGHTS = [('INFO', 5), ('LOW', 20), ('MEDIUM', 40), ('HIGH', 25),
                    ('CRITICAL', 10)]


def _host_ips(count, rng):
    internal = ['10.0.%d.%d' % (i // 250 + 1, i % 250 + 2)
                for i in range(count // 2)]
    external = ['%d.%d.%d.%d' % (rng.randrange(11, 223), rng.randrange(256),
                                 rng.randrange(256), rng.randrange(1, 255))
                for _ in range(count - len(internal))]
    return internal + external


def ensure_hosts(engine, count=2000, seed=99):
    """Create `count` hosts if the table does not already hold that many."""
    rng = random.Random(seed)
    now = dt.datetime.now(UTC)
    ips = _host_ips(count, rng)
    rows = [(ip, now - dt.timedelta(days=7), now, ip.startswith('10.'),
             'PRIVATE' if ip.startswith('10.') else 'US')
            for ip in ips]
    with engine.begin() as conn:
        raw = conn.connection.driver_connection
        conn.execute(text("""
            CREATE TEMP TABLE IF NOT EXISTS host_stage (
                ip inet, first_seen timestamptz, last_seen timestamptz,
                is_internal boolean, country varchar
            ) ON COMMIT DROP"""))
        with raw.cursor() as cur, cur.copy(
                'COPY host_stage (ip, first_seen, last_seen, is_internal, '
                'country) FROM STDIN') as copy:
            copy.set_types(['inet', 'timestamptz', 'timestamptz', 'bool',
                            'varchar'])
            for row in rows:
                copy.write_row(row)
        conn.execute(text("""
            INSERT INTO hosts (ip, first_seen, last_seen, is_internal, country)
            SELECT ip, first_seen, last_seen, is_internal, country
            FROM host_stage ORDER BY ip
            ON CONFLICT (ip) DO NOTHING"""))
        return conn.execute(text(
            'SELECT id FROM hosts ORDER BY id')).scalars().all()


def load_alerts(engine, count, host_ids, threat_type_ids, protocol_ids,
                span_days=14, seed=4242, chunk=50_000, techniques=None,
                technique_ratio=1.4):
    """COPY `count` alert rows (plus technique links) into the database.

    Returns a dict of the row counts actually written.
    """
    rng = random.Random(seed)
    severities = [s for s, _ in SEVERITY_WEIGHTS]
    weights = [w for _, w in SEVERITY_WEIGHTS]
    threat_ids = list(threat_type_ids.values())
    proto_ids = [v for k, v in protocol_ids.items() if k != 'UNKNOWN']
    techniques = list(techniques or [])

    # Skewed source distribution: 10% of hosts raise 70% of alerts, which is
    # what a real SOC sees and what makes a per-source index worth having.
    noisy = host_ids[:max(1, len(host_ids) // 10)]
    now = dt.datetime.now(UTC)
    span = span_days * 86400

    written = 0
    links_written = 0
    alert_cols = ('ts', 'severity', 'threat_type_id', 'src_host_id',
                  'dst_host_id', 'src_port', 'dst_port', 'protocol_id',
                  'confidence', 'description', 'evidence', 'acknowledged')
    # No set_types here: `severity_level` is a user-defined enum and psycopg's
    # binary registry does not know its OID. Text-format COPY lets the server
    # do the cast, which for a one-off loader is fast enough.

    while written < count:
        batch = min(chunk, count - written)
        with engine.begin() as conn:
            raw = conn.connection.driver_connection
            first_id = conn.execute(text(
                "SELECT COALESCE(MAX(id), 0) FROM alerts")).scalar()
            with raw.cursor() as cur, cur.copy(
                    'COPY alerts (%s) FROM STDIN'
                    % ', '.join(alert_cols)) as copy:
                for _ in range(batch):
                    src = (rng.choice(noisy) if rng.random() < 0.7
                           else rng.choice(host_ids))
                    ts = now - dt.timedelta(seconds=rng.random() * span)
                    severity = rng.choices(severities, weights)[0]
                    copy.write_row((
                        ts, severity, rng.choice(threat_ids), src,
                        rng.choice(host_ids), rng.randrange(1024, 65535),
                        rng.choice([22, 80, 443, 445, 3389, 53, 21]),
                        rng.choice(proto_ids), round(rng.uniform(0.5, 1.0), 3),
                        'synthetic benchmark alert', json.dumps(
                            {'window_s': 300, 'count': rng.randrange(5, 500)}),
                        rng.random() < 0.35))
            written += batch

            if techniques:
                link_cols = ('alert_id', 'technique_id', 'confidence', 'ts')
                with raw.cursor() as cur, cur.copy(
                        'COPY alert_techniques (%s) FROM STDIN'
                        % ', '.join(link_cols)) as copy:
                    copy.set_types(['int8', 'varchar', 'float8', 'timestamptz'])
                    for offset in range(batch):
                        alert_id = first_id + offset + 1
                        n_links = 1 if rng.random() > (technique_ratio - 1) \
                            else 2
                        for tid in rng.sample(techniques,
                                              min(n_links, len(techniques))):
                            copy.write_row((alert_id, tid,
                                            round(rng.uniform(0.5, 1.0), 3),
                                            now - dt.timedelta(
                                                seconds=rng.random() * span)))
                            links_written += 1
    return {'alerts': written, 'alert_techniques': links_written}


def load_packets(engine, count, host_ids, protocol_ids, span_hours=6,
                 seed=777, chunk=100_000):
    """COPY `count` packet rows, for queries that touch the largest table."""
    rng = random.Random(seed)
    proto_ids = list(protocol_ids.values())
    now = dt.datetime.now(UTC)
    span = span_hours * 3600
    written = 0
    cols = ('ts', 'src_host_id', 'dst_host_id', 'src_port', 'dst_port',
            'protocol_id', 'frame_len', 'payload_len', 'tcp_flags', 'entropy',
            'is_malicious', 'l7')
    types = ['timestamptz', 'int8', 'int8', 'int4', 'int4', 'int2', 'int4',
             'int4', 'varchar', 'float8', 'bool', 'jsonb']
    while written < count:
        batch = min(chunk, count - written)
        with engine.begin() as conn:
            raw = conn.connection.driver_connection
            with raw.cursor() as cur, cur.copy(
                    'COPY packets (%s) FROM STDIN' % ', '.join(cols)) as copy:
                copy.set_types(types)
                for _ in range(batch):
                    length = rng.randrange(64, 1500)
                    copy.write_row((
                        now - dt.timedelta(seconds=rng.random() * span),
                        rng.choice(host_ids), rng.choice(host_ids),
                        rng.randrange(1024, 65535),
                        rng.choice([22, 80, 443, 445, 53]),
                        rng.choice(proto_ids), length, max(0, length - 54),
                        rng.choice(['PSH|ACK', 'SYN', 'ACK', None]),
                        round(rng.uniform(0.5, 7.9), 3), rng.random() < 0.02,
                        None))
            written += batch
    return {'packets': written}
