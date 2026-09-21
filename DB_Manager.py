"""
DatabaseManager — PostgreSQL persistence for NetWatch SOC.

Eight tables, every one written by the live pipeline:

  1. packets              every processed packet with its decoded L7 summary
  2. connections          flow records keyed on the 5-tuple, upserted per batch
  3. hosts                host inventory + geo enrichment + rollup counters
  4. alerts               detector findings
  5. mitre_techniques     ATT&CK catalog (reference table, seeded from mitre.py)
  6. alert_techniques     many-to-many alert <-> technique with confidence
  7. protocol_stats       per-minute protocol rollup that backs the charts
  8. performance_metrics  measured engine throughput and query latency

There is deliberately no `threats` table: a "threat" is an aggregation over
alerts grouped by (src_ip, threat_type), which `get_threat_summary()` derives
with an indexed query. Materialising it would be a denormalised copy of data
`alerts` already holds.

Backends. PostgreSQL is the production database and the default. SQLite is
available for fast local work via DB_BACKEND=sqlite and is not supported for
production — see db_backends.py for the configuration variables and for the
shared SQL dialect the statements below are written in. This module contains
every query and no driver code; db_backends.py contains every driver
difference and no queries.

Schema. Owned by the versioned migrations under migrations/, applied by
migrate.py. There is no DDL in this file.

Concurrency. Reads come from a pooled connection per caller, so the Flask
worker's threads query in parallel. Writes go through one connection under a
lock: the packet pipeline writes one transaction per batch, and it is the only
writer by design (gunicorn.conf.py enforces a single engine process). This is
a choice now rather than a constraint — PostgreSQL would take concurrent
writers happily — and it avoids batches deadlocking against each other on the
same host and flow rows.
"""

import contextlib
import os
import time
import threading

import db_backends
import geoip
import migrate
import mitre
from db_backends import Json, json_load

TABLES = ('packets', 'connections', 'hosts', 'alerts', 'mitre_techniques',
          'alert_techniques', 'protocol_stats', 'performance_metrics')

# Explicit column lists where the table carries a generated ts_utc column.
# `SELECT *` would put a datetime into the JSON API for no caller's benefit;
# naming the columns also pins the response shape against future migrations.
ALERT_COLUMNS = (
    'id, ts, severity, threat_type, detector, src_ip, dst_ip, src_port, '
    'dst_port, protocol, confidence, description, evidence, acknowledged, '
    'ack_ts')
PERF_COLUMNS = (
    'id, ts, source, window_s, packets_processed, packets_per_min, '
    'alerts_generated, parse_errors, parse_us_avg, detect_us_avg, '
    'db_write_ms, query_p50_ms, query_p95_ms')

SEVERITY_WEIGHT = {'CRITICAL': 10, 'HIGH': 6, 'MEDIUM': 3, 'LOW': 1, 'INFO': 0}


class DatabaseManager:
    """All persistence and every read query the API issues.

    `target` overrides the environment: a PostgreSQL URL, or a file path when
    the backend is SQLite. Passing nothing uses DATABASE_URL / PG_* (or
    NETWATCH_DB under DB_BACKEND=sqlite).
    """

    def __init__(self, target=None, backend=None, auto_migrate=None):
        self.settings = db_backends.resolve_settings(target=target,
                                                     backend=backend)
        self._backend = db_backends.make_backend(self.settings)
        self._write_lock = threading.Lock()
        if auto_migrate is None:
            auto_migrate = os.environ.get('NETWATCH_AUTO_MIGRATE', '1') != '0'
        if auto_migrate:
            self.migrate()
        self.seed_technique_catalog()

    # ── identity ─────────────────────────────────────────────────────────────

    @property
    def dsn(self):
        """The connection target, as given. May contain a password."""
        return self.settings.dsn

    @property
    def display(self):
        """The connection target with any password redacted. Safe to log."""
        return self.settings.display

    @property
    def backend_name(self):
        return self._backend.name

    # ── connections ──────────────────────────────────────────────────────────

    @contextlib.contextmanager
    def _read_conn(self):
        """Borrow a reader connection and always hand it back.

        Under PostgreSQL these come from a pool and must be returned or the
        pool starves; under SQLite it is a thread-local connection and the
        release is a no-op.
        """
        conn = self._backend.reader()
        try:
            yield conn
        finally:
            self._backend.release_reader(conn)

    def close(self):
        with self._write_lock:
            self._backend.close()

    # ── schema ───────────────────────────────────────────────────────────────

    def migrate(self):
        """Apply any pending migrations. Idempotent."""
        with self._write_lock:
            return migrate.apply_pending(self._backend, self._backend.writer())

    def seed_technique_catalog(self):
        """Load the ATT&CK catalog from mitre.py into the reference table."""
        rows = [(t.id, t.name, t.tactic, t.url, t.rationale)
                for t in mitre.all_techniques()]
        with self._write_lock:
            conn = self._backend.writer()
            self._backend.begin(conn)
            try:
                self._backend.executemany(
                    conn,
                    """INSERT INTO mitre_techniques
                       (technique_id, name, tactic, url, rationale)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT (technique_id) DO UPDATE SET
                         name=excluded.name, tactic=excluded.tactic,
                         url=excluded.url, rationale=excluded.rationale""",
                    rows)
                self._backend.commit(conn)
            except Exception:
                self._backend.rollback(conn)
                raise

    def table_names(self):
        with self._read_conn() as conn:
            return self._backend.table_names(conn)

    def index_names(self):
        with self._read_conn() as conn:
            return self._backend.index_names(conn)

    def analyze(self):
        """Refresh planner statistics. Worth calling after a bulk load."""
        with self._write_lock:
            self._backend.analyze(self._backend.writer())

    # ── writes ───────────────────────────────────────────────────────────────

    def persist_batch(self, packets, findings):
        """Write one batch atomically. Returns (packet_rows, alert_rows, ms).

        `packets` are parsed packet dicts; `findings` are Finding objects. The
        whole batch shares one transaction, which is what makes sustained
        throughput possible — a transaction per packet would be ~100x slower.
        """
        t0 = time.perf_counter()
        alert_ids = []
        malicious_ips = {f.src_ip for f in findings if f.src_ip}

        with self._write_lock:
            conn = self._backend.writer()
            self._backend.begin(conn)
            try:
                if packets:
                    self._write_packets(conn, packets, malicious_ips)
                    self._write_connections(conn, packets)
                    self._write_hosts(conn, packets)
                    self._write_protocol_stats(conn, packets, findings)
                alert_ids = self._write_alerts(conn, findings)
                self._backend.commit(conn)
            except Exception:
                self._backend.rollback(conn)
                raise
        return len(packets), len(alert_ids), (time.perf_counter() - t0) * 1000

    @staticmethod
    def _l7_summary(pkt):
        """The decoded application-layer fields, for the JSON column."""
        interesting = {}
        for key, value in pkt.items():
            if key.count('_') and any(key.startswith(p + '_') for p in (
                    'dns', 'http', 'tls', 'ssh', 'ftp', 'smtp', 'pop3',
                    'imap', 'snmp', 'ntp', 'smb', 'rdp', 'dhcp', 'quic',
                    'arp', 'telnet', 'icmp')):
                if isinstance(value, (str, int, float, bool)) or value is None:
                    interesting[key] = value
        return Json(interesting) if interesting else Json(None)

    def _write_packets(self, conn, packets, malicious_ips):
        rows = [
            (p['ts'], p.get('src_ip') or '', p.get('dst_ip') or '',
             p.get('src_port'), p.get('dst_port'), p.get('protocol', 'UNKNOWN'),
             p.get('frame_len', 0), p.get('payload_len', 0),
             p.get('flags', ''), p.get('entropy', 0.0),
             p.get('src_ip') in malicious_ips,
             self._l7_summary(p))
            for p in packets
        ]
        self._backend.executemany(
            conn,
            """INSERT INTO packets
               (ts,src_ip,dst_ip,src_port,dst_port,protocol,frame_len,
                payload_len,flags,entropy,is_malicious,l7_summary)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", rows)

    def _write_connections(self, conn, packets):
        flows = {}
        for p in packets:
            key = (p.get('src_ip') or '', p.get('dst_ip') or '',
                   p.get('src_port') or 0, p.get('dst_port') or 0,
                   p.get('protocol', 'UNKNOWN'))
            f = flows.get(key)
            length = p.get('frame_len', 0)
            if f is None:
                flows[key] = [p['ts'], p['ts'], 1, length,
                              {p.get('flags', '')} - {''}]
            else:
                f[0] = min(f[0], p['ts'])
                f[1] = max(f[1], p['ts'])
                f[2] += 1
                f[3] += length
                if p.get('flags'):
                    f[4].add(p['flags'])
        rows = [(k[0], k[1], k[2], k[3], k[4], v[0], v[1], v[2], v[3],
                 ','.join(sorted(v[4]))[:64]) for k, v in flows.items()]
        # GREATEST/LEAST rather than SQLite's two-argument MAX/MIN, whose names
        # are aggregates in PostgreSQL. See db_backends.py.
        self._backend.executemany(
            conn,
            """INSERT INTO connections
               (src_ip,dst_ip,src_port,dst_port,protocol,first_seen,last_seen,
                packets,bytes,flags_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT (src_ip,dst_ip,src_port,dst_port,protocol)
               DO UPDATE SET
                 last_seen = GREATEST(connections.last_seen, excluded.last_seen),
                 first_seen= LEAST(connections.first_seen, excluded.first_seen),
                 packets   = connections.packets + excluded.packets,
                 bytes     = connections.bytes + excluded.bytes,
                 flags_seen= excluded.flags_seen""", rows)

    def _write_hosts(self, conn, packets):
        agg = {}
        for p in packets:
            length = p.get('frame_len', 0)
            for ip, sent in ((p.get('src_ip'), True), (p.get('dst_ip'), False)):
                if not ip:
                    continue
                h = agg.get(ip)
                if h is None:
                    h = agg[ip] = [p['ts'], p['ts'], 0, 0, 0, 0]
                h[0] = min(h[0], p['ts'])
                h[1] = max(h[1], p['ts'])
                if sent:
                    h[2] += 1
                    h[4] += length
                else:
                    h[3] += 1
                    h[5] += length
        rows = []
        for ip, h in agg.items():
            country, lat, lon = geoip.lookup(ip)
            rows.append((ip, h[0], h[1], country == 'PRIVATE',
                         country, lat, lon, h[2], h[3], h[4], h[5]))
        self._backend.executemany(
            conn,
            """INSERT INTO hosts
               (ip,first_seen,last_seen,is_internal,country,latitude,longitude,
                packets_sent,packets_recv,bytes_sent,bytes_recv)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT (ip) DO UPDATE SET
                 last_seen   = GREATEST(hosts.last_seen, excluded.last_seen),
                 first_seen  = LEAST(hosts.first_seen, excluded.first_seen),
                 packets_sent= hosts.packets_sent + excluded.packets_sent,
                 packets_recv= hosts.packets_recv + excluded.packets_recv,
                 bytes_sent  = hosts.bytes_sent + excluded.bytes_sent,
                 bytes_recv  = hosts.bytes_recv + excluded.bytes_recv""", rows)

    def _write_protocol_stats(self, conn, packets, findings):
        buckets = {}
        for p in packets:
            key = (int(p['ts'] // 60) * 60, p.get('protocol', 'UNKNOWN'))
            b = buckets.setdefault(key, [0, 0, 0])
            b[0] += 1
            b[1] += p.get('frame_len', 0)
        for f in findings:
            key = (int(f.ts // 60) * 60, f.protocol or 'UNKNOWN')
            buckets.setdefault(key, [0, 0, 0])[2] += 1
        rows = [(k[0], k[1], v[0], v[1], v[2]) for k, v in buckets.items()]
        self._backend.executemany(
            conn,
            """INSERT INTO protocol_stats (bucket,protocol,packets,bytes,alerts)
               VALUES (?,?,?,?,?)
               ON CONFLICT (bucket,protocol) DO UPDATE SET
                 packets = protocol_stats.packets + excluded.packets,
                 bytes   = protocol_stats.bytes + excluded.bytes,
                 alerts  = protocol_stats.alerts + excluded.alerts""", rows)

    def _write_alerts(self, conn, findings):
        alert_ids = []
        for f in findings:
            # RETURNING rather than cursor.lastrowid, which is SQLite-only.
            alert_id = self._backend.execute(
                conn,
                """INSERT INTO alerts
                   (ts,severity,threat_type,detector,src_ip,dst_ip,src_port,
                    dst_port,protocol,confidence,description,evidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   RETURNING id""",
                (f.ts, f.severity, f.threat_type, f.detector, f.src_ip,
                 f.dst_ip, f.src_port, f.dst_port, f.protocol, f.confidence,
                 f.reason, Json(f.evidence))).scalar()
            alert_ids.append(alert_id)
            self._backend.executemany(
                conn,
                """INSERT INTO alert_techniques
                   (alert_id,technique_id,confidence,ts) VALUES (?,?,?,?)
                   ON CONFLICT DO NOTHING""",
                [(alert_id, tid, f.confidence, f.ts) for tid in f.techniques])
            if f.src_ip:
                self._backend.execute(
                    conn,
                    """UPDATE hosts SET alert_count = alert_count + 1,
                       threat_score = LEAST(100, threat_score + ?)
                       WHERE ip = ?""",
                    (SEVERITY_WEIGHT[f.severity], f.src_ip))
        return alert_ids

    def record_performance(self, metrics):
        values = {'ts': time.time(), 'source': 'engine', 'window_s': 0,
                  'packets_processed': 0, 'packets_per_min': 0,
                  'alerts_generated': 0, 'parse_errors': 0, 'parse_us_avg': 0,
                  'detect_us_avg': 0, 'db_write_ms': 0, 'query_p50_ms': 0,
                  'query_p95_ms': 0, **metrics}
        order = ('ts', 'source', 'window_s', 'packets_processed',
                 'packets_per_min', 'alerts_generated', 'parse_errors',
                 'parse_us_avg', 'detect_us_avg', 'db_write_ms',
                 'query_p50_ms', 'query_p95_ms')
        with self._write_lock:
            conn = self._backend.writer()
            self._backend.begin(conn)
            try:
                self._backend.execute(
                    conn,
                    """INSERT INTO performance_metrics
                       (ts,source,window_s,packets_processed,packets_per_min,
                        alerts_generated,parse_errors,parse_us_avg,
                        detect_us_avg,db_write_ms,query_p50_ms,query_p95_ms)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    tuple(values[k] for k in order))
                self._backend.commit(conn)
            except Exception:
                self._backend.rollback(conn)
                raise

    # Delete order matters only for readability: alert_techniques rows go with
    # their alert through ON DELETE CASCADE.
    _PRUNE = (
        ('alerts', 'DELETE FROM alerts WHERE ts < ?'),
        ('packets', 'DELETE FROM packets WHERE ts < ?'),
        ('connections', 'DELETE FROM connections WHERE last_seen < ?'),
        ('hosts', 'DELETE FROM hosts WHERE last_seen < ?'),
        ('protocol_stats', 'DELETE FROM protocol_stats WHERE bucket < ?'),
        ('performance_metrics', 'DELETE FROM performance_metrics WHERE ts < ?'),
    )

    def prune(self, before_ts):
        """Delete telemetry older than `before_ts`. Returns rows deleted per table.

        Time-based retention keeps a long-running deployment's database bounded.
        Rows are judged by when they were last relevant: packets and alerts by
        their own timestamp, flows and hosts by `last_seen`. A flow or host that
        is still active keeps its cumulative counters, so those describe its
        whole lifetime rather than only the retained window. A protocol_stats
        bucket is removed only once its entire minute is older than the cutoff.

        PostgreSQL reuses the space autovacuum reclaims, so the database stops
        growing at steady state rather than shrinking; a VACUUM FULL is needed
        to return space to the filesystem and takes an exclusive lock, so run
        it in a maintenance window if you ever need to. The mitre_techniques
        catalog is reference data and is never pruned.
        """
        bucket_cutoff = int(before_ts // 60) * 60
        deleted = {}
        with self._write_lock:
            conn = self._backend.writer()
            self._backend.begin(conn)
            try:
                for table, sql in self._PRUNE:
                    param = bucket_cutoff if table == 'protocol_stats' \
                        else before_ts
                    deleted[table] = self._backend.execute(
                        conn, sql, (param,)).rowcount
                self._backend.commit(conn)
            except Exception:
                self._backend.rollback(conn)
                raise
        return deleted

    def acknowledge_alert(self, alert_id):
        with self._write_lock:
            conn = self._backend.writer()
            self._backend.begin(conn)
            try:
                result = self._backend.execute(
                    conn,
                    'UPDATE alerts SET acknowledged=TRUE, ack_ts=? WHERE id=?',
                    (time.time(), alert_id))
                self._backend.commit(conn)
            except Exception:
                self._backend.rollback(conn)
                raise
            return result.rowcount

    # ── reads ────────────────────────────────────────────────────────────────

    def query(self, sql, params=()):
        """Run one read statement. Returns a db_backends.Result."""
        with self._read_conn() as conn:
            return self._backend.execute(conn, sql, params)

    def rows(self, sql, params=()):
        return self.query(sql, params).rows

    def _rows(self, sql, params=()):
        return self.query(sql, params).rows

    def _one(self, sql, params=()):
        return self.query(sql, params).one()

    def _scalar(self, sql, params=(), default=0):
        return self.query(sql, params).scalar(default)

    # One statement rather than twelve. Each counter is a scalar subquery, so
    # the dashboard's most-polled endpoint costs a single round trip and one
    # shared pass over the buffer cache. Issued separately this was the slowest
    # query in the API under PostgreSQL, where a round trip is a socket rather
    # than a function call.
    _OVERVIEW = """
        SELECT
          (SELECT COUNT(*) FROM packets)                        AS total_packets,
          (SELECT COUNT(*) FROM packets WHERE ts > ?)           AS packets_last_hour,
          (SELECT CAST(AVG(pm) AS DOUBLE PRECISION) FROM (
             SELECT SUM(packets) AS pm FROM protocol_stats
             WHERE bucket > ? GROUP BY bucket) AS per_bucket)   AS packets_per_min,
          (SELECT COUNT(*) FROM alerts)                         AS total_alerts,
          (SELECT COUNT(*) FROM alerts WHERE ts > ?)            AS alerts_24h,
          (SELECT COUNT(*) FROM alerts
             WHERE severity='CRITICAL' AND NOT acknowledged)    AS critical_open,
          (SELECT COUNT(*) FROM alerts WHERE NOT acknowledged)   AS unacknowledged,
          (SELECT COUNT(DISTINCT threat_type) FROM alerts)      AS distinct_threat_types,
          (SELECT COUNT(DISTINCT technique_id)
             FROM alert_techniques)                             AS techniques_observed,
          (SELECT COUNT(*) FROM hosts)                          AS hosts_tracked,
          (SELECT COUNT(*) FROM connections WHERE last_seen > ?) AS active_flows,
          (SELECT AVG(confidence) FROM alerts WHERE ts > ?)      AS mean_confidence
    """

    def get_overview(self):
        now = time.time()
        hour, day = now - 3600, now - 86400
        row = self._one(self._OVERVIEW,
                        (hour, int(now - 600), day, now - 300, day))
        row['packets_per_min'] = round(row['packets_per_min'] or 0.0, 1)
        row['mean_confidence'] = round(row['mean_confidence'] or 0.0, 3)
        return row

    def get_throughput(self, minutes=60):
        cutoff = int(time.time() - minutes * 60)
        return self._rows(
            """SELECT bucket,
                      CAST(SUM(packets) AS BIGINT) AS packets,
                      CAST(SUM(bytes)   AS BIGINT) AS bytes,
                      CAST(SUM(alerts)  AS BIGINT) AS alerts
               FROM protocol_stats WHERE bucket > ?
               GROUP BY bucket ORDER BY bucket""", (cutoff,))

    def get_protocol_distribution(self, minutes=1440):
        cutoff = int(time.time() - minutes * 60)
        return self._rows(
            """SELECT protocol,
                      CAST(SUM(packets) AS BIGINT) AS packets,
                      CAST(SUM(bytes)   AS BIGINT) AS bytes,
                      CAST(SUM(alerts)  AS BIGINT) AS alerts
               FROM protocol_stats WHERE bucket > ?
               GROUP BY protocol ORDER BY packets DESC""", (cutoff,))

    def get_severity_breakdown(self, hours=24):
        cutoff = time.time() - hours * 3600
        return self._rows(
            """SELECT severity, COUNT(*) AS count, AVG(confidence) AS avg_conf
               FROM alerts WHERE ts > ? GROUP BY severity""", (cutoff,))

    def get_alert_timeline(self, hours=24, bucket_s=3600):
        cutoff = time.time() - hours * 3600
        # FLOOR, not CAST-to-integer: SQLite truncates on that cast while
        # PostgreSQL rounds, which would put half the alerts a bucket late.
        return self._rows(
            """SELECT CAST(FLOOR(ts/?) AS BIGINT)*? AS bucket, severity,
                      COUNT(*) AS count
               FROM alerts WHERE ts > ?
               GROUP BY bucket, severity ORDER BY bucket""",
            (bucket_s, bucket_s, cutoff))

    def get_alerts(self, limit=50, offset=0, severity=None, threat_type=None,
                   src_ip=None, acknowledged=None, since=None):
        where, params = [], []
        if severity:
            where.append('severity = ?')
            params.append(severity)
        if threat_type:
            where.append('threat_type = ?')
            params.append(threat_type)
        if src_ip:
            where.append('src_ip = ?')
            params.append(src_ip)
        if acknowledged is not None:
            where.append('acknowledged = ?')
            params.append(bool(acknowledged))
        if since is not None:
            where.append('ts > ?')
            params.append(since)
        clause = ('WHERE ' + ' AND '.join(where)) if where else ''
        total = self._scalar('SELECT COUNT(*) FROM alerts ' + clause,
                             tuple(params))
        rows = self._rows(
            'SELECT %s FROM alerts %s ORDER BY ts DESC LIMIT ? OFFSET ?'
            % (ALERT_COLUMNS, clause), tuple(params) + (limit, offset))
        for r in rows:
            r['evidence'] = json_load(r['evidence']) or {}
        return {'total': total, 'count': len(rows), 'limit': limit,
                'offset': offset, 'alerts': rows}

    def get_alert(self, alert_id):
        alert = self._one(
            'SELECT %s FROM alerts WHERE id = ?' % ALERT_COLUMNS, (alert_id,))
        if not alert:
            return None
        alert['evidence'] = json_load(alert['evidence']) or {}
        alert['techniques'] = self._rows(
            """SELECT t.technique_id, t.name, t.tactic, t.url, t.rationale,
                      at.confidence
               FROM alert_techniques at
               JOIN mitre_techniques t ON t.technique_id = at.technique_id
               WHERE at.alert_id = ?""", (alert_id,))
        # Packets around the alert from the same source, for context.
        alert['related_packets'] = self._rows(
            """SELECT id, ts, src_ip, dst_ip, src_port, dst_port, protocol,
                      frame_len, flags, l7_summary
               FROM packets
               WHERE src_ip = ? AND ts BETWEEN ? AND ?
               ORDER BY ts DESC LIMIT 20""",
            (alert['src_ip'], alert['ts'] - 60, alert['ts'] + 5))
        for packet in alert['related_packets']:
            packet['l7_summary'] = json_load(packet['l7_summary'])
        return alert

    def get_alert_stats_by_type(self, hours=24):
        cutoff = time.time() - hours * 3600
        # COUNT(*) FILTER, not SUM(severity='CRITICAL'): summing a boolean is
        # a type error in PostgreSQL.
        return self._rows(
            """SELECT threat_type, detector, COUNT(*) AS count,
                      AVG(confidence) AS avg_conf,
                      COUNT(*) FILTER (WHERE severity='CRITICAL') AS critical,
                      COUNT(*) FILTER (WHERE severity='HIGH') AS high,
                      MAX(ts) AS last_seen
               FROM alerts WHERE ts > ?
               GROUP BY threat_type, detector ORDER BY count DESC""", (cutoff,))
        # detector is in the GROUP BY because PostgreSQL requires every bare
        # selected column to be there. It does not change the grouping: each
        # detector class sets name == threat_type, so the two are 1:1.

    def get_threat_summary(self, hours=24, limit=50):
        """Aggregated per (source, threat type) — the 'active threats' view.

        Derived rather than stored; see the module docstring.
        """
        cutoff = time.time() - hours * 3600
        return self._rows(
            """SELECT src_ip, threat_type, COUNT(*) AS alert_count,
                      MIN(ts) AS first_seen, MAX(ts) AS last_seen,
                      MAX(confidence) AS max_confidence,
                      COUNT(*) FILTER (WHERE NOT acknowledged) AS open_alerts,
                      MIN(CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH'
                          THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3
                          ELSE 4 END) AS sev_rank
               FROM alerts WHERE ts > ? AND src_ip IS NOT NULL
               GROUP BY src_ip, threat_type
               ORDER BY sev_rank ASC, alert_count DESC LIMIT ?""",
            (cutoff, limit))

    def get_mitre_techniques(self, hours=None):
        params = []
        join = ''
        if hours:
            join = 'AND at.ts > ?'
            params.append(time.time() - hours * 3600)
        return self._rows(
            """SELECT t.technique_id, t.name, t.tactic, t.url, t.rationale,
                      COUNT(at.alert_id) AS alert_count,
                      AVG(at.confidence) AS avg_confidence,
                      MAX(at.ts) AS last_seen
               FROM mitre_techniques t
               LEFT JOIN alert_techniques at
                 ON at.technique_id = t.technique_id %s
               GROUP BY t.technique_id, t.name, t.tactic, t.url, t.rationale
               ORDER BY alert_count DESC, t.technique_id""" % join,
            tuple(params))

    def get_mitre_technique(self, technique_id, limit=25):
        tech = self._one(
            'SELECT technique_id, name, tactic, url, rationale '
            'FROM mitre_techniques WHERE technique_id = ?', (technique_id,))
        if not tech:
            return None
        tech['alert_count'] = self._scalar(
            'SELECT COUNT(*) FROM alert_techniques WHERE technique_id = ?',
            (technique_id,))
        # Grouped by both columns for PostgreSQL's benefit; detector and
        # threat_type are 1:1, so the rows are the same as grouping by detector.
        tech['detectors'] = self._rows(
            """SELECT a.detector, a.threat_type, COUNT(*) AS count
               FROM alert_techniques at JOIN alerts a ON a.id = at.alert_id
               WHERE at.technique_id = ?
               GROUP BY a.detector, a.threat_type ORDER BY count DESC""",
            (technique_id,))
        tech['recent_alerts'] = self._rows(
            """SELECT a.id, a.ts, a.severity, a.threat_type, a.src_ip,
                      a.dst_ip, a.protocol, a.confidence, a.description
               FROM alert_techniques at JOIN alerts a ON a.id = at.alert_id
               WHERE at.technique_id = ?
               ORDER BY a.ts DESC LIMIT ?""", (technique_id, limit))
        return tech

    def get_mitre_coverage(self):
        rows = self._rows(
            """SELECT t.tactic, t.technique_id, t.name,
                      COUNT(at.alert_id) AS alert_count
               FROM mitre_techniques t
               LEFT JOIN alert_techniques at
                 ON at.technique_id = t.technique_id
               GROUP BY t.tactic, t.technique_id, t.name
               ORDER BY t.tactic, t.technique_id""")
        by_tactic = {}
        for r in rows:
            by_tactic.setdefault(r['tactic'], []).append(r)
        return [
            {'tactic': tactic,
             'techniques': techs,
             'total_alerts': sum(t['alert_count'] for t in techs),
             'observed': sum(1 for t in techs if t['alert_count'] > 0),
             'catalogued': len(techs)}
            for tactic, techs in sorted(by_tactic.items())
        ]

    def get_top_hosts(self, limit=15, order='packets_sent'):
        if order not in ('packets_sent', 'bytes_sent', 'threat_score',
                         'alert_count', 'packets_recv'):
            order = 'packets_sent'
        return self._rows(
            'SELECT * FROM hosts ORDER BY %s DESC LIMIT ?' % order, (limit,))

    def get_host(self, ip):
        host = self._one('SELECT * FROM hosts WHERE ip = ?', (ip,))
        if not host:
            return None
        host['top_protocols'] = self._rows(
            """SELECT protocol, COUNT(*) AS packets,
                      CAST(SUM(frame_len) AS BIGINT) AS bytes
               FROM packets WHERE src_ip = ?
               GROUP BY protocol ORDER BY packets DESC LIMIT 10""", (ip,))
        host['recent_alerts'] = self._rows(
            """SELECT id, ts, severity, threat_type, dst_ip, protocol,
                      confidence, description
               FROM alerts WHERE src_ip = ? ORDER BY ts DESC LIMIT 20""",
            (ip,))
        host['top_peers'] = self._rows(
            """SELECT dst_ip AS peer,
                      CAST(SUM(packets) AS BIGINT) AS packets,
                      CAST(SUM(bytes)   AS BIGINT) AS bytes
               FROM connections WHERE src_ip = ?
               GROUP BY dst_ip ORDER BY bytes DESC LIMIT 10""", (ip,))
        return host

    def get_geo_distribution(self):
        return self._rows(
            """SELECT country, COUNT(*) AS hosts,
                      CAST(SUM(packets_sent) AS BIGINT) AS packets,
                      CAST(SUM(bytes_sent)   AS BIGINT) AS bytes,
                      CAST(SUM(alert_count)  AS BIGINT) AS alerts,
                      AVG(latitude) AS latitude, AVG(longitude) AS longitude
               FROM hosts WHERE country NOT IN ('PRIVATE')
               GROUP BY country ORDER BY packets DESC""")

    def get_connections(self, limit=50, order='last_seen', src_ip=None):
        if order not in ('last_seen', 'bytes', 'packets', 'first_seen'):
            order = 'last_seen'
        where, params = '', []
        if src_ip:
            where = 'WHERE src_ip = ?'
            params.append(src_ip)
        return self._rows(
            'SELECT * FROM connections %s ORDER BY %s DESC LIMIT ?'
            % (where, order), tuple(params) + (limit,))

    def get_packets(self, limit=100, protocol=None, src_ip=None, dst_ip=None,
                    malicious_only=False, since=None):
        where, params = [], []
        if protocol:
            where.append('protocol = ?')
            params.append(protocol)
        if src_ip:
            where.append('src_ip = ?')
            params.append(src_ip)
        if dst_ip:
            where.append('dst_ip = ?')
            params.append(dst_ip)
        if malicious_only:
            where.append('is_malicious')
        if since is not None:
            where.append('ts > ?')
            params.append(since)
        clause = ('WHERE ' + ' AND '.join(where)) if where else ''
        rows = self._rows(
            'SELECT * FROM packets %s ORDER BY ts DESC LIMIT ?' % clause,
            tuple(params) + (limit,))
        for r in rows:
            r['l7'] = json_load(r.pop('l7_summary', None)) or {}
        return rows

    def get_performance(self, limit=120, source=None):
        if source:
            return self._rows(
                'SELECT %s FROM performance_metrics WHERE source = ? '
                'ORDER BY ts DESC LIMIT ?' % PERF_COLUMNS, (source, limit))
        return self._rows(
            'SELECT %s FROM performance_metrics ORDER BY ts DESC LIMIT ?'
            % PERF_COLUMNS, (limit,))

    # Exact counts, in one round trip. An estimate from pg_class.reltuples
    # would be cheaper still, but /api/health is the endpoint the container
    # healthcheck and the tests read row counts from, and an approximation
    # there would be worse than useless.
    _COUNTS = 'SELECT ' + ', '.join(
        '(SELECT COUNT(*) FROM "%s") AS "%s"' % (table, table)
        for table in TABLES)

    def health(self):
        t0 = time.perf_counter()
        with self._read_conn() as conn:
            counts = dict(self._backend.execute(conn, self._COUNTS).one())
            latency_ms = (time.perf_counter() - t0) * 1000
            return {
                'status': 'ok',
                'backend': self._backend.name,
                'database': self.display,
                'server_version': self._backend.server_version(conn),
                'db_size_bytes': self._backend.size_bytes(conn),
                'tables': counts,
                'table_count': len(counts),
                'index_count': len(self._backend.index_names(conn)),
                'journal_mode': self._backend.journal_mode(conn),
                'count_query_ms': round(latency_ms, 3),
            }

    def explain(self, sql, params=()):
        """Query-plan rows, each with a 'detail' string — used by tests to
        prove index usage. The plan text is the backend's own."""
        with self._read_conn() as conn:
            return self._backend.explain(conn, sql, params)
