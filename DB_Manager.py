"""
DatabaseManager — persistence for NetWatch SOC.

Two interchangeable backends behind one API (see db_dialects.py):

  PostgreSQL  the deployment target. Selected by NETWATCH_DB_URL, e.g.
              postgresql://netwatch:...@postgres:5432/netwatch
  SQLite      zero-dependency default, used by the test suite, the benchmark
              and single-container runs. Selected by NETWATCH_DB (a path).

Nine tables, every one written by the live pipeline or the validation
harness:

  1. packets              every processed packet with its decoded L7 summary
  2. connections          flow records keyed on the 5-tuple, upserted per batch
  3. hosts                host inventory + geo enrichment + rollup counters
  4. alerts               detector findings
  5. mitre_techniques     ATT&CK catalog (reference table, seeded from mitre.py)
  6. alert_techniques     many-to-many alert <-> technique with confidence
  7. protocol_stats       per-minute protocol rollup that backs the charts
  8. performance_metrics  measured engine/benchmark throughput and latency
  9. validation_runs      PCAP-replay and tuning results (TP/FP/FN, TPR)

There is deliberately no `threats` table: a "threat" is an aggregation over
alerts grouped by (src_ip, threat_type), which `get_threat_summary()` derives
with an indexed query. Materialising it would be a denormalised copy of data
`alerts` already holds.

Concurrency: one long-lived writer connection guarded by a lock, plus
thread-local reader connections. Both backends run with explicit transaction
control, so the BEGIN/COMMIT in the write path means the same thing on each.
"""

import json
import os
import threading
import time

import db_dialects
import geoip
import mitre

DB_PATH = os.environ.get('NETWATCH_DB', db_dialects.DEFAULT_SQLITE_PATH)
DB_URL = os.environ.get('NETWATCH_DB_URL')

SCHEMA = """
-- 1. Raw packet log -----------------------------------------------------
CREATE TABLE IF NOT EXISTS packets (
    id           {PK},
    ts           {REAL}    NOT NULL,
    src_ip       TEXT    NOT NULL,
    dst_ip       TEXT    NOT NULL,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT    NOT NULL,
    frame_len    INTEGER NOT NULL,
    payload_len  INTEGER DEFAULT 0,
    flags        TEXT,
    entropy      {REAL}    DEFAULT 0,
    is_malicious INTEGER DEFAULT 0,
    l7_summary   TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_ts        ON packets(ts DESC);
CREATE INDEX IF NOT EXISTS idx_packets_src_ts    ON packets(src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ts    ON packets(dst_ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_packets_proto_ts  ON packets(protocol, ts DESC);
CREATE INDEX IF NOT EXISTS idx_packets_malicious ON packets(is_malicious, ts DESC);
-- Covering index for the per-host protocol breakdown on the host detail page.
-- Without it that GROUP BY builds a temp b-tree over every packet the host
-- sent, which is the single slowest query in the API at scale.
CREATE INDEX IF NOT EXISTS idx_packets_src_proto ON packets(src_ip, protocol, frame_len);

-- 2. Flow / connection tracking -----------------------------------------
CREATE TABLE IF NOT EXISTS connections (
    id          {PK},
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    src_port    INTEGER NOT NULL DEFAULT 0,
    dst_port    INTEGER NOT NULL DEFAULT 0,
    protocol    TEXT    NOT NULL,
    first_seen  {REAL}    NOT NULL,
    last_seen   {REAL}    NOT NULL,
    packets     INTEGER DEFAULT 0,
    bytes       INTEGER DEFAULT 0,
    flags_seen  TEXT    DEFAULT '',
    state       TEXT    DEFAULT 'ACTIVE',
    UNIQUE(src_ip, dst_ip, src_port, dst_port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_conn_last  ON connections(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_conn_src   ON connections(src_ip, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_conn_bytes ON connections(bytes DESC);
-- Covering index for the per-host peer rollup, for the same reason.
CREATE INDEX IF NOT EXISTS idx_conn_src_dst ON connections(src_ip, dst_ip, packets, bytes);

-- 3. Host inventory ------------------------------------------------------
CREATE TABLE IF NOT EXISTS hosts (
    ip            TEXT    PRIMARY KEY,
    first_seen    {REAL}    NOT NULL,
    last_seen     {REAL}    NOT NULL,
    is_internal   INTEGER DEFAULT 0,
    country       TEXT    DEFAULT 'UNKNOWN',
    latitude      {REAL},
    longitude     {REAL},
    packets_sent  INTEGER DEFAULT 0,
    packets_recv  INTEGER DEFAULT 0,
    bytes_sent    INTEGER DEFAULT 0,
    bytes_recv    INTEGER DEFAULT 0,
    alert_count   INTEGER DEFAULT 0,
    threat_score  {REAL}    DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hosts_country ON hosts(country);
CREATE INDEX IF NOT EXISTS idx_hosts_sent    ON hosts(packets_sent DESC);
CREATE INDEX IF NOT EXISTS idx_hosts_threat  ON hosts(threat_score DESC);

-- 4. Alerts --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id           {PK},
    ts           {REAL}    NOT NULL,
    severity     TEXT    NOT NULL
                 CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    threat_type  TEXT    NOT NULL,
    detector     TEXT    NOT NULL,
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT,
    confidence   {REAL}    NOT NULL,
    description  TEXT    NOT NULL,
    evidence     TEXT,
    acknowledged INTEGER DEFAULT 0,
    ack_ts       {REAL}
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev_ts   ON alerts(severity, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_type_ts  ON alerts(threat_type, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ts   ON alerts(src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ack      ON alerts(acknowledged, ts DESC);

-- 5. ATT&CK catalog ------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    tactic       TEXT NOT NULL,
    url          TEXT,
    rationale    TEXT
);
CREATE INDEX IF NOT EXISTS idx_mitre_tactic ON mitre_techniques(tactic);

-- 6. Alert <-> technique mapping ----------------------------------------
CREATE TABLE IF NOT EXISTS alert_techniques (
    alert_id     INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    technique_id TEXT    NOT NULL REFERENCES mitre_techniques(technique_id),
    confidence   {REAL}    NOT NULL,
    ts           {REAL}    NOT NULL,
    PRIMARY KEY (alert_id, technique_id)
);
CREATE INDEX IF NOT EXISTS idx_at_technique ON alert_techniques(technique_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_at_ts        ON alert_techniques(ts DESC);

-- 7. Per-minute protocol rollup -----------------------------------------
CREATE TABLE IF NOT EXISTS protocol_stats (
    bucket   INTEGER NOT NULL,          -- unix time floored to the minute
    protocol TEXT    NOT NULL,
    packets  INTEGER DEFAULT 0,
    bytes    INTEGER DEFAULT 0,
    alerts   INTEGER DEFAULT 0,
    PRIMARY KEY (bucket, protocol)
);
CREATE INDEX IF NOT EXISTS idx_pstat_bucket ON protocol_stats(bucket DESC);

-- 8. Measured performance ------------------------------------------------
CREATE TABLE IF NOT EXISTS performance_metrics (
    id                {PK},
    ts                {REAL}    NOT NULL,
    source            TEXT    NOT NULL DEFAULT 'engine',
    window_s          {REAL}    NOT NULL,
    packets_processed INTEGER NOT NULL,
    packets_per_min   {REAL}    NOT NULL,
    alerts_generated  INTEGER DEFAULT 0,
    parse_errors      INTEGER DEFAULT 0,
    parse_us_avg      {REAL}    DEFAULT 0,
    detect_us_avg     {REAL}    DEFAULT 0,
    db_write_ms       {REAL}    DEFAULT 0,
    query_p50_ms      {REAL}    DEFAULT 0,
    query_p95_ms      {REAL}    DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_perf_ts     ON performance_metrics(ts DESC);
CREATE INDEX IF NOT EXISTS idx_perf_source ON performance_metrics(source, ts DESC);

-- 9. Validation runs ------------------------------------------------------
-- Written by tests/replay.py (PCAP replay) and tools/noise_experiment.py
-- (threshold tuning). Keeps the measured detection quality of each run next
-- to the data it was measured on, so a claim can be traced to a run rather
-- than to a README.
CREATE TABLE IF NOT EXISTS validation_runs (
    id               {PK},
    ts               {REAL} NOT NULL,
    kind             TEXT   NOT NULL,   -- replay | tuning
    profile          TEXT   NOT NULL,   -- config profile the run used
    corpus           TEXT   NOT NULL,   -- pcap corpus identifier
    pcap_count       INTEGER DEFAULT 0,
    packets          INTEGER DEFAULT 0,
    scenarios        INTEGER DEFAULT 0,
    true_positives   INTEGER DEFAULT 0,
    false_positives  INTEGER DEFAULT 0,
    false_negatives  INTEGER DEFAULT 0,
    precision_pct    {REAL} DEFAULT 0,
    recall_pct       {REAL} DEFAULT 0,
    tpr_pct          {REAL} DEFAULT 0,
    alerts_total     INTEGER DEFAULT 0,
    detail           TEXT
);
CREATE INDEX IF NOT EXISTS idx_val_ts   ON validation_runs(ts DESC);
CREATE INDEX IF NOT EXISTS idx_val_kind ON validation_runs(kind, ts DESC);
"""

TABLES = ('packets', 'connections', 'hosts', 'alerts', 'mitre_techniques',
          'alert_techniques', 'protocol_stats', 'performance_metrics',
          'validation_runs')


class DatabaseManager:
    """Backend-agnostic persistence.

    `db_path` accepts either a filesystem path (SQLite) or a postgresql:// URL.
    With neither, NETWATCH_DB_URL wins over NETWATCH_DB, which wins over
    ./netwatch.db.
    """

    def __init__(self, db_path=None, url=None, schema=None):
        self.dialect = db_dialects.from_env(db_path=db_path, url=url,
                                            schema=schema)
        self.backend = self.dialect.name
        # Kept as `db_path` for backwards compatibility: it is the path for
        # SQLite and the credential-stripped URL for PostgreSQL.
        self.db_path = self.dialect.target
        self._write_lock = threading.Lock()
        self._local = threading.local()
        self._write_conn = self.dialect.connect()
        self.init_schema()
        self.seed_technique_catalog()

    # -- connections ---------------------------------------------------------

    def reader(self):
        """Thread-local read connection. Reused so query latency is honest."""
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = self.dialect.connect(readonly=True)
            self._local.conn = conn
        return conn

    def drop_schema(self):
        """Destroy an isolated PostgreSQL schema. No-op on SQLite."""
        if hasattr(self.dialect, 'drop_schema'):
            with self._write_lock:
                self.dialect.drop_schema(self._write_conn)

    def close(self):
        with self._write_lock:
            self._write_conn.close()
        conn = getattr(self._local, 'conn', None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- statement execution -------------------------------------------------
    #
    # Every statement goes through here so the dialect can rewrite placeholders
    # and type tokens exactly once. psycopg exposes executemany() on cursors
    # only, so both backends are driven through a cursor for symmetry.

    def _exec(self, conn, sql, params=()):
        cur = conn.cursor()
        cur.execute(self.dialect.render(sql), params)
        return cur

    def _execmany(self, conn, sql, rows):
        if not rows:
            return
        cur = conn.cursor()
        cur.executemany(self.dialect.render(sql), rows)

    @staticmethod
    def _begin(conn):
        conn.cursor().execute('BEGIN')

    @staticmethod
    def _commit(conn):
        conn.cursor().execute('COMMIT')

    @staticmethod
    def _rollback(conn):
        try:
            conn.cursor().execute('ROLLBACK')
        except Exception:
            # SQLite raises when no transaction is open; the batch has already
            # failed and the caller re-raises the original error.
            pass

    # -- schema --------------------------------------------------------------

    def init_schema(self):
        with self._write_lock:
            self.dialect.executescript(self._write_conn, SCHEMA)

    def seed_technique_catalog(self):
        """Load the ATT&CK catalog from mitre.py into the reference table."""
        rows = [(t.id, t.name, t.tactic, t.url, t.rationale)
                for t in mitre.all_techniques()]
        with self._write_lock:
            self._begin(self._write_conn)
            try:
                self._execmany(
                    self._write_conn,
                    """INSERT INTO mitre_techniques
                       (technique_id, name, tactic, url, rationale)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT(technique_id) DO UPDATE SET
                         name=excluded.name, tactic=excluded.tactic,
                         url=excluded.url, rationale=excluded.rationale""",
                    rows)
                self._commit(self._write_conn)
            except Exception:
                self._rollback(self._write_conn)
                raise

    def table_names(self):
        return [r['name'] for r in self._rows(self.dialect.table_names_sql())]

    def index_names(self):
        return [(r['table_name'], r['index_name'])
                for r in self._rows(self.dialect.index_names_sql())]

    # ── writes ───────────────────────────────────────────────────────────────

    def persist_batch(self, packets, findings):
        """Write one batch atomically. Returns (packet_rows, alert_rows).

        `packets` are parsed packet dicts; `findings` are Finding objects. The
        whole batch shares one transaction, which is what makes sustained
        throughput possible — a transaction per packet would be ~100x slower.
        """
        t0 = time.perf_counter()
        alert_ids = []
        malicious_ips = {f.src_ip for f in findings if f.src_ip}

        with self._write_lock:
            conn = self._write_conn
            try:
                self._begin(conn)
                if packets:
                    self._write_packets(conn, packets, malicious_ips)
                    self._write_connections(conn, packets)
                    self._write_hosts(conn, packets)
                    self._write_protocol_stats(conn, packets, findings)
                alert_ids = self._write_alerts(conn, findings)
                self._commit(conn)
            except Exception:
                self._rollback(conn)
                raise
        return len(packets), len(alert_ids), (time.perf_counter() - t0) * 1000

    @staticmethod
    def _l7_summary(pkt):
        """Compact JSON of the decoded application-layer fields."""
        interesting = {}
        for key, value in pkt.items():
            if key.count('_') and any(key.startswith(p + '_') for p in (
                    'dns', 'http', 'tls', 'ssh', 'ftp', 'smtp', 'pop3',
                    'imap', 'snmp', 'ntp', 'smb', 'rdp', 'dhcp', 'quic',
                    'arp', 'telnet', 'icmp')):
                if isinstance(value, (str, int, float, bool)) or value is None:
                    interesting[key] = value
        return json.dumps(interesting, separators=(',', ':')) if interesting \
            else None

    def _write_packets(self, conn, packets, malicious_ips):
        rows = [
            (p['ts'], p.get('src_ip') or '', p.get('dst_ip') or '',
             p.get('src_port'), p.get('dst_port'), p.get('protocol', 'UNKNOWN'),
             p.get('frame_len', 0), p.get('payload_len', 0),
             p.get('flags', ''), p.get('entropy', 0.0),
             1 if p.get('src_ip') in malicious_ips else 0,
             self._l7_summary(p))
            for p in packets
        ]
        self._execmany(
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
        self._execmany(
            conn,
            """INSERT INTO connections
               (src_ip,dst_ip,src_port,dst_port,protocol,first_seen,last_seen,
                packets,bytes,flags_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(src_ip,dst_ip,src_port,dst_port,protocol) DO UPDATE SET
                 last_seen = {GREATEST}(connections.last_seen,
                                        excluded.last_seen),
                 first_seen= {LEAST}(connections.first_seen,
                                     excluded.first_seen),
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
            rows.append((ip, h[0], h[1], 1 if country == 'PRIVATE' else 0,
                         country, lat, lon, h[2], h[3], h[4], h[5]))
        self._execmany(
            conn,
            """INSERT INTO hosts
               (ip,first_seen,last_seen,is_internal,country,latitude,longitude,
                packets_sent,packets_recv,bytes_sent,bytes_recv)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ip) DO UPDATE SET
                 last_seen   = {GREATEST}(hosts.last_seen,
                                          excluded.last_seen),
                 first_seen  = {LEAST}(hosts.first_seen,
                                       excluded.first_seen),
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
        self._execmany(
            conn,
            """INSERT INTO protocol_stats (bucket,protocol,packets,bytes,alerts)
               VALUES (?,?,?,?,?)
               ON CONFLICT(bucket,protocol) DO UPDATE SET
                 packets = protocol_stats.packets + excluded.packets,
                 bytes   = protocol_stats.bytes + excluded.bytes,
                 alerts  = protocol_stats.alerts + excluded.alerts""", rows)

    def _write_alerts(self, conn, findings):
        alert_ids = []
        for f in findings:
            # RETURNING rather than lastrowid: supported by SQLite 3.35+ and
            # PostgreSQL alike, so the two backends share one statement.
            row = self._exec(
                conn,
                """INSERT INTO alerts
                   (ts,severity,threat_type,detector,src_ip,dst_ip,src_port,
                    dst_port,protocol,confidence,description,evidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id""",
                (f.ts, f.severity, f.threat_type, f.detector, f.src_ip,
                 f.dst_ip, f.src_port, f.dst_port, f.protocol, f.confidence,
                 f.reason, json.dumps(f.evidence, default=str,
                                      separators=(',', ':')))).fetchone()
            alert_id = row['id'] if isinstance(row, dict) else row[0]
            alert_ids.append(alert_id)
            self._execmany(
                conn,
                """{INSERT_IGNORE} alert_techniques
                   (alert_id,technique_id,confidence,ts) VALUES (?,?,?,?)
                   {ON_CONFLICT_NOTHING}""",
                [(alert_id, tid, f.confidence, f.ts) for tid in f.techniques])
            if f.src_ip:
                self._exec(
                    conn,
                    """UPDATE hosts SET alert_count = alert_count + 1,
                       threat_score = {LEAST}(100, threat_score + ?)
                       WHERE ip = ?""",
                    ({'CRITICAL': 10, 'HIGH': 6, 'MEDIUM': 3,
                      'LOW': 1, 'INFO': 0}[f.severity], f.src_ip))
        return alert_ids

    PERF_COLUMNS = ('ts', 'source', 'window_s', 'packets_processed',
                    'packets_per_min', 'alerts_generated', 'parse_errors',
                    'parse_us_avg', 'detect_us_avg', 'db_write_ms',
                    'query_p50_ms', 'query_p95_ms')

    def record_performance(self, metrics):
        """Store one measured throughput/latency window.

        Positional placeholders rather than named ones: sqlite3 and psycopg
        disagree on named-parameter syntax, and the column order is fixed here
        anyway.
        """
        row = {'ts': time.time(), 'source': 'engine', 'window_s': 0,
               'packets_processed': 0, 'packets_per_min': 0,
               'alerts_generated': 0, 'parse_errors': 0, 'parse_us_avg': 0,
               'detect_us_avg': 0, 'db_write_ms': 0, 'query_p50_ms': 0,
               'query_p95_ms': 0}
        row.update(metrics)
        with self._write_lock:
            self._exec(
                self._write_conn,
                """INSERT INTO performance_metrics (%s) VALUES (%s)"""
                % (','.join(self.PERF_COLUMNS),
                   ','.join('?' * len(self.PERF_COLUMNS))),
                tuple(row[c] for c in self.PERF_COLUMNS))

    def record_validation_run(self, run):
        """Persist one PCAP-replay or tuning result. Returns its row id.

        Written by tests/replay.py and tools/noise_experiment.py so the
        measured detection quality lives next to the data it was measured on.
        """
        payload = {
            'ts': time.time(), 'kind': 'replay', 'profile': 'tuned',
            'corpus': 'unknown', 'pcap_count': 0, 'packets': 0,
            'scenarios': 0, 'true_positives': 0, 'false_positives': 0,
            'false_negatives': 0, 'precision_pct': 0.0, 'recall_pct': 0.0,
            'tpr_pct': 0.0, 'alerts_total': 0, 'detail': None,
        }
        payload.update(run)
        if isinstance(payload['detail'], (dict, list)):
            payload['detail'] = json.dumps(payload['detail'], default=str)
        with self._write_lock:
            row = self._exec(
                self._write_conn,
                """INSERT INTO validation_runs
                   (ts,kind,profile,corpus,pcap_count,packets,scenarios,
                    true_positives,false_positives,false_negatives,
                    precision_pct,recall_pct,tpr_pct,alerts_total,detail)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id""",
                tuple(payload[k] for k in (
                    'ts', 'kind', 'profile', 'corpus', 'pcap_count', 'packets',
                    'scenarios', 'true_positives', 'false_positives',
                    'false_negatives', 'precision_pct', 'recall_pct',
                    'tpr_pct', 'alerts_total', 'detail'))).fetchone()
        return row['id'] if isinstance(row, dict) else row[0]

    def get_validation_runs(self, limit=50, kind=None):
        if kind:
            rows = self._rows(
                """SELECT * FROM validation_runs WHERE kind = ?
                   ORDER BY ts DESC LIMIT ?""", (kind, limit))
        else:
            rows = self._rows(
                'SELECT * FROM validation_runs ORDER BY ts DESC LIMIT ?',
                (limit,))
        for r in rows:
            r['detail'] = json.loads(r['detail']) if r['detail'] else {}
        return rows

    def acknowledge_alert(self, alert_id):
        with self._write_lock:
            cur = self._exec(
                self._write_conn,
                'UPDATE alerts SET acknowledged=1, ack_ts=? WHERE id=?',
                (time.time(), alert_id))
            return cur.rowcount

    # ── reads ────────────────────────────────────────────────────────────────

    def _rows(self, sql, params=()):
        return [dict(r) for r in
                self._exec(self.reader(), sql, params).fetchall()]

    def _one(self, sql, params=()):
        row = self._exec(self.reader(), sql, params).fetchone()
        return dict(row) if row else None

    def _scalar(self, sql, params=(), default=0):
        row = self._exec(self.reader(), sql, params).fetchone()
        if not row:
            return default
        value = list(row.values())[0] if isinstance(row, dict) else row[0]
        return default if value is None else value

    def get_overview(self):
        """Live counters for the dashboard's KPI strip.

        `total_packets` is summed from the protocol_stats rollup rather than
        counted from `packets`. That is what the rollup is for: an unbounded
        COUNT(*) over the packet table is a full scan on both backends, and at
        half a million rows it was the single slowest query in the API —
        51 ms on PostgreSQL against a 50 ms budget. The rollup carries one row
        per (minute, protocol) and is asserted to agree with the packet table
        by test_protocol_stats_rollup_matches_packets.
        """
        now = time.time()
        hour, day = now - 3600, now - 86400
        return {
            'total_packets': self._scalar(
                'SELECT SUM(packets) FROM protocol_stats'),
            # Same reasoning as total_packets: an hour of traffic is most of
            # the packet table, so counting it through the index is barely
            # cheaper than scanning. The rollup answers it from ~60 rows.
            'packets_last_hour': self._scalar(
                'SELECT SUM(packets) FROM protocol_stats WHERE bucket > ?',
                (int(hour),)),
            'packets_per_min': round(self._scalar(
                """SELECT AVG(pm) FROM (
                     SELECT SUM(packets) AS pm FROM protocol_stats
                     WHERE bucket > ? GROUP BY bucket)""",
                (int(now - 600),), 0.0), 1),
            'total_alerts': self._scalar('SELECT COUNT(*) FROM alerts'),
            'alerts_24h': self._scalar(
                'SELECT COUNT(*) FROM alerts WHERE ts > ?', (day,)),
            'critical_open': self._scalar(
                "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' "
                'AND acknowledged=0'),
            'unacknowledged': self._scalar(
                'SELECT COUNT(*) FROM alerts WHERE acknowledged=0'),
            'distinct_threat_types': self._scalar(
                'SELECT COUNT(DISTINCT threat_type) FROM alerts'),
            'techniques_observed': self._scalar(
                'SELECT COUNT(DISTINCT technique_id) FROM alert_techniques'),
            'hosts_tracked': self._scalar('SELECT COUNT(*) FROM hosts'),
            'active_flows': self._scalar(
                'SELECT COUNT(*) FROM connections WHERE last_seen > ?',
                (now - 300,)),
            'mean_confidence': round(self._scalar(
                'SELECT AVG(confidence) FROM alerts WHERE ts > ?', (day,),
                0.0), 3),
        }

    def get_throughput(self, minutes=60):
        cutoff = int(time.time() - minutes * 60)
        return self._rows(
            """SELECT bucket, SUM(packets) AS packets, SUM(bytes) AS bytes,
                      SUM(alerts) AS alerts
               FROM protocol_stats WHERE bucket > ?
               GROUP BY bucket ORDER BY bucket""", (cutoff,))

    def get_protocol_distribution(self, minutes=1440):
        cutoff = int(time.time() - minutes * 60)
        return self._rows(
            """SELECT protocol, SUM(packets) AS packets, SUM(bytes) AS bytes,
                      SUM(alerts) AS alerts
               FROM protocol_stats WHERE bucket > ?
               GROUP BY protocol ORDER BY packets DESC""", (cutoff,))

    def get_severity_breakdown(self, hours=24):
        cutoff = time.time() - hours * 3600
        return self._rows(
            """SELECT severity, COUNT(*) AS count, AVG(confidence) AS avg_conf
               FROM alerts WHERE ts > ? GROUP BY severity""", (cutoff,))

    def get_alert_timeline(self, hours=24, bucket_s=3600):
        cutoff = time.time() - hours * 3600
        return self._rows(
            """SELECT CAST(FLOOR(ts/?) AS {BIGINT})*? AS bucket, severity,
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
            params.append(1 if acknowledged else 0)
        if since is not None:
            where.append('ts > ?')
            params.append(since)
        clause = ('WHERE ' + ' AND '.join(where)) if where else ''
        total = self._scalar('SELECT COUNT(*) FROM alerts ' + clause,
                             tuple(params))
        rows = self._rows(
            'SELECT * FROM alerts %s ORDER BY ts DESC LIMIT ? OFFSET ?'
            % clause, tuple(params) + (limit, offset))
        for r in rows:
            r['evidence'] = json.loads(r['evidence']) if r['evidence'] else {}
        return {'total': total, 'count': len(rows), 'limit': limit,
                'offset': offset, 'alerts': rows}

    def get_alert(self, alert_id):
        alert = self._one('SELECT * FROM alerts WHERE id = ?', (alert_id,))
        if not alert:
            return None
        alert['evidence'] = json.loads(alert['evidence']) \
            if alert['evidence'] else {}
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
        return alert

    def get_alert_stats_by_type(self, hours=24):
        cutoff = time.time() - hours * 3600
        return self._rows(
            """SELECT threat_type, MIN(detector) AS detector,
                      COUNT(*) AS count,
                      AVG(confidence) AS avg_conf,
                      SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END)
                        AS critical,
                      SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) AS high,
                      MAX(ts) AS last_seen
               FROM alerts WHERE ts > ?
               GROUP BY threat_type ORDER BY count DESC""", (cutoff,))

    def get_threat_summary(self, hours=24, limit=50):
        """Aggregated per (source, threat type) — the 'active threats' view.

        Derived rather than stored; see the module docstring.
        """
        cutoff = time.time() - hours * 3600
        return self._rows(
            """SELECT src_ip, threat_type, COUNT(*) AS alert_count,
                      MIN(ts) AS first_seen, MAX(ts) AS last_seen,
                      MAX(confidence) AS max_confidence,
                      SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END)
                        AS open_alerts,
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
               GROUP BY t.technique_id
               ORDER BY alert_count DESC, t.technique_id""" % join,
            tuple(params))

    def get_mitre_technique(self, technique_id, limit=25):
        tech = self._one(
            'SELECT * FROM mitre_techniques WHERE technique_id = ?',
            (technique_id,))
        if not tech:
            return None
        tech['alert_count'] = self._scalar(
            'SELECT COUNT(*) FROM alert_techniques WHERE technique_id = ?',
            (technique_id,))
        tech['detectors'] = self._rows(
            """SELECT a.detector, MIN(a.threat_type) AS threat_type,
                      COUNT(*) AS count
               FROM alert_techniques at JOIN alerts a ON a.id = at.alert_id
               WHERE at.technique_id = ?
               GROUP BY a.detector ORDER BY count DESC""", (technique_id,))
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
               GROUP BY t.technique_id ORDER BY t.tactic, t.technique_id""")
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
            """SELECT protocol, COUNT(*) AS packets, SUM(frame_len) AS bytes
               FROM packets WHERE src_ip = ?
               GROUP BY protocol ORDER BY packets DESC LIMIT 10""", (ip,))
        host['recent_alerts'] = self._rows(
            """SELECT id, ts, severity, threat_type, dst_ip, protocol,
                      confidence, description
               FROM alerts WHERE src_ip = ? ORDER BY ts DESC LIMIT 20""",
            (ip,))
        host['top_peers'] = self._rows(
            """SELECT dst_ip AS peer, SUM(packets) AS packets,
                      SUM(bytes) AS bytes
               FROM connections WHERE src_ip = ?
               GROUP BY dst_ip ORDER BY bytes DESC LIMIT 10""", (ip,))
        return host

    def get_geo_distribution(self):
        return self._rows(
            """SELECT country, COUNT(*) AS hosts,
                      SUM(packets_sent) AS packets, SUM(bytes_sent) AS bytes,
                      SUM(alert_count) AS alerts, AVG(latitude) AS latitude,
                      AVG(longitude) AS longitude
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
            where.append('is_malicious = 1')
        if since is not None:
            where.append('ts > ?')
            params.append(since)
        clause = ('WHERE ' + ' AND '.join(where)) if where else ''
        rows = self._rows(
            'SELECT * FROM packets %s ORDER BY ts DESC LIMIT ?' % clause,
            tuple(params) + (limit,))
        for r in rows:
            r['l7'] = json.loads(r['l7_summary']) if r['l7_summary'] else {}
            r.pop('l7_summary', None)
        return rows

    def get_performance(self, limit=120, source=None):
        if source:
            return self._rows(
                """SELECT * FROM performance_metrics WHERE source = ?
                   ORDER BY ts DESC LIMIT ?""", (source, limit))
        return self._rows(
            'SELECT * FROM performance_metrics ORDER BY ts DESC LIMIT ?',
            (limit,))

    def health(self):
        t0 = time.perf_counter()
        counts = {}
        for table in TABLES:
            counts[table] = self._scalar('SELECT COUNT(*) FROM "%s"' % table)
        latency_ms = (time.perf_counter() - t0) * 1000
        return {
            'status': 'ok',
            'backend': self.backend,
            'db_path': self.db_path,
            'db_size_bytes': self.size_bytes(),
            'tables': counts,
            'table_count': len(counts),
            'index_count': len(self.index_names()),
            'journal_mode': self.dialect.journal_mode(self),
            'count_query_ms': round(latency_ms, 3),
        }

    def size_bytes(self):
        """On-disk size of the store, or 0 when it cannot be determined."""
        if self.backend == db_dialects.POSTGRESQL:
            try:
                return int(self._scalar(
                    'SELECT pg_database_size(current_database())'))
            except Exception:
                return 0
        try:
            return os.path.getsize(self.db_path)
        except OSError:
            return 0

    def explain(self, sql, params=()):
        """Query-plan rows — used by tests to prove index usage.

        The plan format is backend-specific, so callers that only need a
        yes/no answer should use `uses_index()` rather than parsing this.
        """
        return self._rows(self.dialect.explain_sql(sql), params)

    def plan_text(self, sql, params=()):
        return self.dialect.plan_text(self.explain(sql, params))

    def uses_index(self, sql, params=(), index_name=None):
        """True when the backend's planner chooses an index for this query."""
        return self.dialect.plan_uses_index(
            self.plan_text(sql, params), index_name)

    def scans_table(self, sql, params=(), table=None):
        """True when the plan contains a full scan of `table`."""
        return self.dialect.plan_scans_table(self.plan_text(sql, params),
                                             table)
