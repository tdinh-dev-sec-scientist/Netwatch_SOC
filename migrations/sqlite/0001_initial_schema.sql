-- NetWatch SOC — initial SQLite schema (development fallback only).
--
-- PostgreSQL is the production database; see migrations/postgresql/. This file
-- exists so `DB_BACKEND=sqlite` gives a zero-dependency local database with
-- the same tables, columns and index names, and it is kept structurally in
-- step with the PostgreSQL migration of the same number.
--
-- It is NOT equivalent, and cannot be:
--   * SQLite has no JSONB. evidence and l7_summary are TEXT holding
--     json.dumps() output, so they cannot be queried or indexed by key —
--     hence no counterpart to idx_alerts_evidence, and one fewer index.
--   * SQLite has no INCLUDE clause, so the two covering indexes carry their
--     payload columns in the key instead.
--   * SQLite types are affinities, not constraints: BOOLEAN and the integer
--     widths below are documentation, not enforcement. A wrong type reaches
--     these tables silently where PostgreSQL would reject it.

-- 1. Raw packet log -----------------------------------------------------
CREATE TABLE packets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL    NOT NULL,
    src_ip       TEXT    NOT NULL,
    dst_ip       TEXT    NOT NULL,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT    NOT NULL,
    frame_len    INTEGER NOT NULL,
    payload_len  INTEGER NOT NULL DEFAULT 0,
    flags        TEXT,
    entropy      REAL    NOT NULL DEFAULT 0,
    is_malicious BOOLEAN NOT NULL DEFAULT FALSE,
    l7_summary   TEXT
);
CREATE INDEX idx_packets_ts        ON packets (ts DESC);
CREATE INDEX idx_packets_src_ts    ON packets (src_ip, ts DESC);
CREATE INDEX idx_packets_dst_ts    ON packets (dst_ip, ts DESC);
CREATE INDEX idx_packets_proto_ts  ON packets (protocol, ts DESC);
CREATE INDEX idx_packets_malicious ON packets (is_malicious, ts DESC)
    WHERE is_malicious;
CREATE INDEX idx_packets_src_proto ON packets (src_ip, protocol, frame_len);

-- 2. Flow / connection tracking -----------------------------------------
CREATE TABLE connections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    src_port    INTEGER NOT NULL DEFAULT 0,
    dst_port    INTEGER NOT NULL DEFAULT 0,
    protocol    TEXT    NOT NULL,
    first_seen  REAL    NOT NULL,
    last_seen   REAL    NOT NULL,
    packets     INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    flags_seen  TEXT    NOT NULL DEFAULT '',
    state       TEXT    NOT NULL DEFAULT 'ACTIVE',
    UNIQUE (src_ip, dst_ip, src_port, dst_port, protocol)
);
CREATE INDEX idx_conn_last    ON connections (last_seen DESC);
CREATE INDEX idx_conn_src     ON connections (src_ip, last_seen DESC);
CREATE INDEX idx_conn_bytes   ON connections (bytes DESC);
CREATE INDEX idx_conn_src_dst ON connections (src_ip, dst_ip, packets, bytes);

-- 3. Host inventory ------------------------------------------------------
CREATE TABLE hosts (
    ip            TEXT    PRIMARY KEY,
    first_seen    REAL    NOT NULL,
    last_seen     REAL    NOT NULL,
    is_internal   BOOLEAN NOT NULL DEFAULT FALSE,
    country       TEXT    NOT NULL DEFAULT 'UNKNOWN',
    latitude      REAL,
    longitude     REAL,
    packets_sent  INTEGER NOT NULL DEFAULT 0,
    packets_recv  INTEGER NOT NULL DEFAULT 0,
    bytes_sent    INTEGER NOT NULL DEFAULT 0,
    bytes_recv    INTEGER NOT NULL DEFAULT 0,
    alert_count   INTEGER NOT NULL DEFAULT 0,
    threat_score  REAL    NOT NULL DEFAULT 0
);
CREATE INDEX idx_hosts_country ON hosts (country);
CREATE INDEX idx_hosts_sent    ON hosts (packets_sent DESC);
CREATE INDEX idx_hosts_threat  ON hosts (threat_score DESC);

-- 4. Alerts --------------------------------------------------------------
CREATE TABLE alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL    NOT NULL,
    severity     TEXT    NOT NULL
                 CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    threat_type  TEXT    NOT NULL,
    detector     TEXT    NOT NULL,
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT,
    confidence   REAL    NOT NULL,
    description  TEXT    NOT NULL,
    evidence     TEXT,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    ack_ts       REAL,
    ts_utc       TEXT GENERATED ALWAYS AS (datetime(ts, 'unixepoch')) VIRTUAL
);
CREATE INDEX idx_alerts_ts      ON alerts (ts DESC);
CREATE INDEX idx_alerts_sev_ts  ON alerts (severity, ts DESC);
CREATE INDEX idx_alerts_type_ts ON alerts (threat_type, ts DESC);
CREATE INDEX idx_alerts_src_ts  ON alerts (src_ip, ts DESC);
CREATE INDEX idx_alerts_ack     ON alerts (acknowledged, ts DESC)
    WHERE NOT acknowledged;

-- 5. ATT&CK catalog ------------------------------------------------------
CREATE TABLE mitre_techniques (
    technique_id TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    tactic       TEXT NOT NULL,
    url          TEXT,
    rationale    TEXT
);
CREATE INDEX idx_mitre_tactic ON mitre_techniques (tactic);

-- 6. Alert <-> technique mapping ----------------------------------------
CREATE TABLE alert_techniques (
    alert_id     INTEGER NOT NULL
                 REFERENCES alerts (id) ON DELETE CASCADE,
    technique_id TEXT    NOT NULL
                 REFERENCES mitre_techniques (technique_id) ON DELETE RESTRICT,
    confidence   REAL    NOT NULL,
    ts           REAL    NOT NULL,
    PRIMARY KEY (alert_id, technique_id)
);
CREATE INDEX idx_at_technique ON alert_techniques (technique_id, ts DESC);
CREATE INDEX idx_at_ts        ON alert_techniques (ts DESC);

-- 7. Per-minute protocol rollup -----------------------------------------
CREATE TABLE protocol_stats (
    bucket   INTEGER NOT NULL,          -- unix time floored to the minute
    protocol TEXT    NOT NULL,
    packets  INTEGER NOT NULL DEFAULT 0,
    bytes    INTEGER NOT NULL DEFAULT 0,
    alerts   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, protocol)
);
CREATE INDEX idx_pstat_bucket ON protocol_stats (bucket DESC);

-- 8. Measured performance ------------------------------------------------
CREATE TABLE performance_metrics (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                REAL    NOT NULL,
    source            TEXT    NOT NULL DEFAULT 'engine',
    window_s          REAL    NOT NULL,
    packets_processed INTEGER NOT NULL,
    packets_per_min   REAL    NOT NULL,
    alerts_generated  INTEGER NOT NULL DEFAULT 0,
    parse_errors      INTEGER NOT NULL DEFAULT 0,
    parse_us_avg      REAL    NOT NULL DEFAULT 0,
    detect_us_avg     REAL    NOT NULL DEFAULT 0,
    db_write_ms       REAL    NOT NULL DEFAULT 0,
    query_p50_ms      REAL    NOT NULL DEFAULT 0,
    query_p95_ms      REAL    NOT NULL DEFAULT 0,
    ts_utc            TEXT GENERATED ALWAYS AS (datetime(ts, 'unixepoch')) VIRTUAL
);
CREATE INDEX idx_perf_ts     ON performance_metrics (ts DESC);
CREATE INDEX idx_perf_source ON performance_metrics (source, ts DESC);
