-- NetWatch SOC — initial PostgreSQL schema.
--
-- Ported from the original SQLite schema with every table and column name
-- preserved, so existing queries, API responses and the dashboard are
-- unchanged. What differs is type fidelity, and each difference is deliberate:
--
--   BIGINT for ids and counters   PostgreSQL INTEGER is 32-bit where SQLite's
--                                 is 64-bit. bytes_sent/bytes_recv/bytes are
--                                 cumulative and would overflow past 2.1 GB.
--   BOOLEAN for flags             is_malicious / is_internal / acknowledged
--                                 were 0/1 integers under SQLite's dynamic
--                                 typing.
--   JSONB for JSON                evidence and l7_summary were TEXT holding
--                                 json.dumps() output. JSONB is queryable and
--                                 indexable.
--   DOUBLE PRECISION for ts       Epoch seconds, which is what the whole
--                                 pipeline computes with and is UTC by
--                                 definition. A generated ts_utc TIMESTAMPTZ
--                                 column is added to the analyst-facing
--                                 tables so SQL and BI clients get a real
--                                 timestamp without the ingest path paying
--                                 for a conversion on every packet.

-- 1. Raw packet log -----------------------------------------------------
CREATE TABLE packets (
    id           BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts           DOUBLE PRECISION NOT NULL,
    src_ip       TEXT    NOT NULL,
    dst_ip       TEXT    NOT NULL,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT    NOT NULL,
    frame_len    INTEGER NOT NULL,
    payload_len  INTEGER NOT NULL DEFAULT 0,
    flags        TEXT,
    entropy      DOUBLE PRECISION NOT NULL DEFAULT 0,
    is_malicious BOOLEAN NOT NULL DEFAULT FALSE,
    l7_summary   JSONB
);
CREATE INDEX idx_packets_ts        ON packets (ts DESC);
CREATE INDEX idx_packets_src_ts    ON packets (src_ip, ts DESC);
CREATE INDEX idx_packets_dst_ts    ON packets (dst_ip, ts DESC);
CREATE INDEX idx_packets_proto_ts  ON packets (protocol, ts DESC);
-- Only malicious packets are ever filtered on, and they are a tiny minority,
-- so a partial index costs a fraction of the full one to maintain on a write
-- path that takes every packet in the capture.
CREATE INDEX idx_packets_malicious ON packets (is_malicious, ts DESC)
    WHERE is_malicious;
-- Covers the per-host protocol breakdown on the host detail page. Without it
-- that GROUP BY sorts every packet the host sent. frame_len is only summed,
-- never searched, so it rides along in INCLUDE rather than in the key.
CREATE INDEX idx_packets_src_proto ON packets (src_ip, protocol)
    INCLUDE (frame_len);

-- 2. Flow / connection tracking -----------------------------------------
CREATE TABLE connections (
    id          BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    src_port    INTEGER NOT NULL DEFAULT 0,
    dst_port    INTEGER NOT NULL DEFAULT 0,
    protocol    TEXT    NOT NULL,
    first_seen  DOUBLE PRECISION NOT NULL,
    last_seen   DOUBLE PRECISION NOT NULL,
    packets     BIGINT  NOT NULL DEFAULT 0,
    bytes       BIGINT  NOT NULL DEFAULT 0,
    flags_seen  TEXT    NOT NULL DEFAULT '',
    state       TEXT    NOT NULL DEFAULT 'ACTIVE',
    UNIQUE (src_ip, dst_ip, src_port, dst_port, protocol)
);
CREATE INDEX idx_conn_last    ON connections (last_seen DESC);
CREATE INDEX idx_conn_src     ON connections (src_ip, last_seen DESC);
CREATE INDEX idx_conn_bytes   ON connections (bytes DESC);
CREATE INDEX idx_conn_src_dst ON connections (src_ip, dst_ip)
    INCLUDE (packets, bytes);

-- 3. Host inventory ------------------------------------------------------
CREATE TABLE hosts (
    ip            TEXT    PRIMARY KEY,
    first_seen    DOUBLE PRECISION NOT NULL,
    last_seen     DOUBLE PRECISION NOT NULL,
    is_internal   BOOLEAN NOT NULL DEFAULT FALSE,
    country       TEXT    NOT NULL DEFAULT 'UNKNOWN',
    latitude      DOUBLE PRECISION,
    longitude     DOUBLE PRECISION,
    packets_sent  BIGINT  NOT NULL DEFAULT 0,
    packets_recv  BIGINT  NOT NULL DEFAULT 0,
    bytes_sent    BIGINT  NOT NULL DEFAULT 0,
    bytes_recv    BIGINT  NOT NULL DEFAULT 0,
    alert_count   BIGINT  NOT NULL DEFAULT 0,
    threat_score  DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX idx_hosts_country ON hosts (country);
CREATE INDEX idx_hosts_sent    ON hosts (packets_sent DESC);
CREATE INDEX idx_hosts_threat  ON hosts (threat_score DESC);

-- 4. Alerts --------------------------------------------------------------
CREATE TABLE alerts (
    id           BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts           DOUBLE PRECISION NOT NULL,
    severity     TEXT    NOT NULL
                 CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    threat_type  TEXT    NOT NULL,
    detector     TEXT    NOT NULL,
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT,
    confidence   DOUBLE PRECISION NOT NULL,
    description  TEXT    NOT NULL,
    evidence     JSONB,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    ack_ts       DOUBLE PRECISION,
    -- Epoch seconds are what the pipeline and the API speak; this is the same
    -- instant as a real timestamp, for ad-hoc SQL, reporting and BI clients.
    ts_utc       TIMESTAMPTZ GENERATED ALWAYS AS (to_timestamp(ts)) STORED
);
CREATE INDEX idx_alerts_ts      ON alerts (ts DESC);
CREATE INDEX idx_alerts_sev_ts  ON alerts (severity, ts DESC);
CREATE INDEX idx_alerts_type_ts ON alerts (threat_type, ts DESC);
CREATE INDEX idx_alerts_src_ts  ON alerts (src_ip, ts DESC);
-- The dashboard only ever asks for the open queue, never the acknowledged one,
-- so the index covers the rows that are actually selected.
CREATE INDEX idx_alerts_ack     ON alerts (acknowledged, ts DESC)
    WHERE NOT acknowledged;
-- No shipped query reaches inside evidence; this is for analyst SQL such as
-- `WHERE evidence @> '{"dst_port": 445}'`, which would otherwise scan. alerts
-- is the low-volume table, so the write cost is negligible — unlike on
-- packets.l7_summary, which is deliberately left unindexed for that reason.
CREATE INDEX idx_alerts_evidence ON alerts USING GIN (evidence jsonb_path_ops);

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
    -- Retention deletes alerts; their technique links must go with them.
    alert_id     BIGINT NOT NULL
                 REFERENCES alerts (id) ON DELETE CASCADE,
    -- The catalog is reference data seeded from mitre.py and never pruned.
    -- RESTRICT makes removing a technique that alerts still cite an error
    -- rather than a silent orphan or a silent cascade of real findings.
    technique_id TEXT   NOT NULL
                 REFERENCES mitre_techniques (technique_id) ON DELETE RESTRICT,
    confidence   DOUBLE PRECISION NOT NULL,
    ts           DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (alert_id, technique_id)
);
CREATE INDEX idx_at_technique ON alert_techniques (technique_id, ts DESC);
CREATE INDEX idx_at_ts        ON alert_techniques (ts DESC);

-- 7. Per-minute protocol rollup -----------------------------------------
CREATE TABLE protocol_stats (
    bucket   BIGINT NOT NULL,          -- unix time floored to the minute
    protocol TEXT   NOT NULL,
    packets  BIGINT NOT NULL DEFAULT 0,
    bytes    BIGINT NOT NULL DEFAULT 0,
    alerts   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, protocol)
);
CREATE INDEX idx_pstat_bucket ON protocol_stats (bucket DESC);

-- 8. Measured performance ------------------------------------------------
CREATE TABLE performance_metrics (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts                DOUBLE PRECISION NOT NULL,
    source            TEXT   NOT NULL DEFAULT 'engine',
    window_s          DOUBLE PRECISION NOT NULL,
    packets_processed BIGINT NOT NULL,
    packets_per_min   DOUBLE PRECISION NOT NULL,
    alerts_generated  BIGINT NOT NULL DEFAULT 0,
    parse_errors      BIGINT NOT NULL DEFAULT 0,
    parse_us_avg      DOUBLE PRECISION NOT NULL DEFAULT 0,
    detect_us_avg     DOUBLE PRECISION NOT NULL DEFAULT 0,
    db_write_ms       DOUBLE PRECISION NOT NULL DEFAULT 0,
    query_p50_ms      DOUBLE PRECISION NOT NULL DEFAULT 0,
    query_p95_ms      DOUBLE PRECISION NOT NULL DEFAULT 0,
    ts_utc            TIMESTAMPTZ GENERATED ALWAYS AS (to_timestamp(ts)) STORED
);
CREATE INDEX idx_perf_ts     ON performance_metrics (ts DESC);
CREATE INDEX idx_perf_source ON performance_metrics (source, ts DESC);
