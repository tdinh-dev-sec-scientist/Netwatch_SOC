# Database

The PostgreSQL schema, its type choices, migrations and the SQLite development fallback. Back to the [README](../Readme.MD).

## Database — 8 tables

PostgreSQL 16. Every table is written by the live pipeline; this is asserted by
`test_all_eight_tables_are_actually_populated`.

| # | Table | Purpose | Key indexes |
|---|---|---|---|
| 1 | `packets` | Every processed packet with decoded L7 summary (`JSONB`) | `ts`, `(src_ip,ts)`, `(dst_ip,ts)`, `(protocol,ts)`, `(is_malicious,ts)` partial, `(src_ip,protocol) INCLUDE (frame_len)` |
| 2 | `connections` | Flow records keyed on the 5-tuple, upserted per batch | `last_seen`, `(src_ip,last_seen)`, `bytes`, `(src_ip,dst_ip) INCLUDE (packets,bytes)` |
| 3 | `hosts` | Host inventory, geo enrichment, rollup counters, threat score | `country`, `packets_sent`, `threat_score` |
| 4 | `alerts` | Detector findings with `JSONB` evidence | `ts`, `(severity,ts)`, `(threat_type,ts)`, `(src_ip,ts)`, `(acknowledged,ts)` partial, GIN on `evidence` |
| 5 | `mitre_techniques` | ATT&CK catalog (reference table) | `tactic` |
| 6 | `alert_techniques` | Many-to-many alert↔technique with confidence | `(technique_id,ts)`, `ts` |
| 7 | `protocol_stats` | Per-minute protocol rollup backing the charts | `bucket` |
| 8 | `performance_metrics` | Measured throughput and query latency | `ts`, `(source,ts)` |

**25 indexes.** PostgreSQL is unconditionally write-ahead logged; foreign keys
are enforced without being asked. Reads come from a pooled connection per
caller, so the Flask worker's threads query in parallel; writes go through one
connection, because the pipeline writes one transaction per batch and — by
design, enforced by `gunicorn.conf.py` — there is exactly one engine process.

### Type choices

| Column kind | Type | Why |
|---|---|---|
| Surrogate keys | `BIGINT GENERATED ALWAYS AS IDENTITY` | `packets` reaches 2³¹ rows at a few thousand packets a second |
| Byte and packet counters | `BIGINT` | **SQLite's `INTEGER` is 64-bit; PostgreSQL's is 32-bit.** `hosts.bytes_sent` and `connections.bytes` are cumulative and would have overflowed at 2.1 GB |
| `is_malicious`, `is_internal`, `acknowledged` | `BOOLEAN` | Were 0/1 integers under SQLite's dynamic typing |
| `evidence`, `l7_summary` | `JSONB` | Were `TEXT` holding `json.dumps()` output. Queryable and indexable, and the driver parses them for free |
| Timestamps | `DOUBLE PRECISION` epoch seconds, plus a generated `ts_utc TIMESTAMPTZ` | See below |
| Severity | `TEXT` + `CHECK` | Five known values; an enum type would need a migration to extend |

**On timestamps.** Every detector's sliding-window arithmetic, every API
`?since=` parameter and every dashboard chart computes on epoch seconds, and
epoch seconds are UTC by definition — there is no timezone to get wrong, which
is the usual reason to reach for `TIMESTAMPTZ`. So they stay `DOUBLE PRECISION`,
and `alerts` and `performance_metrics` carry a generated
`ts_utc TIMESTAMPTZ GENERATED ALWAYS AS (to_timestamp(ts)) STORED` alongside, so
ad-hoc SQL and reporting tools get a real timestamp type without the ingest path
paying a conversion on every packet. `test_timestamps_are_available_as_timestamptz`
asserts the two agree. On the high-volume tables, `to_timestamp(ts)` in a query
is enough.

### Design notes

- **There is no `threats` table.** A "threat" is an aggregation over alerts
  grouped by `(src_ip, threat_type)`; `get_threat_summary()` derives it with an
  indexed query. Materialising it would duplicate data `alerts` already holds.
  The previous schema had this table and never wrote a single row to it.
- **`protocol_stats` is a genuine rollup, not a convenience copy.** It is what
  keeps the throughput and protocol charts fast as `packets` grows — those
  queries never scan the packet table. `test_protocol_stats_rollup_matches_packets`
  asserts the rollup agrees with the raw rows.
- **Batched writes.** One transaction per batch rather than per packet; this is
  the single largest throughput factor.
- **Partial indexes where the query only wants the minority.** The dashboard
  asks for open alerts and malicious packets, never their complements, so
  `idx_alerts_ack` and `idx_packets_malicious` index only those rows and stay
  small on a write path that sees every packet.
- **The GIN index on `alerts.evidence`** is for analyst SQL such as
  `WHERE evidence @> '{"dst_port": 445}'`; no shipped query uses it. There is
  deliberately none on `packets.l7_summary` — that table takes every packet, and
  a GIN index on it would cost far more in write throughput than ad-hoc queries
  are worth.
- **Foreign keys say what happens on delete.** `alert_techniques.alert_id`
  cascades from `alerts`, so retention takes technique links with it;
  `technique_id` is `RESTRICT`, so removing a technique the alerts still cite is
  an error rather than a silent orphan or a silent cascade of real findings.
- **Index usage is tested, not assumed** — `test_hot_queries_use_their_index`
  runs `EXPLAIN` over the hot queries and fails on a table scan. It uses a
  bulk-loaded 40k-packet, 12k-alert dataset rather than the pipeline fixture:
  PostgreSQL's planner is cost-based, and on a few thousand rows a sequential
  scan genuinely is cheaper, so a smaller dataset would only prove the planner
  had too little information to decide.

### Migrations

The schema lives in numbered SQL files, not in application code:

```
migrations/postgresql/0001_initial_schema.sql
migrations/sqlite/0001_initial_schema.sql
```

```bash
python migrate.py status          # what is applied and what is pending
python migrate.py up              # apply everything pending
python migrate.py up --backend sqlite
```

`DatabaseManager` applies pending migrations on startup, which keeps local
development and the test suite frictionless. Set `NETWATCH_AUTO_MIGRATE=0` where
migrations should be an explicit release step — in particular with more than one
instance, or concurrent boots race each other.

**To change the schema:**

1. Add `migrations/postgresql/000N_what_it_does.sql`, and the matching
   `migrations/sqlite/000N_*.sql`. Both must exist with the same version number
   — `test_every_migration_exists_for_both_backends` fails otherwise. Where a
   change genuinely cannot be expressed in SQLite, write the file anyway and let
   it document why it is a no-op there.
2. Update the queries in `DB_Manager.py`, in the shared dialect documented at
   the top of `db_backends.py`.
3. Run `pytest` against PostgreSQL and again with `DB_BACKEND=sqlite`.

**Never edit an applied migration.** Each file's checksum is recorded, and a
later run reports any that has changed rather than silently diverging from the
database it created. There are no down-migrations: reversing a schema change on
a live database is a decision to make deliberately, as a new forward migration,
not a script to run under pressure.

### SQLite fallback (development only)

`DB_BACKEND=sqlite` runs everything against a local file with no server:

```bash
DB_BACKEND=sqlite python App.py
DB_BACKEND=sqlite pytest
```

It exists for fast local work and for `docker build`, which has no database to
reach. **It is not supported for production**, and the differences are real:

- **No `JSONB`.** `evidence` and `l7_summary` are `TEXT`, so they cannot be
  queried or indexed by key, and there is no counterpart to the GIN index —
  hence 24 indexes there against PostgreSQL's 25.
- **No type enforcement.** SQLite types are affinities, so a wrong value lands
  in a column silently where PostgreSQL would reject it. This is the single
  best reason the test suite defaults to PostgreSQL.
- **32-bit vs 64-bit is the other way round.** SQLite's `INTEGER` holds 64 bits,
  so an overflow that PostgreSQL forced into the open was invisible here.
- **One writer at a time**, with the whole database locked behind it.
- **The planner differs.** It is far more index-eager, and picks different
  indexes for the same query; the plan tests accommodate both.

Tests that assert PostgreSQL-specific behaviour skip themselves under this
backend, so a green SQLite run is a weaker signal than a green PostgreSQL one.
CI runs both.

### Migrating an existing SQLite database

All of this project's data is synthetic — `PacketSimulator` generates it, the
demo starts empty on every cold start — so **there is nothing in the repository
that needs migrating**, and most people can skip this. For an instance that has
been running long enough for its `netwatch.db` to be worth keeping:

```bash
python migrate_sqlite_to_postgres.py --sqlite ./netwatch.db --dry-run
python migrate_sqlite_to_postgres.py --sqlite ./netwatch.db
```

It reads in batches, converts 0/1 to `BOOLEAN` and JSON text to `jsonb`, inserts
with `ON CONFLICT DO NOTHING` so a re-run copies only what is missing, verifies
every table's row count against the source, and advances the identity sequences
past the copied ids so later writes cannot collide. The SQLite file is opened
read-only and is never modified, so it stays a fallback. Migrate into an empty
database: rows keep their original ids, so a destination already holding
different rows at those ids reports the shortfall rather than merging two
histories.
