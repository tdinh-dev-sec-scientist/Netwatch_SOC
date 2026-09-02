# Measured metrics backing the résumé entry

Every number below was produced on this repository at commit `1708590`, on the
machine described in [Environment](#environment). Nothing here is estimated
unless it is explicitly labelled an estimate. Each metric names the command
that reproduces it.

## Environment

```
Python 3.11.15, Linux x86_64 (container), single-threaded workload
SQLite 3.x, WAL journal mode, 32 MB page cache
```

Absolute throughput is hardware-dependent; the *shape* of every result
(ratios, drop counts, index speed-ups) reproduces anywhere.

---

## 1. Pipeline throughput and drop rate — 10-minute soak

```bash
python benchmarks/soak.py --minutes 10 --db /tmp/soak.db
```

| Metric | Measured |
|---|---|
| Duration | 600.1 s (10.00 min) |
| Frames offered | 1,232,400 |
| Packets parsed | 1,232,400 |
| Rows persisted in `packets` | 1,232,400 |
| **Dropped frames** | **0** (offered − persisted) |
| Parse failures | 0 |
| Mean throughput | **2,053.7 pkt/s** (123,224 pkt/min) |
| Per-minute range | 1,834.2 – 2,630.7 pkt/s (median 2,051.5, σ 231.3) |
| Alerts generated | 22 (from 20 injected attack scenarios) |
| Connections tracked | 55,651 |
| Detector state keys | 297 → 311 over 1.23 M packets (bounded) |
| Peak RSS | 139.1 MB |
| Final DB size | 535.4 MB |

Per-minute trace:

```
   min        packets        pkt/s    parse_err     rss_mb   state_keys
     1         158000       2630.7            0       71.8          297
     2         293600       2257.6            0       83.2          298
     3         420400       2113.3            0       87.2          299
     4         543600       2051.5            0       90.2          302
     5         668400       2077.0            0       93.2          311
     6         786800       1970.8            0       96.0          311
     7         901400       1908.8            0       98.8          312
     8        1011600       1834.2            0      101.5          313
     9        1124000       1871.9            0      104.0          311
```

**Drop accounting is exact**: the script asserts
`frames offered == packets parsed == rows in the packets table`. Any
inequality is a dropped frame. The result was 0.

**Internal consistency**: 2,053.7 pkt/s × 600.1 s = 1,232,400 packets. ✓

**Throughput decays 28.8 %** across the run (2,631 → 1,872 pkt/s) as the
`packets` table grows to 1.23 M rows / 535 MB and its six indexes are
maintained on every batch insert. This is a real, explainable characteristic —
not noise — and is why the résumé cites the mean rather than the peak.

### Fresh-database throughput (for contrast)

```bash
python benchmark.py --iterations 5 --packets 20000
```

3,289 – 4,616 pkt/s (mean 3,860) against a database that never exceeds
~107 k rows. The soak figure is the honest sustained number; this one is the
burst number.

---

## 2. Index impact on query latency

```bash
# 1. build a realistically sized dataset
python benchmark.py --iterations 10 --packets 30000 --db /tmp/scale.db --keep-db
# 2. A/B the 22 API-backing queries with and without the 24 indexes
python benchmarks/index_ab.py --db /tmp/scale.db
```

Dataset: **313,380 rows in `packets`**, 108,671 connections, 424,418 rows
total across the 8 tables.

| Aggregate over all 22 API queries | With 24 indexes | Indexes dropped | Factor |
|---|---|---|---|
| p50 | 0.215 ms | 0.544 ms | 2.5× |
| **p95** | **1.226 ms** | **150.771 ms** | **123×** |
| p99 | 3.254 ms | 653.051 ms | 201× |
| max | 3.582 ms | 671.673 ms | 188× |

Worst-hit individual queries:

| Query | Indexed p95 | Unindexed p95 | Factor |
|---|---|---|---|
| `packets_recent` | 1.23 ms | 657.3 ms | 535× |
| `packets_by_protocol` | 1.03 ms | 152.4 ms | 148× |
| `overview` | 1.22 ms | 98.4 ms | 81× |
| `host_detail` | 3.46 ms | 84.8 ms | 24× |
| `alert_detail` | 0.06 ms | 61.9 ms | 983× |

Re-run at `--repeats 5` reproduced it: p95 0.97 ms → 155.0 ms (160×).

> **Method note.** `DatabaseManager.__init__` calls `init_schema()`, which
> re-applies `CREATE INDEX IF NOT EXISTS`. Indexes must therefore be dropped
> *after* the manager is constructed, and the thread-local reader reset, or the
> A/B silently measures the indexed path twice. A first attempt at this
> measurement made exactly that mistake and reported a 1.0× "speed-up".

**Schema**: 8 tables, **24 explicit indexes** (13 of them composite), plus 5
SQLite auto-indexes from `UNIQUE` constraints.

---

## 3. Test suite and coverage

```bash
pip install pytest pytest-cov
pytest                                    # 249 passed in 148.88s
pytest --cov=. --cov-report=term-missing
coverage report --omit="tests/*"          # application-code coverage
```

| Metric | Measured |
|---|---|
| Tests collected and passed | **249** (0 failed) |
| Runtime | 148.9 s |
| Coverage, application code only | **90 %** (2,773 statements, 291 missed) |
| Coverage, including test modules | 92 % |

Per-file breakdown: `App.py` 93 %, `DB_Manager.py` 94 %, `ProtocolAnalyzer.py`
86 %, `PacketSimulator.py` 89 %, `frames.py` 98 %, `benchmark.py` 96 %,
`detectors/` 82–97 %. `engine.py` (the headless container entrypoint) is at
0 % and is the single largest gap.

Distribution: `test_api.py` 64, `test_detectors.py` 63, `test_protocol_analyzer.py`
44, `test_database.py` 32, `test_dashboard.py` 27, `test_mitre.py` 12,
`test_benchmark.py` 7.

---

## 4. API surface

```bash
grep -c "\.route(" App.py     # 25 = 24 JSON endpoints + 1 dashboard HTML route
```

**24 REST endpoints.** Pagination (`limit`/`offset`, validated and clamped),
filtering (`severity`, `threat_type`, `src_ip`, `acknowledged`, `protocol`,
`order`), and a single error contract: `ApiError` → `{"error": ..., "status":
...}` with 400 for invalid parameters and 404 for unknown resources.
Injection attempts are covered by `test_sql_injection_in_filters_is_parameterised`.

---

## 5. False-positive control

```bash
python benchmarks/fp_check.py
```

**0 false positives across 200,000 benign packets over 8 independent seeds**
(25,000 packets per seed, fresh detector state per seed), 0 parse failures.

Corroborated by the soak run: 22 alerts across 1,232,400 packets, and every
alert type raised corresponds to one of the 20 attack scenarios injected during
the run — no spurious threat types appeared.

> Note: the committed test `test_no_false_positives_on_benign_background`
> exercises **one** seed × 20,000 packets. The 8-seed figure comes from
> `benchmarks/fp_check.py` in this directory, which is why it ships here.

---

## 6. Containerization

`Dockerfile` is a **three-stage build** (`builder` → `test` → `runtime`):
dependencies compiled into a venv in `builder`, the full 249-test suite run
inside `test` (`docker build --target test .` fails the build on regression),
and a `runtime` stage carrying only the venv plus explicitly enumerated source
files — no compilers, no package manager, non-root UID 10001, `VOLUME /data`,
and a `HEALTHCHECK` that verifies the schema (`table_count == 8`), not just the
port. `docker-compose.yml` adds `cap_drop: ALL`, a read-only root filesystem
with `tmpfs` mounts, and restricts `NET_RAW`/`NET_ADMIN` to the capture engine
alone.

**Not measured**: image size and build time. No Docker daemon was available in
this environment. To obtain them:

```bash
docker build -t netwatch-soc:latest .
docker images netwatch-soc:latest --format '{{.Size}}'
docker build --target test .            # test-gated build
```

Do not put an image-size number on a résumé until this has actually been run.

---

## Claims that the codebase does **not** support

These appeared in the target résumé template and were removed rather than
padded. See the Honesty Check section of the hand-off for safer wording.

| Template claim | Reality |
|---|---|
| "Migrated persistence from SQLite to PostgreSQL" | No PostgreSQL anywhere. `grep -rniE "postgres\|psycopg\|sqlalchemy"` returns one commented line in `docker-compose.yml` suggesting Postgres as *future* work. |
| "behind SQLAlchemy" | No ORM. Hand-written parameterised SQL on `sqlite3`. |
| "bounded queues and inter-stage backpressure" | The pipeline is synchronous and in-process: `process()` calls parse → detect → buffer inline. There is a size/time-triggered batch buffer (400 packets / 2 s), not a queue, and nothing exerts backpressure on an upstream producer. Detector *state* is bounded and swept by `expire()`; that is a different property. |
| "14 REST endpoints" | 24. |
| "on GitHub Actions CI" | No `.github/` directory exists. The equivalent gate is the Docker `test` stage. |

---

## Repository documentation inconsistencies noticed

Not changed by this work, but worth a follow-up commit:

- `Readme.MD` says "**22 indexes**" in the Database section and "**24**" in the
  Measured results table. The schema has 24.
- The architecture diagram and Files table say "**21 REST endpoints**"; the API
  section and the results table say 24. The code has 24.
- The README states 0 false positives across "240,000 benign packets, 8 seeds",
  but the committed test covers 20,000 packets on 1 seed. `benchmarks/fp_check.py`
  now substantiates 200,000 across 8 seeds.
