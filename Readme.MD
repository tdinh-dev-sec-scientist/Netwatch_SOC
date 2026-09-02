# NetWatch — packet processing pipeline and REST API

A network security monitoring system built as a real streaming pipeline: raw
Ethernet frames in at one end, deep packet inspection over 21 protocols, 17
threat detectors mapped to MITRE ATT&CK, normalized persistence in PostgreSQL,
and a REST API out the other end.

```
 capture ──► protocol parsing ──► rules evaluation ──► persistence ──► REST API
    │             │                     │                   │              │
 FrameSource  ProtocolAnalyzer     RulesEngine         BatchWriter     Flask + repository
 bytes + ts   21 protocols         17 detectors        COPY into       27 endpoints,
              flat field dict      ATT&CK-mapped       10 tables       pagination, filters
    └── bounded queue ──┴── bounded queue ──┴── bounded queue ──┴── bounded queue ──┘
                        backpressure propagates left
```

Every number in this file was measured on the machine described in
[Measured results](#measured-results) by the scripts in `benchmarks/`, and the
raw JSON each one produced is committed under `benchmarks/results/`. Nothing
here is a target, an estimate, or a round number chosen for effect.

---

## Quick start

```bash
# 1. a PostgreSQL to talk to
docker compose up -d db

# 2. the application
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export NETWATCH_DATABASE_URL=postgresql+psycopg://netwatch:netwatch@localhost:5432/netwatch

alembic upgrade head            # schema
python -m netwatch.cli seed     # reference data (protocols, detectors, ATT&CK)

python -m netwatch.cli engine    # the pipeline, no HTTP
python -m netwatch.cli api       # the REST API + dashboard on :5001
```

Or the whole stack at once:

```bash
docker compose up -d --build    # postgres + migrations + engine + API
curl -s localhost:5001/api/health | jq
```

```bash
pytest                                   # the suite
pytest --cov                             # with coverage
python -m benchmarks.pipeline_benchmark  # end-to-end throughput
python -m benchmarks.soak_test           # sustained load + loss accounting
python -m benchmarks.query_benchmark     # index before/after at scale
```

---

## The pipeline

Five stages, each with its own worker pool, joined by four bounded queues.

| Stage | Does | Workers | Why that number |
|---|---|---|---|
| `capture` | pulls `(ts, frame_bytes)` from a `FrameSource`, groups into chunks | 1 | one source, one reader |
| `parse` | Ethernet → IP → TCP/UDP/ICMP → L7 into a flat field dict | 1 (configurable) | pure-Python CPU; more threads do not help under the GIL |
| `rules` | every detector over every packet | 1 (configurable) | detector state is per-source sliding windows; sharding it changes what the detectors see |
| `persist` | batches and commits to PostgreSQL | 2 (configurable) | psycopg releases the GIL on socket waits, so these genuinely overlap with parsing |
| `serve` | maintains the live view the API reads | 1 | bookkeeping only |

### Why the queues are bounded

An unbounded queue does not fail when a stage falls behind. It grows, quietly,
until the OOM killer decides the matter. A bounded queue forces the operator to
choose what happens instead:

* **`BLOCK`** (default) — the producer waits. Slowness propagates backwards to
  the source. Nothing is lost; the offered rate falls to what the slowest stage
  can sustain. This is backpressure.
* **`DROP`** — the producer gives up after a timeout and the frame is
  **counted**. Loss is bounded, visible, and attributable to a named queue.
  This is what you want when the source is a NIC that will not wait for you.

The queue between persistence and the API-facing stage is deliberately `DROP`:
a slow dashboard must never be able to stall the write path. Its losses are
counted separately as feed evictions and are never conflated with packet loss.

### The loss ledger

Every frame the capture stage pulls off its source ends up in exactly one
bucket, and the identity is asserted rather than assumed:

```
frames_captured == packets_persisted
                 + packets_dropped        (a queue refused it)
                 + packets_parse_failed   (the analyzer could not decode it)
                 + packets_write_failed   (its batch did not commit)
```

`Pipeline.verify_accounting()` checks it, `benchmarks/soak_test.py` fails the
run if it does not hold, and `tests/test_pipeline.py` asserts it under clean
runs, garbage input, a failing writer, and forced overflow.

Dropped and failed are kept apart on purpose. "We are overloaded" and "we are
being sent something we do not understand" are different incidents.

### Shutdown is a drain, not a kill

`stop()` tells the capture stage to stop pulling. Capture exits, closes the
parse queue, which ends the parse workers, which close the rules queue, and so
on down the chain. Each stage finishes the work already in front of it, and the
persistence stage commits its partially-filled batch on the way out. That is
why the identity holds exactly at the end of a run, and why `docker stop`
drains instead of discarding.

---

## Database

Ten tables in PostgreSQL behind SQLAlchemy 2.0, migrated with Alembic.

**Reference** (small, seeded per deploy, joined constantly)
`protocols` · `threat_types` · `mitre_techniques`

**Observation** (written by the pipeline)
`hosts` · `packets` · `flows` · `alerts` · `alert_techniques`

**Derived / operational**
`protocol_stats` (per-minute rollup) · `pipeline_runs` (measured windows)

`packets`, `flows` and `alerts` reference `hosts` by surrogate key rather than
repeating a text address on every row: at a million packets that is the
difference between storing an address once and storing it two million times,
and it makes "everything about this host" one indexed join instead of string
comparison across three tables. The same argument applies to `protocols` and
`threat_types`, which additionally carry attributes — risk band, default
severity — that would otherwise be duplicated per row or live only in Python.

There is deliberately no `threats` table. A "threat" is an aggregation over
alerts grouped by (source host, threat type); materialising it would be a
denormalised copy of rows `alerts` already holds.

### The write path

The ORM's unit of work is the wrong tool for an append-only firehose: one
INSERT round trip per packet is the pipeline stalling on the network rather
than on PostgreSQL. So the models are declared with the ORM — they give
migrations, constraints and typed reads — and written through SQLAlchemy Core
plus psycopg's `COPY`. One batch is one transaction:

1. upsert hosts in a single statement that both resolves surrogate ids and
   folds the batch's counters in (`RETURNING` gives the id map the child rows
   need, without a second round trip and without a race)
2. `COPY` the packets
3. upsert flows through a session-scoped staging table
4. upsert the per-minute protocol rollup
5. insert alerts `RETURNING` ids, their technique links, and the host
   threat-score updates they imply

Every upsert sorts its rows by the conflict key, so concurrent writers take row
locks in the same order. Without that, two batches touching an overlapping host
population deadlock and PostgreSQL aborts one of them — which is exactly what
happened the first time the benchmark ran with more than one writer.

---

## REST API

27 endpoints under `/api` (plus a self-describing index at `/api`).

Conventions, applied everywhere:

* **Pagination.** Collections return `total`, `count`, `limit`, `offset`,
  `has_more`, `next_offset` alongside the named array, so a caller can page
  without guessing when to stop.
* **Filtering and sorting.** Sort keys and enumerated values resolve against
  allow-lists to fixed column objects before they reach SQL. An unknown value
  is a 400 that names what was allowed, never a SQL fragment.
* **One error contract.** Every failure — bad parameter, missing resource,
  unhandled exception — leaves as
  `{"error": {"code", "message", "details"}, "status"}`. `code` is stable and
  machine-readable; driver messages and stack traces never reach a client.
* **Timestamps twice.** `ts` as a unix float for charting, `ts_iso` as RFC 3339
  for humans.

```
GET  /api/health                          GET  /api/hosts
GET  /api/stats/overview                  GET  /api/hosts/<ip>
GET  /api/stats/throughput                GET  /api/geo
GET  /api/stats/protocols                 GET  /api/flows
GET  /api/stats/severity                  GET  /api/packets
GET  /api/stats/timeline                  GET  /api/pipeline/metrics
GET  /api/alerts                          GET  /api/pipeline/runs
GET  /api/alerts/<id>                     GET  /api/live/alerts
GET  /api/alerts/stats                    GET  /api/detectors
POST /api/alerts/<id>/acknowledge         GET  /api/protocols
POST /api/alerts/acknowledge              GET  /api/scenarios
GET  /api/threats/summary                 GET  /api/mitre/techniques
GET  /api/threats/types                   GET  /api/mitre/techniques/<id>
                                          GET  /api/mitre/coverage
```

`/api/pipeline/metrics` answers the observability questions directly, without a
query: how many packets entered, how many were processed, how many were
dropped, which stage is slow, how full the queues are, what the end-to-end
latency distribution looks like, and what the process is spending in CPU and
resident memory.

---

## Detection

17 detectors over 21 decoded protocols, each mapped to MITRE ATT&CK. Nothing is
inferred from port numbers alone — ports only choose which decoder to *attempt*,
and every decoder validates the bytes it is given before claiming the protocol.

Detector state is bounded by construction: every per-key structure prunes on
access and is swept on a timer, so a long-running engine does not grow.

The rules stage dispatches by protocol. Most detectors open with a protocol
guard and return immediately — an ARP spoofing rule has nothing to say about a
TLS record — so calling all seventeen for every packet spent most of the stage's
time entering and leaving functions. Each detector declares the protocols it can
fire on; the guard stays in `inspect()` as well, so the hint can only remove
work, never change a verdict.

---

## Testing

The suite runs against a real PostgreSQL. Nothing is mocked: the schema, the
constraints, the `COPY` write path and the query plans are all PostgreSQL
behaviour, and a fake would only prove the fake works.

| File | Covers |
|---|---|
| `test_protocol_analyzer.py` | wire-format decoding, malformed input, entropy |
| `test_detectors.py` | every scenario's ground truth, thresholds, false-positive control over 20k benign packets |
| `test_mitre.py` | ATT&CK catalog integrity and alert→technique links |
| `test_schema.py` | constraints, foreign keys, the enum, index presence, drop/recreate |
| `test_writer.py` | batch atomicity, per-batch aggregation, concurrent writers |
| `test_repository.py` | pagination, filtering, sorting, aggregates, query plans |
| `test_queues.py` | capacity, backpressure, drop accounting, shutdown |
| `test_metrics.py` | histogram accuracy (asserted within 5%), rate window |
| `test_pipeline.py` | the loss identity under clean runs, garbage, writer failure and forced overflow; graceful drain |
| `test_capture.py` | frame sources, determinism from a seed |
| `test_api.py` | every route, the pagination envelope, the error contract |
| `test_benchmarks.py` | the benchmark harness itself |
| `test_dashboard.py` | every dashboard module is backed by a working endpoint |
| `test_config_and_cli.py` | config merging, URL normalisation, the CLI |

Two isolation schemas inside one database: one populated once per session by
running the real pipeline, one truncated before each test that needs a clean
slate.

---

## CI

`.github/workflows/ci.yml` runs on every push:

* **lint** — `ruff check` (line length, import ordering, unused code, bug
  patterns) and `compileall`. `ruff format` is deliberately *not* enforced;
  this codebase aligns tables and argument lists by hand and a formatter would
  flatten that without making anything more correct.
* **test** — Python 3.11 and 3.12 against a `postgres:16` service container.
  Applies the migrations, downgrades to base, applies them again, then runs the
  suite with coverage and a floor.
* **benchmarks** — smoke runs of all three benchmarks. A shared CI runner is
  the wrong place to measure throughput, so this job asserts the harness still
  runs and the loss ledger still balances; the numbers below come from the
  documented local runs.
* **docker** — builds the runtime image, runs the test stage inside it, brings
  the compose stack up with `--wait`, and probes `/api/health` and
  `/api/stats/overview` to prove the containers actually talk to each other.

---

## Containers

Multi-stage build: `builder` resolves dependencies into a venv, `test` runs the
suite inside the image, `runtime` ships the venv plus source with no compilers
or package managers. Runs as a fixed unprivileged uid, on a read-only root
filesystem, with every Linux capability dropped and privilege escalation
blocked.

The compose stack is the split topology — `db`, a one-shot `migrate`, one
`engine` that owns ingest, and a stateless `api` tier that scales with
`--scale api=N`. That separation is the point of moving off SQLite: with a
single-writer file database the API had to live inside the writer's process.

---

## Measured results

MEASURED_RESULTS_PLACEHOLDER

---

## Reproducing

```bash
docker compose up -d db
export NETWATCH_DATABASE_URL=postgresql+psycopg://netwatch:netwatch@localhost:5432/netwatch
alembic upgrade head && python -m netwatch.cli seed

python -m benchmarks.pipeline_benchmark --packets 40000 --repeats 3
python -m benchmarks.pipeline_benchmark --sweep         # the worker/batch matrix
python -m benchmarks.soak_test --minutes 10 --rate 4000
python -m benchmarks.query_benchmark --alerts 400000 --packets 600000
```

Workloads are seeded, so `--seed` reproduces byte-identical traffic. Each run
writes JSON to `benchmarks/results/` recording the machine, the PostgreSQL
settings in force (including `synchronous_commit`), and every number reported.

---

## Honest limitations

* **Traffic is synthetic.** `TrafficGenerator` builds real wire-format frames
  with correct checksums and conformant protocol encodings, and nothing
  downstream knows they were generated — but they are not a packet capture from
  a real network. Substituting a live source is a `FrameSource` subclass; the
  throughput numbers would then also depend on the NIC and the capture path.
* **Throughput is bound by Python, not by PostgreSQL.** Parsing and rule
  evaluation are pure-Python CPU work under the GIL. Adding parse threads does
  not help, and the honest way to scale the CPU stages is more pipeline
  processes, not more threads.
* **The API has no authentication or rate limiting.** Ports bind to loopback
  by default; put a reverse proxy in front before exposing it.
* **Alerts for the database benchmark are loaded synthetically.** Real
  detectors have cooldowns precisely so one attack does not become ten thousand
  duplicate rows, so measuring index behaviour at hundreds of thousands of rows
  needs a loader (`netwatch/db/seed.py`). It is structurally faithful — same
  foreign keys, same severity and threat-type mix, skewed source distribution —
  but it is generated, and the benchmark says so.
