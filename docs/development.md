# Development, testing and deployment

Running NetWatch locally, the test suite, the container topologies and CI. Back to the [README](../Readme.MD).

## Quick start

PostgreSQL is the production database and the default. The quickest way to get
one is the compose service that ships with the project:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env               # development credentials; edit if you like
docker compose up -d postgres      # PostgreSQL 16 on 127.0.0.1:5432

export DATABASE_URL=postgresql://netwatch:netwatch@localhost:5432/netwatch
python migrate.py up               # create the schema (App.py also does this)
python App.py                      # dashboard + live simulation → http://127.0.0.1:5001

pytest                             # full suite, against that same server
python benchmark.py                # throughput, query latency, alert reduction
```

No PostgreSQL to hand? `DB_BACKEND=sqlite python App.py` runs the whole thing
against a local file with no server and no configuration. It is a development
convenience, not a supported deployment — see
[SQLite fallback](database.md#sqlite-fallback-development-only).

`NETWATCH_SIMULATE=0 python App.py` runs the API without generating traffic.
`NETWATCH_DEMO=1 NETWATCH_BACKFILL_MIN=15 python App.py` runs it the way the
public demo does: read-only, rate-limited, and pre-filled with history. See
[Deployment](#deployment).

### Environment variables

Every database setting is environmental; `.env.example` is the annotated list.
The ones that matter:

| Variable | Default | Effect |
|---|---|---|
| `DATABASE_URL` | — | The preferred form. `postgresql://user:pass@host:5432/netwatch?sslmode=require` |
| `PG_HOST`, `PG_PORT`, `PG_USER`, `PG_PASSWORD`, `PG_DB`, `PG_SSLMODE` | `localhost`, `5432`, `netwatch`, —, **required**, — | Discrete fallback, used only when `DATABASE_URL` is unset |
| `DB_BACKEND` | `postgresql` | `sqlite` selects the development fallback |
| `NETWATCH_DB` | `./netwatch.db` | SQLite file path; ignored unless `DB_BACKEND=sqlite` |
| `PG_POOL_MIN`, `PG_POOL_MAX` | `1`, `10` | Reader pool bounds. Keep `PG_POOL_MAX` ≥ `GUNICORN_THREADS` |
| `PG_CONNECT_TIMEOUT` | `10` | Seconds to wait for a connection |
| `PG_STATEMENT_TIMEOUT_MS` | `30000` | Ceiling on any single statement |
| `NETWATCH_AUTO_MIGRATE` | `1` | Apply pending migrations on startup. Set to `0` to make migrations an explicit release step |
| `TEST_DATABASE_URL` | falls back to `DATABASE_URL` | Server the test suite creates its scratch databases on |


## Testing

The suite runs against a **real PostgreSQL server**, because the differences
that matter — strict typing, `JSONB`, boolean columns, the planner's choices —
are invisible to a test that only ever sees SQLite.

```bash
docker compose up -d postgres           # or point at any server you like
export TEST_DATABASE_URL=postgresql://netwatch:netwatch@localhost:5432/netwatch

pytest                                  # full suite
pytest tests/test_detectors.py -v       # every detector + false-positive control
pytest tests/test_database.py -v        # schema, types, indexes, query plans, latency
pytest tests/test_benchmark.py -v       # targets met, alert reduction lossless

DB_BACKEND=sqlite pytest                # the fallback; PostgreSQL-only tests skip
```

`TEST_DATABASE_URL` falls back to `DATABASE_URL`, and to
`postgresql://netwatch:netwatch@localhost:5432/netwatch` — the compose service's
own credentials — if neither is set.

**The suite never writes to the database you name.** It creates
`netwatch_test_*` databases alongside it and drops them at the end, so pointing
it at a development database cannot destroy its contents. Two are used: one
truncated before every test that wants an empty database, and one filled once by
the pipeline for the many tests that only read. `TRUNCATE` costs far less than
`CREATE DATABASE`, and the suite asks for an empty database a few hundred times.

| File | Covers |
|---|---|
| `test_protocol_analyzer.py` | Every protocol, entropy, malformed/truncated input |
| `test_detectors.py` | Each detector fires on its scenario; negative cases; thresholds; state bounding; detector isolation |
| `test_mitre.py` | Catalog integrity, no orphans, no invented IDs, DB linkage |
| `test_database.py` | 8 tables populated, column types and constraints enforced, JSONB queryable, 64-bit counters, `ts_utc` correctness, rollup consistency, index usage at scale, <50 ms, transactionality |
| `test_api.py` | All endpoints, schemas, pagination, 400/404, SQL injection |
| `test_dashboard.py` | Each module wired to a working endpoint, escaping, no mock data |
| `test_benchmark.py` | Determinism, targets met, results persisted; alert-reduction baseline is threshold-identical and suppression loses no incident |
| `test_readme.py` | Every headline count in the README matches what the code produces |
| `test_hardening.py` | Security headers and CSP, read-only demo mode, rate limiter, proxy trust, vendored asset checksum |
| `test_retention.py` | Expiry per table, no orphaned technique links, loop prunes only when configured |
| `test_backfill.py` | History stays inside its window, all threat types present, no future timestamps |
| `test_simulator_loop.py` | Live-window alert accounting, clean shutdown |
| `test_deployment.py` | Image contains every imported module and the migrations; every migration exists for both backends; database service pinned with a healthcheck and waited on; compose profiles, ports and gunicorn settings are valid; Blueprint is hardened |

Fixtures are seeded (`TrafficGenerator(seed=…)` reproduces byte-identical
traffic), and the attack scenarios double as ground truth: each has a known
expected threat type, asserted end to end.


## Deployment

### Containers

```bash
docker compose up -d postgres                       # just the database, for local dev
docker compose --profile all-in-one up -d --build   # engine + API in one process
docker compose --profile split up -d --build        # one engine, two API replicas
docker compose --profile test run --rm tests        # the suite, against that database
```

Every application service belongs to exactly one profile, so the two topologies
can never both start an engine against the same database; `postgres` is in all of
them, because a shared database is infrastructure rather than a topology. The
image runs as a non-root user and writes nothing to disk — the database is
outside the container, so `DATABASE_URL` is all it needs — and the compose file
adds a read-only root filesystem and drops all Linux capabilities.

The bundled `postgres` service is **for development**. In a real deployment point
`DATABASE_URL` at a managed instance and do not start it: you want someone else
running backups, failover and minor-version upgrades. Use `PG_SSLMODE=require`
(`verify-full` if you can pin the CA) whenever the connection leaves the host.

**Connection budget.** PostgreSQL's default `max_connections` is 100 and each
connection costs real memory. The split topology can hold
`replicas × GUNICORN_WORKERS × PG_POOL_MAX` (2 × 4 × 4 = 32) plus the engine's 2.
Raise `max_connections`, or put pgbouncer in front, before scaling much past
that.

**The database is no longer tied to a filesystem**, which is what the split
topology could not previously escape: under SQLite the engine and the API
replicas had to share a volume that supported POSIX advisory locks, so they
could not span hosts. Now they share only a connection string.

### Public demo

`render.yaml` deploys a read-only demo to Render's Free plan. It is configured
entirely through environment variables:

| Variable | Effect |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string, injected by Render from the managed database in the Blueprint |
| `NETWATCH_AUTO_MIGRATE` | Apply pending migrations on startup (`1`); set `0` and run `python migrate.py up` as a release step with more than one instance |
| `PG_POOL_MAX` | Reader pool ceiling per process; keep the tier's total inside the server's `max_connections` |
| `NETWATCH_DEMO=1` | Refuse every non-GET request with 403; show a banner that the traffic is synthetic |
| `NETWATCH_RETENTION_S` | Delete telemetry older than this many seconds (0 keeps everything) |
| `NETWATCH_BACKFILL_MIN` | Generate this many minutes of history, with every attack scenario, at startup |
| `NETWATCH_RATE_PPS` | Live simulated packets per second |
| `NETWATCH_RATE_LIMIT`, `NETWATCH_GLOBAL_RATE_LIMIT` | Requests per window per client and overall, e.g. `600/60`; `0` disables |
| `NETWATCH_PROXY_HOPS` | How many reverse proxies to trust for `X-Forwarded-For` (default 0) |

Deployment steps, the threat model, accepted risks and how to verify a live
deployment are in [docs/demo-deployment.md](demo-deployment.md).

### Continuous integration

Every push runs, on Python 3.11 and 3.12: the migrations from an empty database
(and again, to prove they are idempotent), the test suite against a PostgreSQL
service container, the suite a second time against the SQLite fallback, and the
benchmark gates. Then both Dockerfile stages and `scripts/smoke_test.sh` against
the built image, for the demo configuration and both compose topologies. Render
deploys `main` only after these checks pass.
