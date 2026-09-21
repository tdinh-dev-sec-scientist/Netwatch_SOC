# NetWatch SOC — Network Threat Detection Platform

[![CI](https://github.com/tdinh-dev-sec-scientist/Netwatch_SOC/actions/workflows/ci.yml/badge.svg)](https://github.com/tdinh-dev-sec-scientist/Netwatch_SOC/actions/workflows/ci.yml)

<!-- After the first Render deploy, add the demo link on the next line, e.g.
**Live demo:** https://<service>.onrender.com (read-only, synthetic traffic; the
first load after the service has idled takes about a minute) -->

A network security monitoring platform: deep packet inspection over 21 protocols,
17 modular threat detectors mapped to MITRE ATT&CK, an indexed 8-table PostgreSQL
store, a 24-endpoint REST API, and a 9-module analyst dashboard.

Every number in this README is measured, and the commands to reproduce each one
are given. Where a number falls short of a target, it says so. The headline
counts are pinned by `tests/test_readme.py`, so the documentation cannot drift
from the code without a test failing.

---
##🚀 Live Demo
Application is running at: [https://netwatch-soc-demo.onrender.com](https://netwatch-soc-demo.onrender.com)

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
[SQLite fallback](#sqlite-fallback-development-only).

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

---

## Architecture

```
 frames.py ──────► ProtocolAnalyzer ──────► ThreatDetector ──────► DB_Manager ──────► App.py ──────► Dashboard.html
 (or a live       parses raw bytes         17 detectors,           8 tables,          24 REST        9 modules
  capture)        into 21 protocols        bounded state           batched writes     endpoints
```

The pipeline moves **raw Ethernet frames**, not pre-labelled records. `frames.py`
builds real wire-format bytes (correct IPv4/TCP/UDP/ICMP checksums, conformant
DNS/TLS/SNMP/DHCP encodings) and the analyzer decodes them with no knowledge of
how they were produced. That is what makes the DPI layer and the detectors
independently testable — and it means swapping in a live capture changes nothing
downstream:

```python
from scapy.all import AsyncSniffer
AsyncSniffer(prn=lambda p: simulator.process(bytes(p), time.time())).start()
```

### Data flow for one packet

1. **Parse** — `ProtocolAnalyzer.parse()` walks Ethernet → IPv4/IPv6/ARP →
   TCP/UDP/ICMP → L7, returning a flat dict of extracted fields.
2. **Detect** — `ThreatDetector.analyze()` feeds the parsed packet to all 17
   detectors. Each keeps bounded sliding-window state and returns `Finding`
   objects with severity, confidence, evidence and ATT&CK technique IDs.
3. **Persist** — `PacketSimulator` buffers packets and findings, then
   `DatabaseManager.persist_batch()` writes them in one transaction: the packet
   row, the flow upsert, the host upsert, the protocol rollup, the alert, and
   the alert↔technique links.
4. **Serve** — Flask endpoints query PostgreSQL over a pooled connection; the
   dashboard renders the result.

### Files

| File | Role |
|---|---|
| `frames.py` | Wire-format frame construction (the capture-layer stand-in) |
| `ProtocolAnalyzer.py` | Deep packet inspection: 21 protocols |
| `detectors/` | 17 detectors, one module per threat family |
| `ThreatDetector.py` | Engine: registry, dispatch, state expiry, introspection |
| `mitre.py` | ATT&CK catalog with a written rationale per technique |
| `DB_Manager.py` | Every SQL statement: batched writes and all read queries |
| `db_backends.py` | Driver layer: connection pooling, dialect translation, PostgreSQL and the SQLite fallback |
| `migrate.py` | Versioned SQL migration runner (`status`, `up`) |
| `migrations/` | The schema itself, one numbered file per change per backend |
| `migrate_sqlite_to_postgres.py` | One-off copy of an existing `netwatch.db` into PostgreSQL |
| `geoip.py` | Coarse prefix→country enrichment (**not** a geolocation DB) |
| `config.py` | Every detection threshold, overridable via `NETWATCH_CONFIG` |
| `PacketSimulator.py` | Traffic generation, attack scenarios, engine loop |
| `App.py` | Flask app and API endpoints |
| `hardening.py` | Security headers, read-only demo mode, rate limiting |
| `engine.py` | Headless engine for the split deployment topology |
| `benchmark.py` | Reproducible throughput, latency and alert-volume measurement |
| `static/vendor/` | Vendored Chart.js, checksum-pinned (no CDN scripts) |
| `render.yaml` | Render Blueprint for the public demo |
| `scripts/smoke_test.sh` | End-to-end checks of the image, compose topologies and demo |

---

## Measured results

Produced by `python benchmark.py` on the machine described below. Re-run it and
you will get numbers of the same shape; absolute throughput is hardware-dependent.

```
Environment : Python 3.11.15, PostgreSQL 16.13, Linux x86_64, single-threaded,
              shared container, database on the same host
Command     : python benchmark.py --iterations 5 --packets 20000
Dataset     : 106,690 packets, 120 alerts, 135 technique links
```

| Claim | Target | Measured | Status |
|---|---|---|---|
| Threat types | 15+ | **17** (all 17 proven by a scenario) | ✅ |
| Protocols inspected | 15+ | **21** | ✅ |
| ATT&CK techniques | 12 | **15** across 9 tactics | ✅ |
| Tables | 8 | **8**, all written by the pipeline | ✅ |
| Indexes | — | **25**, usage asserted by `EXPLAIN` on a 40k-row dataset | ✅ |
| REST endpoints | 14+ | **24** | ✅ |
| Dashboard modules | 8+ | **9** | ✅ |
| Throughput | 5,000 pkt/min | **377,498 pkt/min median = 6,292 pkt/s** (5,875–7,080 pkt/s) | ✅ |
| Query latency | < 50 ms | **p50 0.33 ms · p95 10.69 ms · max 16.78 ms** | ✅ |
| Alert-volume reduction | — | **96.1%** (621 → 24), **0 incidents lost** | ✅ |
| False positives | — | **0** across 240,000 benign packets, 8 seeds | ✅ |

At a larger scale — 248,028 packets and 3,776 alerts, produced by relaxing
detector cooldowns so more real detections are retained — latency stays within
target: **p50 1.27 ms, p95 14.51 ms, p99 17.26 ms, max 19.12 ms**, throughput
338,563 pkt/min median.

```bash
# reproduce the scale run
python - <<'EOF'
import json, config
json.dump({k: {'cooldown_s': 0} for k, v in config.DEFAULTS.items()
           if isinstance(v, dict) and 'cooldown_s' in v}, open('lowcooldown.json','w'))
EOF
NETWATCH_CONFIG=lowcooldown.json python benchmark.py --iterations 6 --packets 40000
```

### What moving from SQLite to PostgreSQL cost

Both columns are the same command on the same machine, five iterations of 20,000
packets, ending at 106,690 packets:

| | SQLite (file) | PostgreSQL 16 (same host) | Change |
|---|---|---|---|
| Throughput, median | 383,876 pkt/min (6,398 pkt/s) | 377,498 pkt/min (6,292 pkt/s) | **−1.7%** |
| Query latency p50 | 0.124 ms | 0.328 ms | +0.20 ms |
| Query latency p95 | 0.677 ms | 10.692 ms | **+10.0 ms** |
| `/api/stats/overview` p50 | 0.27 ms | 16.10 ms | +15.8 ms |
| `/api/health` p50 | 0.29 ms | 9.32 ms | +9.0 ms |
| Alert reduction | 96.1%, 0 incidents lost | 96.1%, 0 incidents lost | unchanged |

**Write throughput is essentially unchanged.** Batched inserts through psycopg's
pipeline mode cost about as much as SQLite's, because parse and detect dominate:
27.9 µs and 15.6 µs per packet against a few µs of amortised write.

**Read latency is an order of magnitude worse in the tail, and two endpoints
account for almost all of it** — `/api/stats/overview` and `/api/health`, both of
which count rows. PostgreSQL has no O(1) `COUNT(*)`: it scans. SQLite, on a small
local file with the whole thing in page cache, effectively did not. Collapsing
each endpoint from a dozen separate statements into one statement of scalar
subqueries cut the overall p95 by 25% and is why the numbers are 10 ms rather
than 20 ms, but the scan remains.

This is a real regression and it grows with row count: at 248,028 packets
`/api/stats/overview` is 16.3 ms. It is still **3–5× inside the 50 ms target**,
every other endpoint is at or below 2 ms, and retention bounds the tables — so it
is accepted rather than worked around. The available fix, `pg_class.reltuples`,
returns an estimate, and both the container healthcheck and the test suite read
exact counts from `/api/health`. Worth revisiting for a deployment that keeps
enough history to push it past a few hundred thousand packets.

In exchange: concurrent writers, real type enforcement, queryable `JSONB`,
counters that do not overflow at 2.1 GB, a database that is not tied to a
filesystem, and an API tier that can span hosts.

Throughput is measured end-to-end — parse **and** detect **and** batched
PostgreSQL persistence — over `--iterations` independent runs, reported as mean,
median, min, max and standard deviation, in **both packets/minute and
packets/second**. Prefer the median and quote the range with it: on a shared
or throttled machine the spread between runs is wide (here 4,567–7,555 pkt/s
across five runs), so a single figure without its range says little.

Query latency covers all 22 queries that back the REST API, run against the
dataset the throughput phase actually wrote, reported as p50/p95/p99.

### Alert-volume reduction

The third phase measures how much of the raw detector output the shipped
tuning suppresses, against two explicit baselines on the same workload:

| Baseline | What it is | Result |
|---|---|---|
| Same rules, dedup off | every `cooldown_s` set to 0, **every threshold unchanged** | 621 alerts |
| Shipped tuning | `config.py` as it ships | **24 alerts — 96.1% fewer** |
| Benign-only corpus | 20,000 benign frames through the shipped tuning | **0 alerts** |

The baseline changes *only* the cooldowns, which is what makes the ratio
meaningful: it cannot be inflated by also loosening detection, and
`test_undeduplicated_baseline_only_disables_cooldowns` asserts that every
other threshold is identical between the two configs.

A reduction figure is worthless if it drops real detections, so the benchmark
also checks that suppression is **lossless**. Each finding carries the key its
detector deduplicates on — `Finding.incident_key`, the identity of the
incident rather than of the packet that exposed it, which for a flood is the
victim and not the spoofed source — and the two runs are compared on those
keys. Both resolve to the **same 24 distinct incidents**; the 597 suppressed
alerts are all repeat reports of an incident already raised. `benchmark.py`
exits non-zero if a single incident present in the baseline is missing from
the tuned run.

Severity is triage metadata carried on every alert (here CRITICAL 9, HIGH 9,
MEDIUM 6) — it ranks the queue for an analyst; it is the per-rule cooldowns
and thresholds that do the suppressing.

```bash
python benchmark.py                    # all three phases
python benchmark.py --skip-reduction   # throughput + latency only
```

Reproduce with a JSON record:

```bash
python benchmark.py --iterations 5 --packets 20000 --json results.json
```

The benchmark exits non-zero if any of its three gates fails — throughput
below target, p95 query latency above 50 ms, or an incident lost to alert
suppression — so it can gate CI.

---

## Detection engine — 17 threat types

Each detector lives in its own module under `detectors/`, declares the ATT&CK
techniques it can emit, and is tuned by one section of `config.py`.

| Threat type | Signal used | ATT&CK |
|---|---|---|
| `port_scan` | Distinct destination ports on one host in a window | T1046 |
| `network_recon` | Many hosts within one /24 on a narrow port set; ICMP sweep | T1595 |
| `brute_force` | In-protocol auth failures (FTP 530, SMTP 535, POP3 `-ERR`, IMAP `NO`, HTTP 401); SSH session bursts | T1110, T1078 |
| `credential_attack` | Many usernames from one source; one username across many hosts; cleartext credentials | T1110, T1078 |
| `c2_beacon` | Coefficient of variation of inter-arrival times on one channel | T1071.001 |
| `dns_tunnel` | Oversized label **and** high entropy / TXT-NULL-ANY / volume | T1071.004, T1048 |
| `suspicious_dns` | NXDOMAIN ratio; repeated high-entropy SLD lookups | T1071.004 |
| `icmp_tunnel` | Oversized, high-entropy echo payloads, repeated | T1572, T1048 |
| `protocol_tunnel` | L7 identified by signature on a mismatched port | T1572 |
| `tls_anomaly` | Obsolete version, absent SNI, tiny cipher list (scored together) | T1573 |
| `data_exfil` | Outbound internal→external byte volume in a window | T1041 |
| `lateral_movement` | Internal→internal admin-service fan-out | T1021 |
| `syn_flood` | SYN rate **and** SYN:completed-handshake ratio | T1498 |
| `udp_flood` | UDP packet rate to one destination | T1498 |
| `amplification` | Response:request byte ratio on NTP/DNS/SNMP | T1498.002 |
| `http_anomaly` | SQLi / traversal / XSS / command injection / JNDI / scanner UA | T1190 |
| `arp_spoof` | IP↔MAC binding conflict; gratuitous ARP flood | T1557.002 |

### What the detectors deliberately do *not* alert on

The thresholds were tuned against a benign corpus, and the negative cases are
tested (`tests/test_detectors.py`):

- Long, numerous CDN hostnames — **not** DNS tunnelling (an oversized label is
  required, not merely high entropy and volume).
- High SYN volume that completes its handshakes — **not** a SYN flood.
- Large inbound downloads — **not** exfiltration (direction is checked).
- Ordinary browsing across many networks — **not** a host sweep (targets must
  cluster in one /24).
- Service replies fanning out across ephemeral ports — **not** a port scan.
- Repeated access to a single file server — **not** lateral movement (fan-out
  across hosts is required).

**Measured false-positive rate: 0 alerts across 240,000 benign packets** over
8 independent seeds.

```bash
pytest tests/test_detectors.py::test_no_false_positives_on_benign_background
```

Every threshold is configurable without touching detection logic:

```bash
NETWATCH_CONFIG=thresholds.json python App.py
# {"port_scan": {"distinct_ports": 30}, "c2_beacon": {"max_jitter_ratio": 0.08}}
```

---

## Deep packet inspection — 21 protocols

Identification is **signature-first**: a protocol running on a non-standard port
is still named correctly (and flags `nonstandard_port`, which feeds the
tunnelling detector). Port numbers only choose which decoder to *attempt*; every
decoder validates the bytes before claiming the protocol.

| Layer | Protocol | Extracted |
|---|---|---|
| L2 | **Ethernet** | src/dst MAC, ethertype |
| L2 | **ARP** | opcode, sender/target MAC+IP, gratuitous flag |
| L3 | **IPv4** | addresses, TTL, protocol, ID, flags, fragment offset |
| L3 | **IPv6** | addresses, hop limit, next header, flow label |
| L4 | **TCP** | ports, flags, seq, ack, window, payload length |
| L4 | **UDP** | ports, length |
| L4 | **ICMP** | type, code, echo id/seq, payload length + entropy |
| L7 | **DNS** | qname, qtype, qr, rcode, answer count, max label length, label entropy |
| L7 | **HTTP** | method, URI, version, Host, User-Agent, status, Authorization, Content-Length |
| L7 | **TLS** | record type, version, handshake type, **SNI**, cipher-suite count |
| L7 | **SSH** | protocol version, software string, binary message type |
| L7 | **FTP** | command, argument, response code |
| L7 | **SMTP** | command, argument, response code |
| L7 | **POP3** | command, `+OK`/`-ERR` status |
| L7 | **IMAP** | tag, command, `OK`/`NO`/`BAD` status |
| L7 | **SNMP** | version, community string, PDU type (BER-decoded) |
| L7 | **NTP** | mode, version, request code, monlist + response flags |
| L7 | **TELNET** | negotiation option count, cleartext |
| L7 | **SMB** | dialect (SMB1/SMB2), command |
| L7 | **RDP** | TPKT length, X.224 type, `mstshash` cookie |
| L7 | **DHCP** | op, message type, client MAC |
| L7 | **QUIC** | long-header flag, version, DCID length |

Shannon entropy is computed for every payload and drives the tunnelling and
exfiltration detectors.

Malformed input is handled explicitly: `parse()` raises `ParseError` on frames
too short or malformed to yield a usable L3 record, `safe_parse()` returns
`None` and counts the failure, and truncated *upper* layers degrade gracefully —
the packet keeps what was decoded and gains a `truncated` flag.

---

## MITRE ATT&CK — 15 techniques

`mitre.py` is the single source of truth and is loaded into the
`mitre_techniques` table at startup. Every technique carries a written
**rationale** explaining why the network evidence corresponds to it; the
rationale is served by the API and shown in the dashboard, so a mapping can be
audited rather than taken on trust.

Two invariants are enforced by tests:

- **No orphan techniques** — every catalogued technique is reachable from at
  least one detector (`test_every_catalogued_technique_is_reachable_from_a_detector`).
- **No invented IDs** — the engine refuses to start if a detector names a
  technique missing from the catalog (`ThreatDetector._validate_technique_references`).

| ID | Name | Tactic | Raised by |
|---|---|---|---|
| T1595 | Active Scanning | Reconnaissance | `network_recon` |
| T1190 | Exploit Public-Facing Application | Initial Access | `http_anomaly` |
| T1078 | Valid Accounts | Defense Evasion | `brute_force`, `credential_attack` |
| T1110 | Brute Force | Credential Access | `brute_force`, `credential_attack` |
| T1557.002 | ARP Cache Poisoning | Credential Access | `arp_spoof` |
| T1046 | Network Service Discovery | Discovery | `port_scan` |
| T1021 | Remote Services | Lateral Movement | `lateral_movement` |
| T1071.001 | Application Layer Protocol: Web | Command and Control | `c2_beacon` |
| T1071.004 | Application Layer Protocol: DNS | Command and Control | `dns_tunnel`, `suspicious_dns` |
| T1572 | Protocol Tunneling | Command and Control | `icmp_tunnel`, `protocol_tunnel` |
| T1573 | Encrypted Channel | Command and Control | `tls_anomaly` |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | `data_exfil` |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | `dns_tunnel`, `icmp_tunnel` |
| T1498 | Network Denial of Service | Impact | `syn_flood`, `udp_flood` |
| T1498.002 | Reflection Amplification | Impact | `amplification` |

---

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

---

## REST API — 24 endpoints

All read from PostgreSQL. Empty database returns empty collections, never filler.
Invalid parameters return `400` with a message; unknown resources return `404`.

| Method | Route | Notes |
|---|---|---|
| GET | `/api/health` | Schema, index count, row counts, engine state |
| GET | `/api/stats/overview` | Live counters |
| GET | `/api/stats/throughput` | `?minutes=1..10080` |
| GET | `/api/stats/protocols` | `?minutes=` |
| GET | `/api/stats/severity` | `?hours=1..720` |
| GET | `/api/stats/timeline` | `?hours=`, `?bucket_s=` |
| GET | `/api/alerts` | `?limit&offset&severity&threat_type&src_ip&acknowledged` |
| GET | `/api/alerts/<id>` | Detail + techniques + related packets |
| POST | `/api/alerts/<id>/acknowledge` | |
| GET | `/api/alerts/stats` | Grouped by threat type |
| GET | `/api/threats/summary` | Aggregated per source + threat type |
| GET | `/api/threats/types` | Detector catalog joined with live counts |
| GET | `/api/mitre/techniques` | Catalog + observed counts |
| GET | `/api/mitre/techniques/<id>` | Detail, detectors, recent alerts |
| GET | `/api/mitre/coverage` | Grouped by tactic |
| GET | `/api/hosts/top` | `?order=packets_sent\|bytes_sent\|threat_score\|alert_count` |
| GET | `/api/hosts/<ip>` | Protocols, peers, alerts |
| GET | `/api/geo` | Country rollup |
| GET | `/api/connections` | `?order&src_ip&limit` |
| GET | `/api/packets` | `?protocol&src_ip&dst_ip&malicious_only` |
| GET | `/api/performance` | Measured history + live counters |
| GET | `/api/detectors` | Per-detector counters |
| GET | `/api/protocols` | Supported protocols + parse counts |
| GET | `/api/scenarios` | Replayable attack scenarios |

All filters are parameterised; `test_sql_injection_in_filters_is_parameterised`
confirms injection attempts are treated as literal values.

---

## Dashboard — 9 modules

Every module fetches from the API; there is no seeded or placeholder data in the
template, and `test_no_hardcoded_sample_data` enforces it.

1. **Threat Overview** — KPIs, throughput, severity mix, active threats
2. **Recent Alerts** — filterable queue, acknowledge, technique chips
3. **Threat Distribution** — alerts by type + full detector catalog
4. **MITRE ATT&CK Coverage** — matrix by tactic, click through to technique detail
5. **Protocol Analysis** — traffic by protocol + DPI coverage table
6. **Source / Destination IP Analysis** — talkers, threat scores, geography, flows
7. **Activity Trends** — stacked severity timeline, byte volume
8. **Detection Performance** — measured throughput, query latency, DB health
9. **Live Packet Log** — decoded L7 fields per packet

Clicking an alert, host or technique opens a detail drawer showing the evidence,
the ATT&CK mapping *with its rationale*, and the related packets.

---

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
| `test_readme.py` | Every headline count in this README matches what the code produces |
| `test_hardening.py` | Security headers and CSP, read-only demo mode, rate limiter, proxy trust, vendored asset checksum |
| `test_retention.py` | Expiry per table, no orphaned technique links, loop prunes only when configured |
| `test_backfill.py` | History stays inside its window, all threat types present, no future timestamps |
| `test_simulator_loop.py` | Live-window alert accounting, clean shutdown |
| `test_deployment.py` | Image contains every imported module and the migrations; every migration exists for both backends; database service pinned with a healthcheck and waited on; compose profiles, ports and gunicorn settings are valid; Blueprint is hardened |

Fixtures are seeded (`TrafficGenerator(seed=…)` reproduces byte-identical
traffic), and the attack scenarios double as ground truth: each has a known
expected threat type, asserted end to end.

---

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
deployment are in [docs/demo-deployment.md](docs/demo-deployment.md).

### Continuous integration

Every push runs, on Python 3.11 and 3.12: the migrations from an empty database
(and again, to prove they are idempotent), the test suite against a PostgreSQL
service container, the suite a second time against the SQLite fallback, and the
benchmark gates. Then both Dockerfile stages and `scripts/smoke_test.sh` against
the built image, for the demo configuration and both compose topologies. Render
deploys `main` only after these checks pass.

---

## Honest limitations

- **Traffic is synthetic.** `frames.py` emits real wire-format bytes and the
  analyzer has no privileged knowledge of their origin, so the parsing and
  detection logic is genuinely exercised — but the *traffic mix* is a model of
  an enterprise network, not a capture of one. The measured false-positive rate
  is against that model. Validating against real captured traffic would be the
  next step, and would very likely require re-tuning thresholds.
- **Geo enrichment is a static prefix table**, not MaxMind. `geoip.py` returns
  `UNKNOWN` rather than guessing, and the dashboard labels it "approximate".
  The high-risk country list is a crude proxy, not threat intelligence.
- **SSH brute force is inferred, not observed.** Authentication happens inside
  the encrypted channel; the detector counts cleartext version banners, which is
  the standard network-side signal, and caps its confidence at 0.85 accordingly.
- **Throughput is single-threaded and hardware-dependent.** The benchmark reports
  what your machine measured, not a fixed figure. The run recorded above spans
  4,567–7,555 pkt/s across five iterations on a shared container; quote the
  median with its range rather than the best iteration.
- **The alert-reduction figure is scoped to deduplication.** Its baseline is
  the same rules with cooldowns disabled, so 96.1% is what per-rule dedup
  contributes on this workload — not a comparison against some other tool's
  alert volume, and not a claim about threshold tuning, whose effect is
  reported separately as the false-positive count on benign traffic. The ratio
  also depends on the workload: a capture with longer sustained attacks would
  have more duplicates to collapse and a higher ratio.
- **No prior "99.2% accuracy" claim is made.** Accuracy requires labelled ground
  truth across both classes; what is measured here is detection of known
  scenarios and a false-positive count on a benign corpus. Those two numbers are
  reported, and nothing is extrapolated from them.
- **The dev server is for demonstration.** It binds to `127.0.0.1` by default;
  the container image serves through gunicorn instead.
- **Exact row counts get slower as the database grows.** PostgreSQL has no
  O(1) `COUNT(*)`, so `/api/health` and `/api/stats/overview` scan to count. Both
  are one statement of scalar subqueries rather than a dozen round trips, which
  keeps them at roughly 5 ms p95 on the benchmark's dataset — well inside the
  50 ms target, but growing with row count where SQLite's were flat. The obvious
  fix, `pg_class.reltuples`, returns an estimate, and the container healthcheck
  and the tests read exact counts from `/api/health`; retention bounds the tables
  in the meantime. Revisit if a deployment keeps enough history for it to matter.
- **There is no authentication.** The public demo is safe to expose only because
  demo mode makes it read-only and it holds no real data. The dashboard's inline
  event handlers still require `'unsafe-inline'` in the Content-Security-Policy;
  [docs/demo-deployment.md](docs/demo-deployment.md) lists this and the other
  accepted risks.
