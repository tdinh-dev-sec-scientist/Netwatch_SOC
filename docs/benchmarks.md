# Benchmarks

Throughput, query latency and alert-volume measurements on synthetic traffic, with the commands to reproduce them. For real traffic see [real-traffic-validation.md](real-traffic-validation.md). Back to the [README](../Readme.MD).

## Measured results

Produced by `python benchmark.py` on the machine described below. Re-run it and
you will get numbers of the same shape; absolute throughput is hardware-dependent.

```
Environment : Python 3.13.16, PostgreSQL 16.15, Linux x86_64, single-threaded,
              shared container, database on the same host
Command     : python benchmark.py --iterations 5 --packets 20000
Dataset     : 113,390 packets, 140 alerts, 155 technique links
```

| Claim | Target | Measured | Status |
|---|---|---|---|
| Threat types | 15+ | **18** (all 18 proven by a scenario) | ✅ |
| Protocols inspected | 15+ | **21** | ✅ |
| ATT&CK techniques | 12 | **16** across 9 tactics | ✅ |
| Tables | 8 | **8**, all written by the pipeline | ✅ |
| Indexes | — | **25**, usage asserted by `EXPLAIN` on a 40k-row dataset | ✅ |
| REST endpoints | 14+ | **25** | ✅ |
| Dashboard modules | 8+ | **9** | ✅ |
| Throughput | 5,000 pkt/min | **352,359 pkt/min median = 5,873 pkt/s** (5,646–6,074 pkt/s) | ✅ |
| Query latency | < 50 ms | **p50 0.39 ms · p95 11.85 ms · max 21.01 ms** | ✅ |
| Alert-volume reduction | — | **96.6%** (818 → 28), **0 incidents lost** | ✅ |
| Detection on real traffic | — | **6 / 6** held-out CSE-CIC-IDS2018 attacks; Suricata + ET Open on the same captures: 3 / 6 — [details](real-traffic-validation.md) | ✅ |
| False positives | — | **1.0 per host-hour** on held-out real traffic (CSE-CIC-IDS2018; 507 before fixing the 5 bugs it exposed; Suricata + ET Open severity 1-2: 26.7) — [details](real-traffic-validation.md) | ✅ |

At a larger scale — 256,068 packets and 4,992 alerts, produced by relaxing
detector cooldowns so more real detections are retained — latency stays within
target: **p50 1.55 ms, p95 19.75 ms, p99 22.21 ms, max 27.35 ms**, throughput
315,282 pkt/min median.

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
packets, ending at 106,690 packets. Measured at the time of the migration, with
17 detectors; the headline table above is the current code:

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

This is a real regression and it grows with row count: at 256,068 packets
`/api/stats/overview` is 21.1 ms (p50). It is still **more than 2× inside the
50 ms target**, every endpoint but it, `/api/health` and host detail is under
4 ms, and retention bounds the tables — so it
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
or throttled machine the spread between runs can be wide (here 5,646–6,074
pkt/s across five runs; 4,567–7,555 on an earlier run), so a single figure
without its range says little.

Query latency covers all 22 queries that back the REST API, run against the
dataset the throughput phase actually wrote, reported as p50/p95/p99.

### Alert-volume reduction

The third phase measures how much of the raw detector output the shipped
tuning suppresses, against two explicit baselines on the same workload:

| Baseline | What it is | Result |
|---|---|---|
| Same rules, dedup off | every `cooldown_s` set to 0, **every threshold unchanged** | 818 alerts |
| Shipped tuning | `config.py` as it ships | **28 alerts — 96.6% fewer** |
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
keys. Both resolve to the **same 28 distinct incidents**; the 790 suppressed
alerts are all repeat reports of an incident already raised. `benchmark.py`
exits non-zero if a single incident present in the baseline is missing from
the tuned run.

Severity is triage metadata carried on every alert (here CRITICAL 9, HIGH 13,
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
