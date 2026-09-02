# Performance engineering log

What was measured, what the profile said, what changed, and what changed as a
result. In order, because the order is the point: nothing here was optimised
before it was shown to be the bottleneck.

Machine for every measurement below: 4 vCPU, 16 GB RAM, Linux 6.18,
CPython 3.11.15, PostgreSQL 16.13 on the same host. PostgreSQL settings at
their defaults unless a step says otherwise. Reproduce with the commands in
[Reproducing](../Readme.MD#reproducing).

---

## Step 0 — baseline

The starting point was a single-threaded loop: parse, detect, buffer, and
write a batch to SQLite every 400 packets.

```
21,338 packets in 4.61s  →  4,629 packets/sec
per packet: 50.0 µs parse + 28.8 µs detect
```

Two thirds of the wall clock was unaccounted for by parse and detect, which
put the rest in SQLite and in the loop itself.

---

## Step 1 — profile the CPU stages

`cProfile` over 21k packets, parsing only:

```
ncalls   tottime  function
 23281     1.397  shannon_entropy          ← 55% of all parse time
2064344   0.168  math.log2
 21338     0.114  parse
```

`shannon_entropy` is called for every packet carrying an L4 payload. It was a
Python loop over every byte of the payload, followed by a 256-iteration loop
computing `p * log2(p)`.

**Change.** Histogram the payload with `numpy.bincount`, and replace the
per-symbol term with a precomputed table of `c * log2(c)` plus the identity

```
H = log2(n) - (1/n) * Σ cᵢ log2(cᵢ)
```

which is the same sum with the division hoisted out. A pure-Python fallback
covers the case where numpy is unavailable.

Verified identical: 3,000 real payloads, zero results differing by more than a
rounding step.

```
entropy:  22.0 µs  →   7.0 µs per call   (3.1×)
parse:    43.4 µs  →  27.4 µs per packet (1.6×)
```

---

## Step 2 — profile the rules stage

```
ncalls   tottime  function
 21338     0.191  RulesEngine.analyze
 42573     0.071  is_internal          (+ 0.057 in its generator expression)
```

Two findings. `is_internal` re-parsed the same few thousand addresses over and
over — memoised, bounded at 65k entries. And `analyze` was calling all 17
detectors for every packet, when most open with a protocol guard and return
immediately.

**Change.** Each detector declares the protocols it can fire on; the engine
caches a per-protocol detector tuple. The guard stays inside `inspect()`, so
the hint can only remove work, never change a verdict.

```
detect:  21.2 µs  →  17.0 µs per packet
```

Detector output is unchanged: the scenario ground-truth tests and the
20k-packet false-positive test both still pass.

---

## Step 3 — the pipeline is slower than the loop it replaced

The first working five-stage pipeline ran at **2,438 packets/sec** — worse
than the single-threaded baseline. Replacing the database with a no-op writer
made it **3,505 packets/sec**, which ruled out PostgreSQL entirely.

The parse stage reported 252 µs of service time per packet against 27 µs
measured standalone, at ~100% of one core. The cost was the producer/consumer
handshake: one `queue.Queue` put and get per packet per boundary is six lock
acquisitions, and once a queue is full, roughly one futex sleep and wake per
packet.

**Change.** Stages exchange *chunks* of packets, not single packets. The
capture stage groups frames into chunks of 256, closing a chunk on size or on a
50 ms age deadline so a quiet pipeline still moves promptly. Queue capacity is
counted in chunks; the flow counters stay in packets, because the loss ledger
has to balance in packets.

```
no-op writer:   3,505  →  12,286 packets/sec
PostgreSQL:     2,438  →   6,638 packets/sec
```

---

## Step 4 — profile the write path

```
cumtime  step
  1.92s  flow upsert
  1.87s  packet COPY
  0.33s  host upsert
```

and inside those, in Python:

```
0.320s  psycopg array dumping (11 parallel lists per flow upsert)
0.316s  l7_summary            (711k `startswith` calls over packet keys)
```

**Changes.**

* Flows go through a session-scoped `TEMP` staging table loaded with `COPY`,
  then one server-side `INSERT ... SELECT ... ON CONFLICT`, instead of eleven
  parallel arrays psycopg has to adapt per batch.
* `l7_summary` memoises the prefix test per field name. Field names come from a
  fixed vocabulary the decoders define, so the scan happens once per distinct
  name rather than once per key per packet.

A separate micro-benchmark isolated where the remaining server-side cost goes,
`COPY` of 20,000 packet rows:

| table configuration | µs/row | rows/sec |
|---|---:|---:|
| bare | 3.5 | 283,000 |
| primary key only | 4.2 | 239,000 |
| + 5 indexes | 12.0 | 83,000 |
| + 3 foreign keys | 24.4 | 41,000 |
| both | 29.7 | 34,000 |

Foreign-key checks cost more than index maintenance — they are per-row
triggers taking a shared lock on the referenced row. Both were kept: the
correctness they buy is worth 30 µs a row when the pipeline's ceiling is set by
Python, not by the database.

---

## Step 5 — the writers deadlocked

With more than one persistence worker, batches began failing:

```
psycopg.errors.DeadlockDetected
9,531 of 21,338 packets counted as write failures
```

Two concurrent batches upserting an overlapping set of hosts acquired row locks
in different orders.

**Change.** Every upsert sorts its rows by the conflict key, so all writers take
locks in the same order. A bounded retry with jittered backoff covers the
residual case, and only retries conditions that mean "nothing committed" —
deadlock, serialization failure, lock timeout. A constraint violation is a bug
and still surfaces.

`tests/test_writer.py::test_concurrent_writers_do_not_deadlock_on_shared_hosts`
is the regression test: four threads, four batches each, over an overlapping
host population.

---

## Step 6 — sweep the configuration

`python -m benchmarks.pipeline_benchmark --sweep` over persistence workers ×
batch size, 31,338 frames per run, zero drops and a balanced ledger throughout:

```
persist=1 batch=2000  ->  7,617 pkt/s
persist=2 batch=2000  ->  7,616 pkt/s   e2e p95 1,121 ms
persist=2 batch=4000  ->  7,123 pkt/s
persist=3 batch=2000  ->  7,336 pkt/s
persist=4 batch=500   ->  5,198 pkt/s
```

More writers past two costs more in GIL contention and lock ordering than it
buys in overlap. Two workers with a batch of 2,000 is the default.

---

## Step 7 — `synchronous_commit`

Letting PostgreSQL acknowledge a commit before the WAL record reaches disk is a
legitimate tuning knob for a telemetry firehose. Measured, 41,338 frames × 3
runs:

| `synchronous_commit` | mean packets/sec |
|---|---:|
| `on` (PostgreSQL default) | 7,767 |
| `off` | 7,223 |

No gain — the difference is inside run-to-run noise, and confirms the pipeline
is bound by Python CPU rather than by WAL flushes. **The default is left at
`on`.** A throughput number bought by weakening durability would need a caveat;
this one does not.

---

## Step 8 — the query side

`python -m benchmarks.query_benchmark` loads a realistic dataset, then times
every query the REST API issues, twice: once with only primary keys, unique
constraints and single-column indexes, and once with the composite indexes
added. Same data, same queries, same process, same order; `ANALYZE` before each
pass so the planner works from fresh statistics; `EXPLAIN` captured for both.

The first run showed the composite indexes doing exactly what they were
designed for on the filtered list endpoints — and made no difference at all to
the pooled p95, because whole-table aggregates dominated the tail:

```
overview             629 ms      ← twelve separate scalar queries, one of them
                                   COUNT(*) over a million packet rows
mitre_coverage       266 ms
threat_type_catalog  233 ms
```

**Change (independent of indexing).** `get_overview` became a single statement
with correlated subqueries — twelve round trips to one — and its two most
expensive counters were re-sourced. `COUNT(*) FROM packets` and
`COUNT(*) FROM packets WHERE ts > …` are both already maintained exactly in the
per-minute `protocol_stats` rollup, written in the same transaction as the
packets themselves, so summing a few dozen rollup rows gives the identical
number. `COUNT(DISTINCT …)` over the alert and technique-link tables became
`EXISTS` probes against the small catalog tables — the same answer read from
the other side of the join. A partial index on open criticals covers the
dashboard's alert counter.

```
overview:  629 ms  →  88 ms
```

Full before/after results are in [Measured results](../Readme.MD#measured-results).
