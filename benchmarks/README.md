# benchmarks/

Measurement scripts that substantiate the numbers in `docs/RESUME_METRICS.md`.
`benchmark.py` at the repository root covers burst throughput and query latency;
these three cover what it does not.

| Script | Answers |
|---|---|
| `soak.py` | Does the pipeline hold its rate, and drop nothing, under sustained load? |
| `index_ab.py` | What do the 24 indexes actually buy, at scale? |
| `fp_check.py` | Do the detectors stay silent on benign traffic across many seeds? |

```bash
# sustained load: exact drop accounting, throughput drift, RSS, state growth
python benchmarks/soak.py --minutes 10 --db /tmp/soak.db

# index A/B — build a large dataset first, then measure with and without indexes
python benchmark.py --iterations 10 --packets 30000 --db /tmp/scale.db --keep-db
python benchmarks/index_ab.py --db /tmp/scale.db

# false-positive control across 8 seeds
python benchmarks/fp_check.py
```

`soak.py` writes roughly 0.5 GB per 10 minutes; point `--db` at a volume with room.

`index_ab.py` must drop the indexes *after* `DatabaseManager.__init__` has run,
because `init_schema()` re-applies `CREATE INDEX IF NOT EXISTS`. Dropping them
on the file beforehand measures the indexed path twice and reports a 1.0×
speed-up.
