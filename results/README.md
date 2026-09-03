# Measured results

The raw artifacts docs/VALIDATION.md cites. Each was produced by the command
named in its `methodology` or header block, on the environment recorded in the
file, and is committed so a reader can check the report against the data rather
than taking the report's word for it.

| File | Produced by |
|---|---|
| `replay.json` | `python -m tests.replay --json results/replay.json` |
| `noise.json` | `python -m tools.noise_experiment --json results/noise.json` |
| `benchmark.json` | `python benchmark.py --runs 11 --warmup 1 --packets 20000 --json results/benchmark.json` |
| `benchmark-postgres.json` | the same, with `--db postgresql://…` |

Re-running any of them overwrites the file. Throughput figures are
hardware-dependent and will differ on another machine; the detection and
noise figures are deterministic given the same corpus, whose SHA-256 digests
are in `pcaps/manifest.json`.
