# Limitations

What NetWatch does not do, and where its numbers stop applying. Back to the [README](../Readme.MD).

## Honest limitations

- **Most numbers are from synthetic traffic.** `frames.py` emits real
  wire-format bytes and the analyzer has no privileged knowledge of their
  origin, but the *traffic mix* is a model. The one real-traffic validation,
  [CSE-CIC-IDS2018](real-traffic-validation.md), found that model had
  hidden five bugs worth 375 false positives per host-hour and four attack
  classes it could not see. Both were fixed and re-measured on held-out
  captures, but it is one 2018 lab network with six held-out attacks; a
  different network would surface different problems. Two dataset attacks
  aimed at a closed port are reported as `syn_flood`, which is what the wire
  shows.
- **Geo enrichment is a static prefix table**, not MaxMind. `geoip.py` returns
  `UNKNOWN` rather than guessing, and the dashboard labels it "approximate".
  The high-risk country list is a crude proxy, not threat intelligence.
- **SSH brute force is inferred, not observed.** Authentication happens inside
  the encrypted channel; the detector counts cleartext version banners, which is
  the standard network-side signal, and caps its confidence at 0.85 accordingly.
- **Throughput is single-threaded and hardware-dependent.** The benchmark reports
  what your machine measured, not a fixed figure. The run recorded above spans
  5,646–6,074 pkt/s across five iterations on a shared container; quote the
  median with its range rather than the best iteration.
- **The alert-reduction figure is scoped to deduplication.** Its baseline is
  the same rules with cooldowns disabled, so 96.6% is what per-rule dedup
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
  [docs/demo-deployment.md](demo-deployment.md) lists this and the other
  accepted risks.
