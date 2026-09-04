# Resume bullets

Every figure below is a measurement, traceable to a command in
[`VALIDATION.md`](VALIDATION.md) and to a JSON artifact under `results/`. No
placeholder survives.

---

## The three bullets

**NetWatch SOC — Network Detection Platform** | Python, Scapy, Flask,
PostgreSQL, Docker | May 2025 – Present

- Built a detection engine covering **17** threat categories (port scanning,
  brute force, DNS tunneling, C2 beaconing, data exfiltration, lateral
  movement) with per-alert mapping to **15** MITRE ATT&CK techniques across 9
  tactics, validated against **24** replayed attack PCAPs at a **96.2%**
  true-positive rate and 100% precision, with zero false positives over 120,000
  benign packets.
- Implemented a deep-packet-inspection pipeline parsing **21** protocols (TCP,
  UDP, HTTP/S, DNS, TLS, ARP) at a sustained **5,721 packets/sec** on replayed
  capture — median of **10** runs after a discarded warm-up, same 21,338-packet
  PCAP each run.
- Cut alert noise **99%** (6,739 → 36 alerts) through severity scoring and
  per-rule threshold tuning against a benign-traffic baseline, eliminating all
  4,801 baseline false positives while raising true-positive rate from 92.3% to
  96.2%, and surfacing triaged events through **25** REST endpoints and **9**
  live dashboard modules.

---

## Where each number comes from

| Figure | Value | Source |
|---|---|---|
| Threat categories | 17 | `detectors.REGISTRY` |
| ATT&CK techniques | 15, across 9 tactics | `mitre.TECHNIQUES`; all 15 observed in the replay run |
| Attack PCAPs replayed | 24 (18 canonical + 6 evasion) | `pcaps/manifest.json`; 30 files total including 6 benign |
| True-positive rate | 96.15 % (25 TP / 26 expected) | `results/replay.json` → `summary.combined` |
| Precision | 100.00 % (0 false positives) | same |
| Benign false positives | 0 over 120,000 packets | `summary.alerts_on_benign_captures` |
| Protocols parsed | 21 | `ProtocolAnalyzer.SUPPORTED_PROTOCOLS` |
| Throughput | 5,720.9 pkt/s median | `results/benchmark.json` → `throughput.pipeline_packets_per_s.median` |
| Benchmark runs | 10 measured, 1 warm-up discarded | `throughput.measured_runs` / `warmup_runs` |
| Alerts before tuning | 6,739 | `results/noise.json` → `delta.alerts_before` |
| Alerts after tuning | 36 | `delta.alerts_after` |
| Noise reduction | 99.47 % | `(6739 − 36) / 6739 × 100` |
| Baseline false positives removed | 4,801 → 0 | `delta.benign_alerts_before` / `_after` |
| REST endpoints | 25 under `/api/` | `App.py` route table |
| Dashboard modules | 9 | `<section id="view-…">` in the template |

---

## Rounding

- **96.2%** ← 96.15 %, one decimal.
- **5,721 packets/sec** ← 5,720.9, nearest whole packet.
- **99%** ← 99.47 %. Rounded *down* to the whole percent, and the raw counts
  (6,739 → 36) are given alongside so the exact figure is recoverable. Writing
  "99.5%" would round up and read as precision the experiment does not warrant.

---

## What these bullets deliberately do not say

Worth knowing before an interview, because each of these is the first question
a technically sharp reader will ask.

**"24 replayed attack PCAPs" is a synthetic corpus.** The frames are real wire
format with correct checksums, Scapy writes and reads real libpcap files, and
the round trip is asserted byte-identical — so the parsing and detection logic
is genuinely exercised. What is modelled rather than captured is the traffic
*mix*. The bullet says "replayed attack PCAPs", which is accurate; it does not
claim they came from a production network, because they did not.

**96.2% is the combined figure, and it is the honest one.** The 18 canonical
attacks score 100%, which mostly proves the pipeline is wired up — those
scenarios were written to be detectable. The 6 evasion variants (a scan paced
across windows, a beacon with heavy jitter, a tunnel split across short labels,
a transfer spread over five peers) score 85.7%, and that is the number with
information in it. Quoting the 100% alone would be technically true and
misleading.

**One detection is missed, on purpose and on the record.** A C2 beacon with
±45% jitter is not detected: coefficient-of-variation scoring cannot see
through that much jitter, and loosening the threshold far enough made benign
traffic alert. A test asserts it stays missed so the documented limitation
cannot go stale.

**"Cut alert noise 99%" needs its caveat.** 89% of that reduction comes from
three rules whose untuned forms are unusable rather than merely noisy —
"one source contacted 10 distinct hosts in 60 seconds" fires on every browsing
workstation. Tuning made three broken rules work; it did not shave a
percentage off a working system. If asked, the better number is the
false-positive rate: 400.08 → 0.00 per 10,000 benign packets. The bullet leads
with the raw counts for that reason.

**The pre-tuning baseline was chosen carefully, and an earlier version was
wrong.** Setting every cooldown to zero made each rule alert once per
qualifying packet and produced a 99.98% reduction that measured nothing but the
absence of deduplication. The baseline now carries a flat 30-second dedup timer
on every rule, a test enforces it, and all 68 differing configuration values
are printed by `config.profile_diff('untuned')`.

**Throughput is single-threaded, outside Docker, on one idle machine.**
5,721 pkt/s is what this CPU did with nothing else running. The same benchmark
under load — a gunicorn pool, a busy PostgreSQL and a Docker daemon competing
for four cores — gave 3,801 pkt/s, 34% lower, and reported a higher *parse*
cost despite the parser being identical. The figure also drifts downward across
the runs inside one invocation, from 7,030 to 5,144, because each run appends
to the same store. The methodology transfers; the number is a statement about
a machine at a moment. On PostgreSQL the same capture runs at 5,186 pkt/s —
about 9% slower, the price of a round trip per batch in exchange for concurrent
writers.

**Docker images were not built during validation.** The registry CDN is blocked
by the environment's egress policy. The compose topology was verified by
running the same processes directly against PostgreSQL — `engine.py` as the
writer, gunicorn with 4 workers as the readers, all 25 endpoints and all 9
dashboard modules — and by static packaging tests. No figure in the bullets was
taken inside a container.

---

## Optional variants

**If a shorter second bullet is needed** (drops the methodology clause):

> Implemented a deep-packet-inspection pipeline parsing 21 protocols (TCP, UDP,
> HTTP/S, DNS, TLS, ARP) with sustained throughput of 5,721 packets/sec on
> replayed PCAP capture, measured as the median of 10 runs.

**If the reader is likely to distrust a 99% figure**, lead with the rate:

> Cut benign-traffic false positives from 400 to 0 per 10,000 packets (a 99%
> reduction in total alert volume, 6,739 → 36) through severity scoring and
> per-rule threshold tuning, while raising true-positive rate from 92.3% to
> 96.2%.

**If space allows one extra clause on the first bullet**, the evasion split is
the most credible thing in the project:

> …validated against 24 replayed attack PCAPs at a 96.2% true-positive rate —
> 100% on canonical attacks, 85.7% on threshold-evasion variants — with zero
> false positives over 120,000 benign packets.
