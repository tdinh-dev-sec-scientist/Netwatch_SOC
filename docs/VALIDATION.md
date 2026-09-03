# NetWatch SOC — validation report

Every number in this document was produced by running the commands shown, on
the environment described below, against the corpus whose digest is recorded.
Nothing is estimated, extrapolated or carried over from a previous run.

Where a result is weaker than it looks, or could not be verified at all, it
says so — see [Limitations](#limitations), which is the part worth reading
before the headline figures.

Reproduce everything:

```bash
pip install -r requirements.txt
python -m tools.make_pcaps          # build the corpus (57 MB, ~40 s)
pytest -q                           # 360 tests
python -m tests.replay              # detection quality
python -m tools.noise_experiment    # alert-noise reduction
python benchmark.py --runs 11 --warmup 1 --packets 20000   # throughput
```

---

## Environment

| | |
|---|---|
| OS | Ubuntu 24.04.4 LTS, Linux 6.18.44 x86_64 |
| CPU | Intel Xeon @ 2.80 GHz, 4 vCPU |
| RAM | 15 GB |
| Python | 3.11.15 |
| Scapy | 2.7.0 |
| Flask | 3.1.3 |
| psycopg | 3.3.5 |
| PostgreSQL | 16.13 (server and client) |
| SQLite | 3.45.1 |
| pytest | 9.1.1 |
| Docker | 29.3.1, Compose 5.1.1 |

Benchmarks were run **outside Docker**, directly on the host, single-threaded.
The Docker images could not be built in this environment (see
[Limitations](#limitations)), so no in-container figure is reported rather than
a guessed one.

---

## Architecture counts

Each of these is derived from the code at runtime, not from documentation, and
asserted by a test.

| Claim | Measured | Where it comes from | Test |
|---|---|---|---|
| Threat categories | **17** | `detectors.REGISTRY` | `test_registry_covers_at_least_fifteen_threat_types` |
| MITRE ATT&CK techniques | **15** across 9 tactics | `mitre.TECHNIQUES` | `test_every_catalogued_technique_is_reachable_from_a_detector` |
| Protocols with field extraction | **21** | `ProtocolAnalyzer.SUPPORTED_PROTOCOLS` | `tests/test_protocol_analyzer.py` (44 tests) |
| REST endpoints | **25** under `/api/` | `App.py` route table | `test_all_registered_routes_are_covered_by_tests` |
| Dashboard modules | **9** | `<section id="view-…">` in the template | `test_at_least_eight_modules_exist` |
| Database tables | **9** | `DB_Manager.TABLES` | `test_schema_has_exactly_nine_tables` |
| Indexes | **24** (SQLite) / **36** (PostgreSQL) | catalog introspection | `test_index_count_is_substantial` |

The target counts in the project brief were 15 threat categories, 12
techniques, 15 protocols, 14 endpoints and 8 dashboard modules. Every one is
met or exceeded by the actual implementation; the figures above are the real
ones, not the targets.

---

## Detection coverage

### 17 threat categories

Each is one module under `detectors/`, tuned by one section of `config.py`, and
declares the ATT&CK techniques it can emit.

| Detector | Signal | ATT&CK |
|---|---|---|
| `port_scan` | Distinct destination ports on one host, over a 60 s burst window **or** a 900 s slow window | T1046 |
| `network_recon` | Many hosts inside one /24 on a narrow port set; ICMP echo sweep | T1595 |
| `brute_force` | In-protocol auth failures (FTP 530, SMTP 535, POP3 `-ERR`, IMAP `NO`, HTTP 401), over a 120 s or a 900 s window; SSH session bursts | T1110, T1078 |
| `credential_attack` | Many usernames from one source; one username across many hosts; cleartext credentials | T1110, T1078 |
| `c2_beacon` | Coefficient of variation of inter-arrival times on one channel | T1071.001 |
| `dns_tunnel` | Oversized label **or** a run of encoded labels, plus entropy / TXT-NULL-ANY / volume | T1071.004, T1048 |
| `suspicious_dns` | NXDOMAIN ratio; repeated high-entropy SLD lookups | T1071.004 |
| `icmp_tunnel` | Oversized, high-entropy echo payloads, repeated | T1572, T1048 |
| `protocol_tunnel` | L7 identified by signature on a mismatched port | T1572 |
| `tls_anomaly` | Obsolete version, absent SNI, tiny cipher list (scored together) | T1573 |
| `data_exfil` | Outbound internal→external bytes, per destination **or** totalled per source across peers | T1041 |
| `lateral_movement` | Internal→internal admin-service fan-out | T1021 |
| `syn_flood` | SYN rate **and** SYN:completed-handshake ratio, over a 10 s or a 60 s window | T1498 |
| `udp_flood` | UDP packet rate to one destination | T1498 |
| `amplification` | Response:request byte ratio on NTP / DNS / SNMP | T1498.002 |
| `http_anomaly` | SQLi / traversal / XSS / command injection / JNDI / scanner UA | T1190 |
| `arp_spoof` | IP↔MAC binding conflict; gratuitous ARP flood | T1557.002 |

### 15 ATT&CK techniques

`mitre.py` is the single source of truth and is loaded into the
`mitre_techniques` table at startup. Every technique carries a written
rationale explaining why the network evidence corresponds to it, served by
`/api/mitre/techniques` and shown in the dashboard, so a mapping can be audited
rather than trusted.

Two invariants are enforced by tests: no technique is catalogued that no
detector can raise, and the engine refuses to start if a detector names a
technique that is not in the catalog.

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

All 15 were observed in the replay run below — no technique is catalogued but
unreachable.

### 21 protocols

Identification is **signature-first**: a protocol on a non-standard port is
still named correctly, and flags `nonstandard_port`, which is what feeds the
tunnelling detector. Port numbers only choose which decoder to *attempt*; every
decoder validates the bytes before claiming the protocol.

Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS, SSH, FTP, SMTP,
POP3, IMAP, SNMP, NTP, TELNET, SMB, RDP, DHCP, QUIC — 21 named in
`SUPPORTED_PROTOCOLS`, each with real field extraction rather than a
layer-presence check. `tests/test_protocol_analyzer.py` asserts the extracted
fields for each, plus entropy, malformed frames and truncated upper layers.

19 of the 21 appeared in the benchmark capture; DHCP and IPv6 are exercised by
the unit tests rather than by the traffic mix.

---

## PCAP replay validation

```bash
python -m tools.make_pcaps
python -m tests.replay --json results/replay.json
```

### Corpus

Built by `tools/make_pcaps.py` and written through Scapy as real libpcap files.
Generation is seeded, so re-running reproduces the files byte-for-byte, and
`pcaps/manifest.json` records a SHA-256 per file. Corpus identifier for this
run: `manifest:0f29a94022a78222`.

| Class | Files | Packets | Ground truth |
|---|---|---|---|
| `attack/` | 18 | 32,624 | the threat type(s) the scenario exhibits |
| `evasion/` | 6 | 14,635 | the same threat, shaped to sit under a threshold |
| `benign/` | 6 | 120,000 | no alerts at all |
| **Total** | **30** | **167,259** | |

Attack and evasion captures embed the attack in benign background traffic of
the same span, which is the shape a real capture has — not an isolated attack
against silence.

### Scoring

The unit is one **(capture, threat_type)** pair:

- **TP** — an expected threat type was raised on a capture that contains it
- **FN** — an expected threat type was not raised
- **FP** — a threat type was raised that the capture is not ground-truthed for;
  on a benign capture, every distinct threat type raised is one FP

```
true-positive rate = TP / (TP + FN)
precision          = TP / (TP + FP)
```

Counting distinct types rather than raw alerts is deliberate: a detector that
fires four times during a four-minute port scan has made one detection, not
four, and raw counts would let one noisy detector on one capture swamp the
score. Alert volume is reported separately and is what the noise experiment
works on.

Each capture is replayed with a fresh analyzer, a fresh detector set and a
fresh database, so no state leaks between files.

### Results

| | Primary (18 attack + 6 benign) | Evasion (6) | Combined (30) |
|---|---|---|---|
| Packets | 152,624 | 14,635 | 167,259 |
| Expected detections | 19 | 7 | 26 |
| True positives | 19 | 6 | 25 |
| False positives | 0 | 0 | 0 |
| False negatives | 0 | 1 | 1 |
| **True-positive rate** | **100.00 %** | **85.71 %** | **96.15 %** |
| **Precision** | **100.00 %** | 100.00 % | **100.00 %** |
| Alerts raised | 26 | 10 | 36 |
| Parse errors | 0 | 0 | 0 |

**Alerts raised on the benign baseline: 0, across 120,000 packets from six
independent seeds.**

17 of 17 threat types and 15 of 15 ATT&CK techniques were exercised.

#### Per-capture

All 18 canonical attack captures and all 6 benign captures passed. Of the six
evasion captures, five were detected and one was not:

| Evasion capture | Expected | Detected | Note |
|---|---|---|---|
| `slow_port_scan` | `port_scan` | yes | caught by the 900 s window; confidence capped at 0.85 |
| `slow_brute_force` | `brute_force`, `credential_attack` | yes | caught by the 900 s window |
| `throttled_syn_flood` | `syn_flood` | yes | caught by the 60 s window, handshake-ratio guard intact |
| `fragmented_dns_tunnel` | `dns_tunnel` | yes | caught by the encoded-label-run condition |
| `distributed_exfil` | `data_exfil` | yes | caught by the per-source byte total across peers |
| `jittered_beacon` | `c2_beacon` | **no** | **known miss — see below** |

#### The known miss

`jittered_beacon` is a C2 channel checking in every ~45 s with ±45 % jitter.
`c2_beacon` scores the coefficient of variation of inter-arrival times, and at
that much jitter the CV is indistinguishable from ordinary chatty traffic.
Loosening `max_jitter_ratio` far enough to catch it made benign traffic alert,
so it was not loosened. Catching this needs a different signal — consistent
payload size, channel longevity, or destination reputation — not a different
threshold.

This is asserted by `test_high_jitter_beacon_is_a_known_miss`, so if a future
change does catch it the test fails and this section gets corrected rather
than quietly going stale.

#### A ground-truth correction

The `brute_force` scenario originally listed only `brute_force` as expected,
and the run reported one false positive: `credential_attack` firing on the same
capture. On inspection the detector was right and the label was wrong —
guessing an FTP password necessarily sends that password in cleartext, so the
traffic genuinely is both a brute-force attempt and a credential exposure, and
an analyst should see both alerts.

The ground truth was corrected to list both. Before the correction the primary
corpus scored 19 TP / 1 FP / 0 FN — precision 94.74 %, TPR 100 %. Both numbers
are given so the correction can be judged rather than taken on trust.

---

## Alert-noise reduction

```bash
python -m tools.noise_experiment --json results/noise.json --show-diff
```

The same 30-capture corpus is replayed twice, once under
`config.PROFILES['untuned']` and once under the shipped defaults. Both runs
execute identical code down identical paths; the only difference is
configuration, and `config.profile_diff('untuned')` prints all **68 values**
across **17 sections** that differ.

### The pre-tuning profile

`UNTUNED` is meant to be a plausible first pass, not a worst case — the
measurement is only worth something if what it improves on is something a
competent engineer would actually have written. Every difference is one of
three kinds, annotated inline in `config.py`:

- **[T]** a textbook threshold, taken from what the technique looks like in
  isolation rather than from what benign traffic does
- **[C]** a single-signal rule: the detector alerts on its primary indicator
  without requiring a second, independent one
- **[D]** one flat 30-second dedup timer on every rule, rather than a cooldown
  matched to each behaviour's timescale

The **[D]** choice matters and is worth stating. An earlier version of this
experiment set every cooldown to zero, which made each rule alert once per
qualifying packet and produced a 99.98 % reduction that measured nothing but
the absence of deduplication. A test now enforces that the untuned profile
deduplicates.

### Results

| | untuned | tuned | reduction |
|---|---|---|---|
| Alerts, all 30 captures | 6,739 | 36 | **99.47 %** |
| Alerts on benign traffic | 4,801 | **0** | **100.00 %** |
| Alerts on attack traffic | 1,938 | 36 | 98.14 % |
| False positives per 10k benign packets | 400.08 | 0.00 | |
| True positives | 24 | **25** | |
| True-positive rate | 92.31 % | **96.15 %** | |

```
reduction = (alerts_before - alerts_after) / alerts_before * 100
          = (6739 - 36) / 6739 * 100
          = 99.47 %
```

Detection was **not** traded for quiet: every threat type detected under the
untuned profile is still detected under the tuned one, and the tuned profile
detects one more (the slow port scan, which the untuned profile's missing
long-window signal cannot see). The experiment exits non-zero if a detection
is ever lost.

### Where the reduction comes from

A single headline percentage says nothing about whether the improvement is
broad or the work of one pathological rule, so the report attributes it:

| Rule | Alerts removed | Share of the reduction |
|---|---|---|
| `network_recon` | 2,578 | 38.46 % |
| `lateral_movement` | 1,792 | 26.73 % |
| `c2_beacon` | 1,592 | 23.75 % |
| `port_scan` | 393 | 5.86 % |
| `dns_tunnel` | 334 | 4.98 % |

Three rules account for 89 % of it, and in each case the naive form is
genuinely unusable rather than merely noisy:

- **`network_recon`** untuned is "one source contacted 10+ distinct hosts in
  60 s", with no /24 clustering and no narrow-port-set requirement. Every
  browsing workstation trips it continuously.
- **`lateral_movement`** untuned alerts on a single internal admin-port
  connection, so every SMB session to the file server is an alert.
- **`c2_beacon`** untuned needs four callbacks at up to 35 % jitter with no
  minimum interval, so ordinary request/response chatter reads as beaconing.

That is the honest shape of this result: threshold tuning did not shave a
percentage off a working system, it made three unusable rules usable. A
reader who wants the conservative number should take the false-positive rate —
400.08 to 0.00 per 10,000 benign packets — rather than the volume percentage.

---

## Throughput benchmark

```bash
python benchmark.py --runs 11 --warmup 1 --packets 20000 --query-repeats 30 \
    --json results/benchmark.json
```

### Methodology

- One capture is written once and **replayed byte-identically by every run**.
  The capture is built from a fixed epoch and a fixed seed, so its digest is
  reproducible across invocations and machines:
  **21,338 packets, 720.6 s span, `sha256 733406817c39404f`**.
- Every run uses the same configuration (`config.DEFAULTS`).
- **11 runs; the first is discarded as warm-up** (cold page cache, cold
  allocator); 10 are measured.
- The reported statistic is the **median** of the measured runs — median rather
  than mean so one scheduling hiccup cannot move the headline. A test asserts
  the reported figure really is the median of the per-run values printed
  beside it.
- Two rates are reported because they answer different questions:
  - **pipeline** — parse → detect → batched persistence, over frames already
    in memory. This is the DPI pipeline's own rate.
  - **replay** — the same work with Scapy reading each frame off disk. This is
    what an end-to-end PCAP replay sustains.
- Run outside Docker, single-threaded, on the environment described above.

### SQLite (default backend)

| Run | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| pipeline pkt/s | 4,190 | 4,290 | 4,071 | 4,011 | 3,703 | 3,740 | 3,861 | 3,625 | 3,656 | 3,721 |
| replay pkt/s | 3,892 | 3,505 | 3,547 | 3,558 | 3,363 | 3,149 | 3,324 | 3,321 | 3,239 | 3,191 |

| | median | mean | min | max | stdev |
|---|---|---|---|---|---|
| **pipeline** | **3,800.8 pkt/s** | 3,886.9 | 3,625.3 | 4,290.0 | 237.8 |
| **replay** | **3,343.6 pkt/s** | 3,408.9 | 3,149.1 | 3,892.3 | 222.3 |

Median pipeline rate is **3,800.8 packets/sec** (228,048 packets/min).
Per packet: 46.8 µs parse + 32.1 µs detect. Parse errors: 0.

### PostgreSQL (deployment backend)

| Run | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| pipeline pkt/s | 3,416 | 3,407 | 3,484 | 3,460 | 3,574 | 3,590 | 3,438 | 3,594 | 3,410 | 3,323 |

| | median | mean | min | max | stdev |
|---|---|---|---|---|---|
| **pipeline** | **3,449.0 pkt/s** | 3,469.4 | 3,322.8 | 3,593.5 | 90.6 |
| **replay** | **3,090.0 pkt/s** | 3,062.5 | 2,961.9 | 3,175.4 | 74.7 |

PostgreSQL costs about 9 % of pipeline throughput against SQLite on the same
capture, which is the price of a network round trip per batch in exchange for
concurrent writers. The variance is markedly lower.

### Query latency

All 22 queries that back the REST API, run 30 times each against the dataset
the throughput phase actually wrote (469,436 packets, 9,169 flows, 711 hosts,
528 alerts, 594 technique links).

| Backend | p50 | p95 | p99 | max |
|---|---|---|---|---|
| SQLite | 0.293 ms | 1.017 ms | 2.710 ms | 3.184 ms |
| PostgreSQL | 0.636 ms | 8.977 ms | 45.823 ms | 54.966 ms |

Both meet the < 50 ms p95 budget. The PostgreSQL tail is one query — see the
next section.

### A scaling fix found by this benchmark

The first PostgreSQL run put `/api/stats/overview` at **51 ms p50**, over the
50 ms budget on its own. The cause was two unbounded counts in
`get_overview()`: `COUNT(*) FROM packets`, and an hour-windowed count that at
this dataset size covers most of the table anyway. Both are now answered from
the `protocol_stats` rollup, which holds one row per (minute, protocol) and is
asserted to agree with the packet table by
`test_protocol_stats_rollup_matches_packets`.

| | before | after |
|---|---|---|
| `overview` p50, PostgreSQL | 51.1 ms | 3.9 ms |
| overall p95, PostgreSQL | 42.1 ms | 9.0 ms |
| overall p95, SQLite | 2.7 ms | 1.0 ms |

`test_overview_total_packets_agrees_with_the_packet_table` guards the shortcut:
the optimisation is only valid while the rollup and the table agree.

---

## Database

Nine tables, all written by the pipeline or the validation harness.

| # | Table | Purpose |
|---|---|---|
| 1 | `packets` | every processed packet with its decoded L7 summary |
| 2 | `connections` | flow records keyed on the 5-tuple, upserted per batch |
| 3 | `hosts` | host inventory, geo enrichment, rollup counters, threat score |
| 4 | `alerts` | detector findings with JSON evidence |
| 5 | `mitre_techniques` | ATT&CK catalog, seeded from `mitre.py` |
| 6 | `alert_techniques` | many-to-many alert↔technique with confidence |
| 7 | `protocol_stats` | per-minute protocol rollup backing the charts and the KPI counters |
| 8 | `performance_metrics` | measured engine and benchmark throughput/latency |
| 9 | `validation_runs` | PCAP replay and tuning results (TP/FP/FN, TPR) |

Tables 1–8 are asserted populated by the live pipeline
(`test_all_pipeline_tables_are_actually_populated`); table 9 is written by the
replay and tuning harnesses and round-tripped by
`test_validation_runs_round_trip`.

Both backends run the same schema, rendered through `db_dialects.py`. Index
usage is asserted, not assumed: `test_hot_queries_use_an_index` runs the
backend's own planner over the hot queries and fails on a full scan.

**There is deliberately no `threats` table.** A "threat" is an aggregation over
alerts grouped by `(src_ip, threat_type)`, derived by `get_threat_summary()`
with an indexed query. Materialising it would duplicate what `alerts` holds.

---

## REST API — 25 endpoints

Every endpoint was exercised against a live PostgreSQL-backed deployment
(gunicorn, 4 workers): **25/25 returned 200**, plus the dashboard route.

| Method | Route | Function |
|---|---|---|
| GET | `/api/health` | schema, index count, row counts, engine state, backend |
| GET | `/api/stats/overview` | live counters |
| GET | `/api/stats/throughput` | packets/bytes per minute, `?minutes=` |
| GET | `/api/stats/protocols` | traffic by protocol, `?minutes=` |
| GET | `/api/stats/severity` | alert counts by severity, `?hours=` |
| GET | `/api/stats/timeline` | severity timeline, `?hours=`, `?bucket_s=` |
| GET | `/api/alerts` | filter by severity, type, source, ack state; paginated |
| GET | `/api/alerts/<id>` | detail + techniques + related packets |
| POST | `/api/alerts/<id>/acknowledge` | acknowledge an alert |
| GET | `/api/alerts/stats` | grouped by threat type |
| GET | `/api/threats/summary` | aggregated per source + threat type |
| GET | `/api/threats/types` | detector catalog joined with live counts |
| GET | `/api/mitre/techniques` | catalog + observed counts |
| GET | `/api/mitre/techniques/<id>` | detail, detectors, recent alerts |
| GET | `/api/mitre/coverage` | grouped by tactic |
| GET | `/api/hosts/top` | top talkers, `?order=` |
| GET | `/api/hosts/<ip>` | protocols, peers, alerts for one host |
| GET | `/api/geo` | country rollup |
| GET | `/api/connections` | flow table, `?order&src_ip&limit` |
| GET | `/api/packets` | packet log, `?protocol&src_ip&dst_ip&malicious_only` |
| GET | `/api/performance` | measured history + live counters |
| GET | `/api/detectors` | per-detector counters |
| GET | `/api/protocols` | supported protocols + parse counts |
| GET | `/api/scenarios` | replay corpus ground truth, attack vs evasion |
| GET | `/api/validation` | recorded replay and tuning results |

Invalid parameters return 400 with a message; unknown resources return 404. All
filters are parameterised — `test_sql_injection_in_filters_is_parameterised`
confirms injection attempts are treated as literal values. An empty database
returns empty collections, never filler.

---

## Dashboard — 9 modules

Verified in a real browser (headless Chromium) against the PostgreSQL
deployment. All nine modules rendered with no page errors and no panel left in
its loading state.

| # | Module | Backing endpoints |
|---|---|---|
| 1 | Threat Overview | `/api/stats/overview`, `/api/stats/throughput`, `/api/stats/severity`, `/api/threats/summary`, `/api/alerts` |
| 2 | Recent Alerts | `/api/alerts` |
| 3 | Threat Distribution | `/api/threats/types`, `/api/alerts/stats` |
| 4 | MITRE ATT&CK Coverage | `/api/mitre/coverage`, `/api/mitre/techniques` |
| 5 | Protocol Analysis | `/api/stats/protocols`, `/api/protocols` |
| 6 | Source / Destination IP Analysis | `/api/hosts/top`, `/api/geo`, `/api/connections` |
| 7 | Activity Trends | `/api/stats/timeline`, `/api/stats/throughput` |
| 8 | Detection Performance | `/api/performance`, `/api/health`, `/api/validation` |
| 9 | Live Packet Log | `/api/packets` |

Module 8 now renders the measured replay and tuning results — true-positive
rate, precision, captures replayed, benign false positives, known misses, and
the before/after alert volumes. When nothing has been recorded it says so
rather than showing a figure nothing measured.

`test_no_hardcoded_sample_data` enforces that no module ships seeded values.

### A fault found by this verification

Chart.js is loaded from a CDN, and `Chart.defaults` was assigned at script
scope. When that fetch fails — an offline host, a restrictive egress policy, a
CSP — the assignment threw and aborted the rest of the inline script, taking
the navigation handlers and *every* data loader with it: a completely blank
dashboard, not merely a chartless one. The library is now probed before use and
a missing one costs the charts alone; the canvases say why they are empty.
Verified by loading the dashboard with the CDN unreachable.

---

## Docker

`docker compose up -d --build` runs PostgreSQL, a dedicated engine container
(the writer) and replicated API workers (the readers). The split is the reason
for PostgreSQL: SQLite's single-writer constraint forces engine and API into
one process, which the `sqlite` profile still offers for a demo.

| Profile | Command |
|---|---|
| default | `docker compose up -d --build` |
| `sqlite` | `docker compose --profile sqlite up -d` |
| `test` | `docker compose --profile test run --rm tests` |
| `bench` | `docker compose --profile bench run --rm benchmark` |
| `validate` | `docker compose --profile validate run --rm validate` |

**The images could not be built in this environment** — see
[Limitations](#limitations). What was verified instead:

- `docker compose config` parses and validates the whole file.
- `tests/test_packaging.py` (22 tests) checks what a failed build would have
  caught: every shipped module is copied into the runtime stage, nothing copied
  is missing, `.dockerignore` excludes nothing that is copied, every
  third-party import is declared in `requirements.txt`, the healthchecks expect
  the right table count, PostgreSQL publishes no port, and the API binds only
  to loopback. Every shipped module is also imported.
- The PostgreSQL topology itself was run directly on the host, exactly as the
  containers invoke it: `python engine.py` as the writer (3,443 packets
  processed, 0 parse errors) and `gunicorn --config gunicorn.conf.py` with
  4 workers as the readers, serving all 25 endpoints and all 9 dashboard
  modules against the same database.

Hardening in the compose file: non-root, read-only root filesystem, all Linux
capabilities dropped, `no-new-privileges`, no host networking, no published
database port, API bound to `127.0.0.1`.

---

## Test results

```bash
pytest -q                                                    # SQLite
NETWATCH_TEST_DB_URL=postgresql://… pytest -q                # PostgreSQL
```

| Backend | Total | Passed | Failed | Skipped | Time |
|---|---|---|---|---|---|
| SQLite | 360 | **360** | 0 | 0 | 55.5 s |
| PostgreSQL | 360 | **359** | 0 | 1 | 59.8 s |

The single skip is `test_wal_mode_enabled`, which asserts a SQLite journal mode
that has no PostgreSQL equivalent.

| File | Tests | Covers |
|---|---|---|
| `test_detectors.py` | 79 | every detector fires on its scenario; negative cases; evasion variants; thresholds; state bounding; detector isolation |
| `test_api.py` | 69 | every endpoint, schemas, pagination, 400/404, SQL injection |
| `test_protocol_analyzer.py` | 44 | every protocol, entropy, malformed and truncated input |
| `test_database.py` | 36 | 9 tables, rollup consistency, index usage, latency, transactionality |
| `test_dashboard.py` | 30 | each module wired to a working endpoint, escaping, no mock data, CDN resilience |
| `test_noise.py` | 29 | reduction arithmetic, both config profiles, no detection lost to tuning |
| `test_packaging.py` | 22 | image contents, dependencies, healthchecks, port exposure |
| `test_replay.py` | 15 | scoring arithmetic, corpus determinism, state isolation, persistence |
| `test_benchmark.py` | 12 | capture reproducibility, median reporting, warm-up handling, targets |
| `test_pcap_io.py` | 12 | byte-identical PCAP round trip, streaming, corpus manifest |
| `test_mitre.py` | 12 | catalog integrity, no orphans, no invented IDs, database linkage |

---

## Limitations

These are the things a reviewer should weigh against the numbers above.

**Traffic is synthetic.** `frames.py` emits real wire-format Ethernet with
correct IPv4/TCP/UDP/ICMP checksums and conformant DNS/TLS/SNMP/DHCP encodings,
Scapy writes and reads real libpcap files, and the analyzer decodes them with
no knowledge of their origin — so the parsing and detection logic is genuinely
exercised, and the round trip is asserted byte-identical. What is *modelled*
rather than captured is the **traffic mix**. The 0-false-positive result is
against that model. Validating against real captured traffic is the next step
and would very likely require re-tuning thresholds.

**A 100 % true-positive rate on the canonical corpus is a weak claim on its
own.** Those 18 scenarios were written to be detectable, and detecting them
mostly proves the pipeline is wired up. The evasion corpus exists because of
that: it is the number that carries information, and it is 85.71 %. The
combined 96.15 % is the figure worth quoting.

**The noise-reduction percentage is dominated by three rules.** 89 % of the
reduction comes from `network_recon`, `lateral_movement` and `c2_beacon`, whose
untuned forms are unusable rather than merely noisy. The percentage is real and
reproducible, but "cut alert noise 99 %" oversells what tuning did across the
detector set as a whole. The false-positive rate — 400.08 to 0.00 per 10,000
benign packets — is the more conservative and more informative statement.

**Docker images were not built.** The registry CDN
(`production.cloudfront.docker.com`) is blocked by this environment's egress
policy, which returns 403 to the CONNECT. The Dockerfile and compose topology
are therefore verified by static checks and by running the same processes
directly against PostgreSQL, not by a container run. Nothing in this document
claims a measurement taken inside a container.

**`/api/health` does not scale.** It reports exact row counts for all nine
tables, which means an unbounded `COUNT(*)` over `packets`. At 469k packets
that is 42 ms immediately after a bulk load and 25 ms after `VACUUM ANALYZE` —
within budget, but linear in table size, and it is polled every 30 s by the
container healthcheck. Capped or estimated counts would fix it; not done,
because the endpoint's contract is exact counts.

**High-jitter C2 beaconing is not detected.** See the known miss above. This is
a limitation of coefficient-of-variation scoring, not a tuning choice.

**Throughput is single-threaded and hardware-dependent.** The benchmark reports
what this machine measured. A different CPU will give a different number; the
methodology, not the figure, is what transfers.

**Geo enrichment is a static prefix table**, not MaxMind. `geoip.py` returns
`UNKNOWN` rather than guessing, and the dashboard labels it approximate. The
high-risk country list is a crude proxy, not threat intelligence.

**SSH brute force is inferred, not observed.** Authentication happens inside
the encrypted channel; the detector counts cleartext version banners, which is
the standard network-side signal, and caps its confidence at 0.85 accordingly.

**No accuracy figure is claimed.** Accuracy needs labelled ground truth across
both classes. What is measured here is detection of known scenarios and a
false-positive count on a benign corpus. Those two numbers are reported and
nothing is extrapolated from them.

**The API has no authentication or rate limiting.** Ports bind to `127.0.0.1`
by default. Put a reverse proxy in front for TLS and authn before changing
that.

**There is no migration tooling.** The schema is applied with
`CREATE TABLE IF NOT EXISTS` at startup, which is adequate while changes are
additive. A column type change would need a real migration.
