# NetWatch SOC — Network Threat Detection Platform

A network security monitoring platform: deep packet inspection over 21 protocols,
17 modular threat detectors mapped to MITRE ATT&CK, an indexed 8-table SQLite
store, a 24-endpoint REST API, and a 9-module analyst dashboard.

Every number in this README is measured, and the commands to reproduce each one
are given. Where a number falls short of a target, it says so. The headline
counts are pinned by `tests/test_readme.py`, so the documentation cannot drift
from the code without a test failing.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python App.py                 # dashboard + live simulation → http://127.0.0.1:5001
pytest                        # 264 tests
python benchmark.py           # throughput, latency, alert volume, detection rate
```

`NETWATCH_SIMULATE=0 python App.py` runs the API without generating traffic.

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
4. **Serve** — Flask endpoints query SQLite; the dashboard renders the result.

### Files

| File | Role |
|---|---|
| `frames.py` | Wire-format frame construction (the capture-layer stand-in) |
| `ProtocolAnalyzer.py` | Deep packet inspection: 21 protocols |
| `detectors/` | 17 detectors, one module per threat family |
| `ThreatDetector.py` | Engine: registry, dispatch, state expiry, introspection |
| `mitre.py` | ATT&CK catalog with a written rationale per technique |
| `DB_Manager.py` | 8-table schema, batched writes, all read queries |
| `geoip.py` | Coarse prefix→country enrichment (**not** a geolocation DB) |
| `config.py` | Every detection threshold, overridable via `NETWATCH_CONFIG` |
| `PacketSimulator.py` | Traffic generation, attack scenarios, engine loop |
| `App.py` | Flask app, 24 REST endpoints |
| `benchmark.py` | Reproducible throughput, latency, alert-volume and detection-rate measurement |

---

## Measured results

Produced by `python benchmark.py` on the machine described below. Re-run it and
you will get numbers of the same shape; absolute throughput is hardware-dependent.

```
Environment : Python 3.11.15, Linux x86_64, single-threaded, shared container
Command     : python benchmark.py --iterations 5 --packets 20000
Dataset     : 106,690 packets, 120 alerts, 135 technique links
```

| Claim | Target | Measured | Status |
|---|---|---|---|
| Threat types | 15+ | **17** (all 17 proven by a scenario) | ✅ |
| Protocols inspected | 15+ | **21** | ✅ |
| ATT&CK techniques | 12 | **15** across 9 tactics | ✅ |
| SQLite tables | 8 | **8**, all written by the pipeline | ✅ |
| Indexes | — | **24**, usage asserted by `EXPLAIN QUERY PLAN` | ✅ |
| REST endpoints | 14+ | **24** | ✅ |
| Dashboard modules | 8+ | **9** | ✅ |
| Throughput | 5,000 pkt/min | **222,212–315,115 pkt/min median = 3,704–5,252 pkt/s** across two runs | ✅ |
| Query latency | < 50 ms | **p50 0.15 ms · p95 1.15 ms · max 1.61 ms** | ✅ |
| Detection rate | — | **100%** — 54/54 labelled captures (18 scenarios × 3 seeds) | ✅ |
| Alert-volume reduction | — | **96.1%** (621 → 24), **0 incidents lost** | ✅ |
| False positives | — | **0** across 240,000 benign packets, 8 seeds | ✅ |

At a larger scale — 248,028 packets and 3,776 alerts, produced by relaxing
detector cooldowns so more real detections are retained — latency stays within
target: **p50 0.45 ms, p95 3.63 ms, p99 4.00 ms, max 5.60 ms**, throughput
278,919 pkt/min.

```bash
# reproduce the scale run
python - <<'EOF'
import json, config
json.dump({k: {'cooldown_s': 0} for k, v in config.DEFAULTS.items()
           if isinstance(v, dict) and 'cooldown_s' in v}, open('lowcooldown.json','w'))
EOF
NETWATCH_CONFIG=lowcooldown.json python benchmark.py --iterations 6 --packets 40000
```

Throughput is measured end-to-end — parse **and** detect **and** batched
SQLite persistence — over `--iterations` independent runs, reported as mean,
median, min, max and standard deviation, in **both packets/minute and
packets/second**.

**Do not quote a single throughput figure from this project.** Two runs of the
identical command on the identical container, minutes apart under different
load, measured:

| Run | Median | Range across 5 iterations |
|---|---|---|
| A | 5,252 pkt/s | 4,567 – 7,555 pkt/s |
| B | 3,704 pkt/s | 3,277 – 5,039 pkt/s |

That is a 1.4× swing in the median and 2.3× between the extremes, on the same
code and the same machine. The honest statement is the conservative one — this
pipeline sustains **a few thousand packets/second single-threaded on a shared
container** — and any tighter claim is measuring the machine's spare capacity,
not the code. Run it on your own hardware and quote what you measure, with its
range.

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
python benchmark.py                    # all four phases
python benchmark.py --skip-reduction   # skip the alert-volume phase
```

### Detection rate — 54 labelled captures

The fourth phase scores the engine against ground truth. Every attack scenario
is replayed at several seeds, **embedded in benign background traffic** rather
than run in isolation, and a capture counts as detected only if the threat type
the scenario is *labelled* with fires — an alert of some other type does not
rescue it.

```
captures            : 54 (18 scenarios x 3 seeds, each embedded in 2000 benign packets)
detected            : 54  (100.0%)
every labelled attack detected: MET
```

```bash
python benchmark.py --detection-seeds 5      # 18 scenarios x 5 seeds = 90 captures
```

Two things this number is **not**:

- **It is not an accuracy or true-positive rate.** It is recall against
  labelled scenarios: how many known attacks were caught. Precision would
  require ground truth on the negative class too; what stands in for that here
  is the false-positive count on benign traffic (0 alerts over 240,000
  packets), reported separately and never combined into one headline figure.
- **It is not a measure of coverage against real-world attacks.** The captures
  are this project's own scenarios. 100% means the engine catches every attack
  it was built to catch, at every seed tried — not that it catches every attack
  that exists.

The rate is only meaningful if it can fail, so two tests sabotage a detector's
threshold and assert the phase reports the miss:
`test_detection_rate_reports_a_scenario_it_cannot_catch` and
`test_detection_counts_only_the_labelled_threat_type` — the latter pins the
strictness, because the `brute_force` scenario also raises `credential_attack`,
and that must not count as detecting brute force.

Reproduce with a JSON record:

```bash
python benchmark.py --iterations 5 --packets 20000 --json results.json
```

The benchmark exits non-zero if any of its four gates fails — throughput below
target, p95 query latency above 50 ms, an incident lost to alert suppression,
or a labelled attack missed — so it can gate CI.

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

Every table is written by the live pipeline; this is asserted by
`test_all_eight_tables_are_actually_populated`.

| # | Table | Purpose | Key indexes |
|---|---|---|---|
| 1 | `packets` | Every processed packet with decoded L7 summary | `ts`, `(src_ip,ts)`, `(dst_ip,ts)`, `(protocol,ts)`, `(is_malicious,ts)` |
| 2 | `connections` | Flow records keyed on the 5-tuple, upserted per batch | `last_seen`, `(src_ip,last_seen)`, `bytes` |
| 3 | `hosts` | Host inventory, geo enrichment, rollup counters, threat score | `country`, `packets_sent`, `threat_score` |
| 4 | `alerts` | Detector findings with JSON evidence | `ts`, `(severity,ts)`, `(threat_type,ts)`, `(src_ip,ts)`, `(acknowledged,ts)` |
| 5 | `mitre_techniques` | ATT&CK catalog (reference table) | `tactic` |
| 6 | `alert_techniques` | Many-to-many alert↔technique with confidence | `(technique_id,ts)`, `ts` |
| 7 | `protocol_stats` | Per-minute protocol rollup backing the charts | `bucket` |
| 8 | `performance_metrics` | Measured throughput and query latency | `ts`, `(source,ts)` |

**24 indexes.** WAL journal mode, one long-lived writer connection under a lock
plus thread-local reader connections, and foreign keys enforced.

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
- **Index usage is tested, not assumed** — `test_hot_queries_use_an_index` runs
  `EXPLAIN QUERY PLAN` over the hot queries and fails on a full table scan.

---

## REST API — 24 endpoints

All read from SQLite. Empty database returns empty collections, never filler.
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

```bash
pytest                                  # 264 tests
pytest tests/test_detectors.py -v       # every detector + false-positive control
pytest tests/test_database.py -v        # schema, indexes, query plans, latency
pytest tests/test_benchmark.py -v       # targets met, alert reduction lossless
```

| File | Covers |
|---|---|
| `test_protocol_analyzer.py` | Every protocol, entropy, malformed/truncated input |
| `test_detectors.py` | Each detector fires on its scenario; negative cases; thresholds; state bounding; detector isolation |
| `test_mitre.py` | Catalog integrity, no orphans, no invented IDs, DB linkage |
| `test_database.py` | 8 tables populated, rollup consistency, index usage, <50 ms, transactionality |
| `test_api.py` | All endpoints, schemas, pagination, 400/404, SQL injection |
| `test_dashboard.py` | Each module wired to a working endpoint, escaping, no mock data |
| `test_benchmark.py` | Determinism, targets met, results persisted; alert-reduction baseline is threshold-identical and suppression loses no incident; detection rate scores every scenario and is proven able to report a miss |
| `test_readme.py` | Every headline count in this README matches what the code produces |

Fixtures are seeded (`TrafficGenerator(seed=…)` reproduces byte-identical
traffic), and the attack scenarios double as ground truth: each has a known
expected threat type, asserted end to end.

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
- **No accuracy or true-positive rate is claimed.** Accuracy requires labelled
  ground truth across both classes. What is measured here is a detection rate
  over labelled scenarios (100% of 54 captures) and a false-positive count on a
  benign corpus (0 over 240,000 packets). Both numbers are reported separately
  and nothing is extrapolated from them — in particular they are never blended
  into a single "accuracy" or "true-positive rate" figure, which would imply a
  labelled negative class this project does not have.
- **The dev server is for demonstration.** It binds to `127.0.0.1` by default;
  use a production WSGI server to expose it, and note there is no authentication
  on the API.
