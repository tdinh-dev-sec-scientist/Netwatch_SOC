# NetWatch SOC — Network Threat Detection Platform

A network detection platform: deep packet inspection over 21 protocols,
17 modular threat detectors mapped to MITRE ATT&CK, PCAP replay validation with
measured true-positive and false-positive rates, an indexed 9-table store on
PostgreSQL or SQLite, a 25-endpoint REST API and a 9-module analyst dashboard.

Every number below was measured on this machine by a command you can re-run.
Where a result is weaker than it looks, it says so. The full working —
methodology, per-run figures, ground truth and limitations — is in
[`docs/VALIDATION.md`](docs/VALIDATION.md).

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python App.py                     # dashboard + live simulation → http://127.0.0.1:5001
pytest                            # 360 tests
python -m tools.make_pcaps        # build the PCAP corpus (once, ~40 s)
python -m tests.replay            # detection quality: TP/FP/FN, TPR, precision
python -m tools.noise_experiment  # alert-noise reduction, untuned vs tuned
python benchmark.py               # throughput + query latency
```

`NETWATCH_SIMULATE=0 python App.py` runs the API without generating traffic.

With Docker:

```bash
docker compose up -d --build              # PostgreSQL + engine + API workers
docker compose --profile test run --rm tests
docker compose --profile validate run --rm validate
```

---

## Architecture

```
 PCAP file ─┐                                                        ┌─► REST API ─► Dashboard
            ├─► pcap_io ─► ProtocolAnalyzer ─► ThreatDetector ─► DB_Manager        (25 endpoints,
 live NIC ──┘   (scapy)     21 protocols       17 detectors      9 tables            9 modules)
                            field extraction   severity +        PostgreSQL
 frames.py ─┘                                  ATT&CK mapping    or SQLite
```

Scapy owns the boundary with the wire — PCAP read/write and live sniffing — but
not decoding. `ProtocolAnalyzer` parses raw bytes itself, so a frame is decoded
identically whether it came from a capture file, an interface or the traffic
generator, and swapping the source changes nothing downstream:

```python
from pcap_io import live_sniffer
live_sniffer(lambda frame, ts: simulator.process(frame, ts), iface='eth0').start()
```

A capture written and read back is asserted byte-identical, which is what lets
the corpus double as ground truth.

### Data flow for one packet

1. **Parse** — `ProtocolAnalyzer.parse()` walks Ethernet → IPv4/IPv6/ARP →
   TCP/UDP/ICMP → L7, returning a flat dict of extracted fields.
2. **Detect** — `ThreatDetector.analyze()` feeds it to all 17 detectors. Each
   keeps bounded sliding-window state and returns `Finding` objects with
   severity, confidence, evidence and ATT&CK technique IDs.
3. **Persist** — `PacketSimulator` buffers, then `persist_batch()` writes the
   whole batch in one transaction: packet rows, flow upserts, host upserts, the
   protocol rollup, alerts and alert↔technique links.
4. **Serve** — Flask endpoints query the store; the dashboard renders it.

Nothing in the hot path issues a query or an HTTP call.

### Files

| File | Role |
|---|---|
| `pcap_io.py` | Scapy capture layer: PCAP read/write, live sniffer |
| `frames.py` | Wire-format frame construction |
| `ProtocolAnalyzer.py` | Deep packet inspection: 21 protocols |
| `detectors/` | 17 detectors, one module per threat family |
| `ThreatDetector.py` | Engine: registry, dispatch, state expiry, introspection |
| `mitre.py` | ATT&CK catalog with a written rationale per technique |
| `DB_Manager.py` | 9-table schema, batched writes, all read queries |
| `db_dialects.py` | Everything that differs between PostgreSQL and SQLite |
| `config.py` | Every threshold, plus the documented pre-tuning profile |
| `PacketSimulator.py` | Traffic generation, 24 attack scenarios, engine loop |
| `App.py` | Flask app, 25 REST endpoints |
| `engine.py` | Headless writer process for the split deployment |
| `benchmark.py` | Throughput and query-latency measurement |
| `tools/make_pcaps.py` | Builds the PCAP corpora and their manifest |
| `tools/noise_experiment.py` | Untuned vs tuned alert-volume measurement |
| `tests/replay.py` | PCAP replay scoring: TP/FP/FN, TPR, precision |

---

## Measured results

Ubuntu 24.04, Python 3.11.15, Scapy 2.7.0, Intel Xeon @ 2.80 GHz (4 vCPU),
outside Docker. Full methodology in [`docs/VALIDATION.md`](docs/VALIDATION.md).

### Detection quality — `python -m tests.replay`

30 PCAPs, 167,259 packets, corpus `manifest:0f29a94022a78222`.

| | Canonical attacks + benign | Evasion variants | Combined |
|---|---|---|---|
| Captures | 24 | 6 | 30 |
| Expected detections | 19 | 7 | 26 |
| TP / FP / FN | 19 / 0 / 0 | 6 / 0 / 1 | 25 / 0 / 1 |
| **True-positive rate** | **100.00 %** | **85.71 %** | **96.15 %** |
| **Precision** | 100.00 % | 100.00 % | **100.00 %** |

**Zero alerts on 120,000 benign packets** across six independent seeds.

The evasion corpus is the number that carries information. A canonical attack
corpus alone mostly proves the pipeline is wired up, so there is a second
corpus of the same attacks paced or split to sit under a threshold: a scan at
one port every 12 s, a tunnel split across short labels, a transfer spread over
five peers. Five of those six gaps were closed with detection work — a second
time scale for `port_scan`, `brute_force` and `syn_flood`, a multi-label
encoding condition for `dns_tunnel`, a per-source byte total for `data_exfil` —
not by loosening thresholds; the benign baseline still raises nothing.

The sixth is a **known miss**: a beacon with ±45 % jitter. Coefficient-of-
variation scoring cannot see through that much jitter, and loosening it far
enough made benign traffic alert. A test asserts it stays a miss, so the
limitation cannot go stale.

### Throughput — `python benchmark.py --runs 11 --warmup 1`

One capture (21,338 packets, `sha256 733406817c39404f`) replayed by every run
under one configuration. 11 runs, the first discarded as warm-up, **median** of
the remaining 10.

| Backend | pipeline (parse+detect+persist) | replay (incl. Scapy PCAP read) |
|---|---|---|
| SQLite | **3,800.8 pkt/s** (3,625–4,290, σ 238) | 3,343.6 pkt/s |
| PostgreSQL | **3,449.0 pkt/s** (3,323–3,594, σ 91) | 3,090.0 pkt/s |

Per packet: 46.8 µs parse + 32.1 µs detect. Zero parse errors.

Query latency over the 22 queries backing the API, against the 469,436-packet
dataset the throughput phase wrote: **p50 0.29 ms / p95 1.02 ms** (SQLite),
**p50 0.64 ms / p95 8.98 ms** (PostgreSQL). Both under the 50 ms budget.

### Alert noise — `python -m tools.noise_experiment`

Same corpus replayed under `config.PROFILES['untuned']` and under the shipped
defaults. Identical code; 68 configuration values differ.

| | untuned | tuned | reduction |
|---|---|---|---|
| Alerts, all captures | 6,739 | 36 | **99.47 %** |
| Alerts on benign traffic | 4,801 | **0** | 100.00 % |
| False positives / 10k benign packets | 400.08 | **0.00** | |
| True positives | 24 | **25** | |
| True-positive rate | 92.31 % | **96.15 %** | |

Detection was not traded for quiet: nothing detected under the untuned profile
is lost, and the tuned profile detects one more. The experiment exits non-zero
if a detection is ever lost.

**Read this figure carefully.** 89 % of the reduction comes from three rules
(`network_recon`, `lateral_movement`, `c2_beacon`) whose untuned forms are
unusable rather than merely noisy — "one source contacted 10 hosts in 60 s"
fires on every browsing workstation. Tuning made three broken rules work; it
did not shave a percentage off a working system. The false-positive rate,
400.08 → 0.00 per 10,000 benign packets, is the more informative statement.

---

## Detection engine — 17 threat categories

Each detector lives in its own module under `detectors/`, declares the ATT&CK
techniques it can emit, and is tuned by one section of `config.py`. Adding a
category means adding a class and one line in `detectors/__init__.py`.

Every finding carries: threat type, severity, confidence, a written reason,
source/destination and ports, protocol, timestamp, structured evidence, the
detector's rule id, and its ATT&CK technique IDs.

| Threat category | Signal | ATT&CK |
|---|---|---|
| `port_scan` | Distinct ports on one host — 60 s burst **or** 900 s slow window | T1046 |
| `network_recon` | Many hosts in one /24 on a narrow port set; ICMP sweep | T1595 |
| `brute_force` | In-protocol auth failures over 120 s or 900 s; SSH session bursts | T1110, T1078 |
| `credential_attack` | Many usernames from one source; one username across hosts; cleartext creds | T1110, T1078 |
| `c2_beacon` | Coefficient of variation of inter-arrival times | T1071.001 |
| `dns_tunnel` | Oversized label **or** encoded-label run, plus entropy / TXT-NULL-ANY / volume | T1071.004, T1048 |
| `suspicious_dns` | NXDOMAIN ratio; repeated high-entropy SLD lookups | T1071.004 |
| `icmp_tunnel` | Oversized high-entropy echo payloads, repeated | T1572, T1048 |
| `protocol_tunnel` | L7 identified by signature on a mismatched port | T1572 |
| `tls_anomaly` | Obsolete version, absent SNI, tiny cipher list (scored together) | T1573 |
| `data_exfil` | Outbound bytes per destination **or** totalled per source across peers | T1041 |
| `lateral_movement` | Internal→internal admin-service fan-out | T1021 |
| `syn_flood` | SYN rate **and** SYN:handshake ratio, over 10 s or 60 s | T1498 |
| `udp_flood` | UDP packet rate to one destination | T1498 |
| `amplification` | Response:request byte ratio on NTP / DNS / SNMP | T1498.002 |
| `http_anomaly` | SQLi / traversal / XSS / command injection / JNDI / scanner UA | T1190 |
| `arp_spoof` | IP↔MAC binding conflict; gratuitous ARP flood | T1557.002 |

### What the detectors deliberately do *not* alert on

Thresholds were tuned against a benign corpus and the negative cases are tested
(`tests/test_detectors.py`):

- Long, numerous CDN hostnames — **not** DNS tunnelling.
- Three-label domains like `static1.assets.cdn.example.com` — **not** a
  multi-label encoded tunnel.
- High SYN volume that completes its handshakes — **not** a flood, at either
  time scale.
- Large inbound downloads — **not** exfiltration (direction is checked).
- Ordinary browsing across many networks — **not** a sweep (targets must
  cluster in one /24).
- Repeated access to a single file server — **not** lateral movement.
- Service replies fanning out across ephemeral ports — **not** a port scan.

Every threshold is configurable without touching detection logic:

```bash
NETWATCH_CONFIG=thresholds.json python App.py
# {"port_scan": {"distinct_ports": 30}, "c2_beacon": {"max_jitter_ratio": 0.08}}

NETWATCH_PROFILE=untuned python -m tests.replay   # score the pre-tuning posture
```

---

## MITRE ATT&CK — 15 techniques across 9 tactics

`mitre.py` is the single source of truth and is loaded into the
`mitre_techniques` table at startup. Every technique carries a written
**rationale** for why the network evidence corresponds to it; it is served by
the API and shown in the dashboard, so a mapping can be audited rather than
taken on trust.

Two invariants are enforced by tests: no technique is catalogued that no
detector can raise, and the engine refuses to start if a detector names a
technique missing from the catalog.

Reconnaissance (T1595) · Initial Access (T1190) · Defense Evasion (T1078) ·
Credential Access (T1110, T1557.002) · Discovery (T1046) · Lateral Movement
(T1021) · Command and Control (T1071.001, T1071.004, T1572, T1573) ·
Exfiltration (T1041, T1048) · Impact (T1498, T1498.002).

All 15 were observed in the replay run.

---

## Deep packet inspection — 21 protocols

Identification is **signature-first**: a protocol running on a non-standard
port is still named correctly (and flags `nonstandard_port`, which feeds the
tunnelling detector). Ports only choose which decoder to *attempt*; every
decoder validates the bytes before claiming the protocol.

| Layer | Protocols | Examples of what is extracted |
|---|---|---|
| L2 | Ethernet, ARP | MACs, ethertype, opcode, sender/target bindings, gratuitous flag |
| L3 | IPv4, IPv6 | addresses, TTL/hop limit, protocol, ID, flags, fragment offset, flow label |
| L4 | TCP, UDP, ICMP | ports, flags, seq/ack, window, type/code, echo id/seq, payload length |
| L7 | DNS, HTTP, TLS, SSH, FTP, SMTP, POP3, IMAP, SNMP, NTP, TELNET, SMB, RDP, DHCP, QUIC | qname/qtype/rcode/label entropy, method/URI/Host/UA/status/auth, SNI/version/cipher count, banners, commands and response codes, BER-decoded community strings, monlist flags, dialects, cookies |

Shannon entropy is computed for every payload and drives the tunnelling and
exfiltration detectors. `parse()` raises `ParseError` on frames too short or
malformed to yield a usable L3 record; truncated *upper* layers degrade
gracefully with a `truncated` flag.

---

## Database — 9 tables, two backends

PostgreSQL is the deployment target; SQLite is the zero-dependency default used
by the tests and the benchmark. One schema is rendered through `db_dialects.py`,
which isolates everything that actually differs: placeholder style, identity
columns, 8-byte floats, scalar `MIN`/`MAX`, conflict-ignore inserts, catalog and
plan introspection.

```bash
NETWATCH_DB_URL=postgresql://netwatch:…@postgres:5432/netwatch python App.py
NETWATCH_DB=/data/netwatch.db python App.py            # SQLite
NETWATCH_TEST_DB_URL=postgresql://… pytest -q          # run the suite on Postgres
```

| # | Table | Purpose |
|---|---|---|
| 1 | `packets` | every processed packet with its decoded L7 summary |
| 2 | `connections` | flow records keyed on the 5-tuple, upserted per batch |
| 3 | `hosts` | host inventory, geo enrichment, rollup counters, threat score |
| 4 | `alerts` | detector findings with JSON evidence |
| 5 | `mitre_techniques` | ATT&CK catalog (reference table) |
| 6 | `alert_techniques` | many-to-many alert↔technique with confidence |
| 7 | `protocol_stats` | per-minute rollup backing the charts and the KPI counters |
| 8 | `performance_metrics` | measured engine and benchmark throughput/latency |
| 9 | `validation_runs` | PCAP replay and tuning results (TP/FP/FN, TPR) |

24 indexes on SQLite, 36 on PostgreSQL. Index usage is **tested, not assumed** —
`test_hot_queries_use_an_index` runs the backend's own planner and fails on a
full scan. Batched writes: one transaction per batch, which is the single
largest throughput factor.

`protocol_stats` is a genuine rollup, not a convenience copy: it keeps the
charts *and* the KPI counters off the packet table. Moving two unbounded counts
onto it took `/api/stats/overview` from 51 ms to 3.9 ms on PostgreSQL at 469k
packets.

---

## REST API — 25 endpoints

All read from the database. An empty database returns empty collections, never
filler. Invalid parameters return 400 with a message; unknown resources return
404. All filters are parameterised, and
`test_sql_injection_in_filters_is_parameterised` confirms injection attempts
are treated as literal values.

Health · overview · throughput · protocol stats · severity · timeline · alert
list, detail, acknowledge and stats · threat summary and catalog · ATT&CK
techniques, technique detail and coverage · top hosts · host detail · geo ·
connections · packets · performance · detectors · protocols · replay-corpus
scenarios · **validation results**.

The full table with parameters is in [`docs/VALIDATION.md`](docs/VALIDATION.md).

---

## Dashboard — 9 modules

Every module fetches from the API; `test_no_hardcoded_sample_data` enforces
that none ships seeded values.

1. **Threat Overview** — KPIs, throughput, severity mix, active threats
2. **Recent Alerts** — filterable queue, acknowledge, technique chips
3. **Threat Distribution** — alerts by type + the full detector catalog
4. **MITRE ATT&CK Coverage** — matrix by tactic, click through to a technique
5. **Protocol Analysis** — traffic by protocol + DPI coverage
6. **Source / Destination IP Analysis** — talkers, threat scores, geography, flows
7. **Activity Trends** — stacked severity timeline, byte volume
8. **Detection Performance** — measured throughput, query latency, DB health,
   **and the PCAP-replay validation results**: TPR, precision, benign false
   positives, known misses, before/after alert volumes
9. **Live Packet Log** — decoded L7 fields per packet

Module 8 shows what was measured or says nothing has been — an unvalidated
deployment looks unvalidated. Charts come from a CDN, and a blocked CDN costs
the charts alone; the rest of the dashboard keeps working.

---

## Testing

```bash
pytest -q                                     # 360 tests on SQLite
NETWATCH_TEST_DB_URL=postgresql://… pytest -q # the same suite on PostgreSQL
```

**360 passed on SQLite; 359 passed, 1 skipped on PostgreSQL** (the skip is a
SQLite journal-mode assertion with no PostgreSQL equivalent).

| File | Tests | Covers |
|---|---|---|
| `test_detectors.py` | 79 | every detector, negative cases, evasion variants, state bounding |
| `test_api.py` | 69 | every endpoint, schemas, pagination, 400/404, SQL injection |
| `test_protocol_analyzer.py` | 44 | every protocol, entropy, malformed and truncated input |
| `test_database.py` | 36 | 9 tables, rollup consistency, index usage, latency, transactionality |
| `test_dashboard.py` | 30 | modules wired to working endpoints, escaping, CDN resilience |
| `test_noise.py` | 29 | reduction arithmetic, both profiles, no detection lost to tuning |
| `test_packaging.py` | 22 | image contents, dependencies, healthchecks, port exposure |
| `test_replay.py` | 15 | scoring arithmetic, corpus determinism, state isolation |
| `test_benchmark.py` | 12 | capture reproducibility, median reporting, warm-up handling |
| `test_pcap_io.py` | 12 | byte-identical PCAP round trip, streaming, manifest |
| `test_mitre.py` | 12 | catalog integrity, no orphans, no invented IDs |

---

## Honest limitations

The full list is in [`docs/VALIDATION.md`](docs/VALIDATION.md#limitations). The
ones that matter most:

- **Traffic is synthetic.** The frames are real wire format and the PCAPs are
  real libpcap files, so the parsing and detection logic is genuinely
  exercised — but the *traffic mix* is a model of an enterprise network, not a
  capture of one. The zero-false-positive result is against that model.
  Validating on real captured traffic would likely require re-tuning.
- **100 % on the canonical corpus is a weak claim on its own.** Those scenarios
  were written to be detectable. The evasion result (85.71 %) and the combined
  figure (96.15 %) are the informative ones.
- **The 99.47 % noise reduction is dominated by three rules.** See the caveat
  above; the false-positive rate is the better statement.
- **Docker images were not built here** — the registry CDN is blocked by this
  environment's egress policy. The compose topology was verified by running the
  same processes directly against PostgreSQL, and by static packaging tests.
- **High-jitter C2 beaconing is not detected**, and `/api/health` does not scale
  (exact `COUNT(*)` over all nine tables).
- **No accuracy figure is claimed.** Accuracy needs labelled ground truth across
  both classes; what is measured is detection of known scenarios and a
  false-positive count on a benign corpus.
- **The API has no authentication or rate limiting.** Ports bind to `127.0.0.1`;
  put a reverse proxy in front before changing that.
