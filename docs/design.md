# Design

How NetWatch is put together: the packet pipeline, the detection engine, deep packet inspection, the ATT&CK mapping and the dashboard. Back to the [README](../Readme.MD).

## Architecture

```
 frames.py ──────► ProtocolAnalyzer ──────► ThreatDetector ──────► DB_Manager ──────► App.py ──────► Dashboard.html
 (or a live       parses raw bytes         18 detectors,           8 tables,          25 REST        9 modules
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
2. **Detect** — `ThreatDetector.analyze()` feeds the parsed packet to all 18
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
| `detectors/` | 18 detectors, one module per threat family |
| `incidents.py` | Alert-to-incident correlation, shared by the API and the evaluation |
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
| `replay.py` | pcap replay through the real pipeline: alerts as JSON lines, or `--persist` into PostgreSQL for the dashboard |
| `eval/cicids2018/` | Fetch, ground truth and scoring for the real-traffic validation |
| `static/vendor/` | Vendored Chart.js, checksum-pinned (no CDN scripts) |
| `render.yaml` | Render Blueprint for the public demo |
| `scripts/smoke_test.sh` | End-to-end checks of the image, compose topologies and demo |


## Detection engine — 18 threat types

Each detector lives in its own module under `detectors/`, declares the ATT&CK
techniques it can emit, and is tuned by one section of `config.py`.

| Threat type | Signal used | ATT&CK |
|---|---|---|
| `port_scan` | Distinct destination ports on one host in a window | T1046 |
| `network_recon` | Many hosts within one /24 on a narrow port set; ICMP sweep | T1595 |
| `brute_force` | In-protocol auth failures (FTP 530, SMTP 535, POP3 `-ERR`, IMAP `NO`, HTTP 401); SSH session bursts; login-form POST bursts | T1110, T1078 |
| `credential_attack` | Many usernames from one source; one username across many hosts; cleartext credentials | T1110, T1078 |
| `c2_beacon` | Coefficient of variation of inter-arrival times on one channel; high-rate polling of one external URL path | T1071.001 |
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
| `http_flood` | HTTP request rate to one service; mass of unfinished request heads (Slowloris) | T1499.002 |
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

**Measured false-positive rate on real traffic: 1.0 alerts per host-hour** on
held-out CSE-CIC-IDS2018 captures, and 1.1 on the development captures — down
from 507 and 375 as first shipped, by fixing five logic bugs the synthetic
corpus could not expose, with no threshold changed. Correlated into incidents
(`/api/incidents`), that is about 10 false incidents per host per day. Every remaining false
positive is traced to a cause in
[docs/real-traffic-validation.md](real-traffic-validation.md). On the
synthetic corpus the rate is 0 across 240,000 benign packets over 8 seeds.

```bash
pytest tests/test_detectors.py::test_no_false_positives_on_benign_background
```

Every threshold is configurable without touching detection logic:

```bash
NETWATCH_CONFIG=thresholds.json python App.py
# {"port_scan": {"distinct_ports": 30}, "c2_beacon": {"max_jitter_ratio": 0.08}}
```


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


## MITRE ATT&CK — 16 techniques

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
| T1499.002 | Service Exhaustion Flood | Impact | `http_flood` |


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
