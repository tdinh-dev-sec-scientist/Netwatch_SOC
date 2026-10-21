# NetWatch — a network intrusion detection system, tested on real attacks

[![CI](https://github.com/tdinh-dev-sec-scientist/Netwatch_SOC/actions/workflows/ci.yml/badge.svg)](https://github.com/tdinh-dev-sec-scientist/Netwatch_SOC/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-16%20techniques-C8102E)

A student project in detection engineering. NetWatch reads raw network
packets, decodes them with deep packet inspection over 21 protocols, runs 18
behavioural detectors mapped to MITRE ATT&CK, correlates the alerts into
incidents, and serves them to an analyst dashboard — all in Python, on
PostgreSQL.

What makes it more than a lab exercise: I tested it on **31 million packets of
real, labelled attack traffic** ([CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html)),
found out it was badly wrong, fixed it, and measured it again on traffic it had
never seen — next to Suricata, an industry-standard IDS, on the same packets.

**[Live demo →](https://netwatch-soc-demo.onrender.com)** read-only, replaying
45 minutes of real attack traffic in a loop.

**Demo video (2 min):** a walkthrough of the dashboard on the replayed traffic —
posture, the alert queue, a SQL injection alert with the request that fired it,
top talkers, decoded packets, the 18 detectors and the pipeline.

[![NetWatch SOC — 2-minute demo walkthrough](docs/images/demo-video.png)](docs/media/netwatch-demo.mp4)

![Alert queue: real detections from the CSE-CIC-IDS2018 replay, each mapped to ATT&CK techniques](docs/images/alert-queue.png)

---

## Results on real traffic

Scored against the dataset's ground truth. *Held-out* traffic was only
replayed after the code was frozen, so these are not numbers I tuned toward.

| On held-out real traffic (6 attacks, 82 host-hours) | NetWatch | Suricata + ET Open rules |
|---|---|---|
| Attacks detected | **6 / 6** | 3 / 6 |
| False alerts per host per hour | **1.0** | 26.7 (severity 1-2) · 3,296 (all rules) |
| False incidents per host per day | **10** | 372 (severity 1-2) |

How it got there, in three rounds:

| | First version | Round 1: five bugs fixed | Round 2: four blind spots closed |
|---|---|---|---|
| Attacks detected (development set) | 16 / 18 | 11 / 18 | **18 / 18** |
| False alerts per host per hour | 375 | 1.1 | **1.1** |

- **The first version was unusable on real traffic** — one false alert every
  ten seconds per host — even though it scored zero false positives on my
  synthetic tests. 99.7% of the noise came from five logic bugs, not bad
  thresholds; for example, Windows RDP wraps its sessions in TLS, which my
  tunnelling detector read as an attacker hiding traffic.
- **Fixing the bugs made detection *drop* (16 → 11)**, because one of them had
  been "detecting" a botnet for the wrong reason. I kept the honest number.
- **Round 2 added detection for what was still invisible** — HTTP floods,
  Slowloris, login-form brute force and a botnet polling its C2 server every
  second — with thresholds set between measured benign and attack traffic.
- **Suricata's signatures win where a signature exists** (it caught a reverse
  shell NetWatch has no signal for); behaviour-based detection wins on floods,
  brute force and C2 timing. They are complementary, not competitors.

Full write-up, every false positive traced to a cause:
**[docs/real-traffic-validation.md](docs/real-traffic-validation.md)**

---

## At a glance

| | | |
|---|---|---|
| Protocols inspected | L2-L7, identified by byte signature rather than port | **21** |
| Threat types | one detector each, all proven by a synthetic attack scenario | **18** |
| ATT&CK techniques | across 9 tactics, each with a written rationale | **16** |
| Tables | PostgreSQL, all written by the pipeline | **8** |
| Indexes | usage checked with `EXPLAIN` in the test suite | **25** |
| REST endpoints | Flask, parameterised queries, read-only demo mode | **25** |
| Throughput | parse + detect + batched PostgreSQL writes, one thread | **5,873** packets/s |
| Query latency | p95 across the 22 queries behind the API | **11.9** ms |
| Tests | PostgreSQL and SQLite in CI, plus a Docker smoke test | **392** |

## How it works

```mermaid
flowchart LR
    A["pcap / pcapng file<br/>or traffic simulator"] --> B["ProtocolAnalyzer<br/>deep packet inspection"]
    B --> C["ThreatDetector<br/>18 detectors"]
    C --> D[("PostgreSQL<br/>8 tables")]
    D --> E["Flask REST API<br/>+ incident correlation"]
    E --> F["Analyst dashboard"]
    D --> G["Splunk via HEC"]
```

1. **Parse.** `ProtocolAnalyzer` walks each frame from Ethernet up to the
   application layer — DNS, HTTP, TLS (with SNI), SSH, SMB, RDP and more —
   naming protocols by their bytes, so SSH hidden on port 443 is still SSH.
2. **Detect.** Every parsed packet goes to every detector. Each keeps a small
   sliding-window state (ports per source, failures per service, request
   timing) and raises a finding with severity, confidence, evidence and
   ATT&CK techniques. Cooldowns stop one attack from raising thousands of
   duplicates.
3. **Store.** Packets, flows, hosts, alerts and technique links are written
   to PostgreSQL in one transaction per batch.
4. **Triage.** The API groups alerts on the same pair of hosts into incidents,
   so an analyst sees one SSH brute force rather than dozens of alerts about it.

## What it detects

| Detector | Signal | ATT&CK |
|---|---|---|
| `port_scan`, `network_recon` | Many ports on one host; many hosts in one /24; ICMP sweeps | T1046, T1595 |
| `brute_force`, `credential_attack` | Login failures (FTP, SMTP, POP3, IMAP, HTTP 401); SSH and login-form bursts; many usernames from one source | T1110, T1078 |
| `c2_beacon` | Metronomic callbacks (low timing jitter); an internal host polling one external URL | T1071.001 |
| `dns_tunnel`, `suspicious_dns` | Oversized high-entropy DNS labels; NXDOMAIN storms; DGA-like names | T1071.004, T1048 |
| `icmp_tunnel`, `protocol_tunnel` | Data hidden in ping payloads; a protocol on the wrong port | T1572, T1048 |
| `tls_anomaly` | Obsolete TLS, missing SNI, tiny cipher lists from internal clients | T1573 |
| `data_exfil` | Large outbound volume to one external host | T1041 |
| `lateral_movement` | One internal host fanning out over SMB, RDP or WinRM | T1021 |
| `syn_flood`, `udp_flood`, `amplification` | Half-open SYNs; UDP packet rate; reflected response ratios | T1498, T1498.002 |
| `http_flood` | HTTP request floods; Slowloris-style unfinished requests | T1499.002 |
| `http_anomaly` | SQL injection, XSS, path traversal, Log4Shell, scanner user agents | T1190 |
| `arp_spoof` | IP-to-MAC binding conflicts; gratuitous ARP floods | T1557.002 |

Every threshold lives in `config.py` and can be overridden with a JSON file —
no code changes.

## Screenshots

<p>
  <img src="docs/images/attack-coverage.png" alt="ATT&CK coverage matrix shaded by alerts seen" width="49%">
  <img src="docs/images/posture.png" alt="Posture view: traffic, alerts over time and severity mix" width="49%">
</p>

## Run it

PostgreSQL is the database; the bundled compose file starts one.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker compose up -d postgres
export DATABASE_URL=postgresql://netwatch:netwatch@localhost:5432/netwatch

python App.py                    # dashboard on http://127.0.0.1:5001, simulated traffic
pytest                           # the test suite
```

Replay real traffic instead of simulating it:

```bash
# the 45-minute sample the public demo runs
NETWATCH_REPLAY_PCAP=demo/cicids2018-sample.pcap.gz NETWATCH_BACKFILL_MIN=45 python App.py

# or analyse any capture offline and get the alerts as JSON lines
python replay.py capture.pcap --alerts alerts.jsonl
```

No PostgreSQL? `DB_BACKEND=sqlite python App.py` runs everything on a local
file. More options: [docs/development.md](docs/development.md).

## Built with

Python 3 (standard library for parsing and detection — no Scapy), Flask,
PostgreSQL 16 with psycopg 3, Chart.js, Docker, GitHub Actions, Render.
Evaluated with CSE-CIC-IDS2018 and Suricata 7 with the ET Open ruleset;
alerts forward to Splunk over HEC ([integrations/splunk](integrations/splunk/README.md)).

```
ProtocolAnalyzer.py   deep packet inspection
detectors/            one module per threat family
ThreatDetector.py     runs every detector over every packet
incidents.py          alert-to-incident correlation
DB_Manager.py         all SQL; migrations/ holds the schema
App.py                Flask API and dashboard
replay.py             pcap/pcapng replay through the real pipeline
eval/cicids2018/      dataset fetch, ground truth, scoring, Suricata runner
tests/                392 tests, run against real PostgreSQL
```

## What I learned

- **Synthetic tests prove the code does what I meant, not that what I meant is
  right.** My generator could only produce traffic I had already imagined;
  real traffic had Windows RDP sessions, ECN-flagged TCP handshakes and
  internet scanners I had never thought about.
- **A false positive is a bug report.** Tracing each one to its cause found
  real logic errors. Raising thresholds would have hidden them.
- **Measure on data you have not looked at.** The held-out sets are what make
  the final numbers believable — including to me.
- **Signature and behaviour detection need each other.** Suricata caught what
  NetWatch could not, and the reverse.

## Limitations

It is a learning project, and its numbers come with fine print: one 2018 lab
network, six held-out attacks, a single-threaded Python engine, no
authentication outside the read-only demo, and two dataset attacks aimed at a
closed port that NetWatch reports as SYN floods (which is what the wire shows).
The full list is in [docs/limitations.md](docs/limitations.md).

## Documentation

| | |
|---|---|
| [Real-traffic validation](docs/real-traffic-validation.md) | Method, every round, every false positive, the Suricata comparison |
| [Design](docs/design.md) | Pipeline, detectors, protocol decoders, ATT&CK mapping, dashboard |
| [Database](docs/database.md) | Schema, type choices, indexes, migrations |
| [REST API](docs/api.md) | All 25 endpoints |
| [Benchmarks](docs/benchmarks.md) | Throughput, latency and alert-reduction measurements |
| [Development](docs/development.md) | Setup, tests, containers, CI |
| [Demo deployment](docs/demo-deployment.md) | The Render deployment and its threat model |
