# NetWatch on real traffic: CSE-CIC-IDS2018

Every other number in this project comes from synthetic traffic. This is the
answer to "and on real traffic?": 31 million packets from a labelled public
dataset, replayed through the unmodified pipeline, scored against the
dataset's ground truth, with every false positive traced to a cause and the
same captures run through Suricata with the ET Open ruleset for reference.

## Results

Three rounds, each measured on a development set and then on held-out
captures that were not replayed until that round's code was frozen.

| | As shipped | Round 1: bugs fixed | Round 2: misses closed |
|---|---|---|---|
| **Development** — 18 host captures, 10.0 M packets, 157 host-hours | | | |
| Labelled attacks detected (right type) | 16 / 18 (9) | 11 / 18 (9) | **18 / 18 (17)** |
| False-positive alerts per host-hour | 374.6 | 1.1 | **1.1** |
| False-positive incidents per host-day | 292.1 | 9.9 | **9.9** |
| Alert precision | 3.0% | 65.0% | 73.0% |
| **Held-out 1** — 7 captures, 1.8 M packets, 53 host-hours | | | |
| Labelled attacks detected (right type) | 3 / 4 (3) | 3 / 4 (3) | **4 / 4 (4)** |
| False-positive alerts per host-hour | 506.7 | 1.3 | **1.3** |
| False-positive incidents per host-day | 545.3 | 12.7 | **12.7** |
| **Held-out 2** — 5 captures, 19.5 M packets, 29 host-hours, a host population used nowhere else | | | |
| Labelled attacks detected (right type) | — | — | **2 / 2 (1)** |
| False-positive alerts per host-hour | — | — | **0.4** |
| False-positive incidents per host-day | — | — | **5.8** |

**As shipped, NetWatch was unusable on real traffic**: about one false alert
every ten seconds per host. The synthetic suite's "0 false positives across
240,000 benign packets" said nothing about this, because the synthetic
generator never produced the traffic that caused them.

**Round 1 — five logic bugs, not thresholds, caused 99.7% of them.** No
detection threshold was changed. On the held-out days false positives fell by
the same factor (300-400×) and detection was unchanged, so the fixes
generalise rather than fit the data they came from. Detection on the
development set *fell*, from 16 to 11 of 18, and that was the honest number:
all ten botnet hosts had been "detected" by the port-scan detector misreading
the C2 server's replies as a scan — one of the five bugs.

**Round 2 — closing what was still missed.** Three new signals for the four
attacks NetWatch could not see (application-layer DoS, Slowloris, login-form
brute force, a botnet polling faster than any beacon interval), each with a
threshold set between the busiest benign behaviour and the attack, with a
4-6× margin on both sides. Development detection went to 18 of 18 and the
first held-out set to 4 of 4, with **no new false positives on either**. A
second held-out set, fetched only after the round-2 code was frozen, caught
the HULK flood within 28 seconds as `http_flood` and raised 11 false alerts
in 29 host-hours.

**Incidents are what an analyst works.** `incidents.py` groups alerts on the
same host pair within 30 minutes; on the development set 662 alerts become 167
incidents, and the false ones come to about one per host every two and a half
hours.

Full per-attack tables: [`eval/cicids2018/results/`](../eval/cicids2018/results/).

## Against Suricata

The same captures, ground truth, scoring and incident correlation, applied to
Suricata 7.0.3 with ET Open (54,399 rules, 2024-12-11). Three configurations,
from untouched to the usual first tuning steps (`eval/cicids2018/suricata.py`).
Scoring is in Suricata's favour: its alerts are credited for any attack they
touch, since its signature names do not map onto threat types.

| | Dev: detected | Dev: false alerts / host-hour | Held-out 1+2: detected | Held-out: false alerts / host-hour | Held-out: false incidents / host-day |
|---|---|---|---|---|---|
| **NetWatch (round 2)** | **18 / 18** | **1.1** | **6 / 6** | **1.0** | **10.3** |
| Suricata + ET Open, as distributed | 14 / 18 | 2,777 | 3 / 6 | 3,296 | 1,393 |
| … without engine anomaly events | 4 / 18 | 619 | 3 / 6 | 590 | 1,304 |
| … severity 1-2 only | 4 / 18 | 7.2 | 3 / 6 | 26.7 | 372 |

Held-out = 6 attacks over 82 host-hours (held-out 1 and 2 combined). Per-set
reports: `eval/cicids2018/results/suricata_*`.

What the comparison shows, and does not:

- **Suricata's signatures are precise where a signature exists.** It caught
  the XSS and SQL injection with high-severity web-attack rules, the SSH
  brute force with a scan rule, and the infiltration through its reverse
  shell — a Windows command prompt sent outbound, which NetWatch has no
  signal for. NetWatch caught the same infiltration by its internal nmap
  scan instead.
- **Volume- and behaviour-defined attacks have no signature.** Slowloris,
  GoldenEye, HULK, SlowHTTPTest and the login-form brute force raised no
  alert at all, at any severity; the botnet's C2 polling raised only generic
  severity-3 HTTP-protocol anomaly events, which is how the untuned
  configuration "detects" it.
- **Untuned, the noise is the story**: 437,155 false alerts on the development
  set, 72% of them invalid-checksum events (the captures were taken with
  checksum offload) and 19% "RDP response to external host" policy alerts.
- **This is not a verdict on Suricata.** ET Open is a general ruleset, not
  tuned for this lab; NetWatch's round-2 thresholds were chosen on the
  development set, which is why the held-out columns are the fair comparison.
  The two are complementary: signatures for known exploits, behaviour for
  floods, brute force and C2 timing.

## Dataset

**CSE-CIC-IDS2018** (Canadian Institute for Cybersecurity and the
Communications Security Establishment), the successor to CIC-IDS2017 by the
same lab with the same labelling method. It was chosen over CIC-IDS2017 and
CTU-13 because it is on AWS Open Data (`s3://cse-cic-ids2018`): the other two
are served from university hosts this environment's network policy does not
reach. The victims are real Windows and Ubuntu hosts in AWS with a scripted
benign workload, attacked from external AWS instances on a published schedule.

Each day is one 38-50 GB zip of ~450 per-host pcaps. `fetch.py` reads the
zip's central directory with HTTP range requests and pulls only the members it
needs — 8 GB instead of 400 GB. Some captures are pcapng; `replay.py` reads
both formats.

| Set | Day | Captures | Labelled attacks |
|---|---|---|---|
| dev | Wed 14 Feb | FTP/SSH server `.69.25` | FTP-BruteForce, SSH-Bruteforce |
| dev | Thu 15 Feb | web server `.69.25` | DoS-GoldenEye, DoS-Slowloris |
| dev | Thu 22 Feb | DVWA server `.69.28` | Web brute force, XSS, SQL injection |
| dev | Wed 28 Feb | workstation `.69.24` | Infiltration (dropper, then internal nmap) |
| dev | Fri 2 Mar | 14 workstations | Ares botnet on 10 of them; 4 clean controls |
| held-out 1 | Fri 23 Feb | DVWA server + 1 workstation | Web brute force, XSS, SQL injection |
| held-out 1 | Thu 1 Mar | workstation `.69.13` | Infiltration |
| held-out 1 | Wed 21 Feb | 4 workstations | none (benign) |
| held-out 2 | Fri 16 Feb | web/FTP server `.69.25` (pcapng, 19 M packets) | DoS-Hulk, DoS-SlowHTTPTest |
| held-out 2 | Wed 14 Feb | 4 workstations on the 172.31.64-67 department subnets | none (benign) |

## Method

To browse a capture in the dashboard rather than score it, replay it into
PostgreSQL through the live write path (packets, flows, hosts, rollups,
alerts, technique links), shifted so it ends now:

```bash
DATABASE_URL=postgresql://netwatch:netwatch@localhost:5432/netwatch \
    python replay.py data/cicids2018/Thursday-22-02-2018_UCAP172.31.69.28.pcap \
    --persist --rebase-now
NETWATCH_SIMULATE=0 python App.py
```

Scoring:

```bash
for t in ground_truth holdout holdout2; do
  python eval/cicids2018/fetch.py --out data/cicids2018 --truth eval/cicids2018/$t.json
  python eval/cicids2018/run.py --data data/cicids2018 --out results/$t \
      --truth eval/cicids2018/$t.json
done
# Suricata on the same captures (rules: suricata-update, or the copy in the
# jasonish/suricata image at /var/lib/suricata/rules/suricata.rules)
python eval/cicids2018/suricata.py --data data/cicids2018 --rules suricata.rules \
    --out results/suricata-dev --captures results/ground_truth/captures.json
```

- **Replay.** `replay.py` reads each pcap and pushes every frame through the
  same `ProtocolAnalyzer.safe_parse` → `ThreatDetector.analyze` path as live
  traffic, on the capture's own clock, so windows and cooldowns behave as they
  would have live. One detector instance per host capture: each is a separate
  sensor.
- **Ground truth.** Attacker, victim and time window for each attack, from the
  dataset's published schedule (lab local time is UTC−4 in the captures).
  Every attacker address was confirmed in the pcaps with `talkers.py`: it is
  the dominant external talker to its victim inside its window and absent
  outside it. Windows are padded 10 minutes each side.
- **True positive:** inside a window, linking attacker and victim in either
  direction — or, for infiltration, raised from the compromised host towards
  an internal address with one of the expected threat types. **Everything else
  is a false positive against the labels**, including alerts on real attacks
  the dataset does not label (see below).
- **Detected** means at least one true-positive alert; **right type** means
  one of them was of an expected threat type. The botnet counts once per
  infected host.
- **False positives per host-hour** = false-positive alerts ÷ the summed
  duration of all host captures. It is per sensor-hour, not per network-hour.
- **Incidents** are alerts correlated by `incidents.py` (same host pair, either
  direction, within 30 minutes; floods by victim). An incident is true if any
  of its alerts is.

## Round 1: the false positives, and why

As shipped, development set:

| Cause | Alerts | Share |
|---|---|---|
| `protocol_tunnel` — TLS inside RDP on 3389 | 48,904 | 82.9% |
| `tls_anomaly` — TLS 1.0 ClientHellos from internet RDP clients | 9,412 | 16.0% |
| `c2_beacon` — keep-alives on long-lived Windows service connections | 400 | 0.7% |
| everything else | 249 | 0.4% |

### Bugs found and fixed

1. **RDP's TLS was read as tunnelling** (`ProtocolAnalyzer.py`). RDP's standard
   security layer is a TLS handshake inside the connection on 3389. The
   analyzer identifies protocols by signature, saw TLS on a port hinted as RDP,
   and flagged a protocol/port mismatch on every RDP session — and the victims
   have RDP open to the internet, so every scanner that touched them did it.
   STARTTLS ports (21, 25, 110, 143, 587) have the same property and were
   exempted for the same reason. SSH on 443 still alerts.
2. **Inbound legacy TLS was scored as our encrypted channel**
   (`detectors/c2.py`). `tls_anomaly` maps to T1573, an implant's encrypted C2.
   An internet scanner sending TLS 1.0 to our RDP port is someone else's
   client; it now only scores ClientHellos from internal hosts.
3. **Beacon detection counted server replies and mid-session packets**
   (`detectors/c2.py`). Every TLS record on a long-lived connection counted as
   a "callback", in both directions, so a Windows push-notification session
   with a 60 s keep-alive looked like a 0%-jitter beacon from the client and,
   reversed, from Microsoft's server. A callback is now a new TCP connection,
   a TLS ClientHello, an HTTP request or a QUIC handshake packet.
4. **Replies from high service ports looked like a port scan**
   (`detectors/recon.py`). The reply filter only recognised source ports below
   1024. The botnet's C2 listens on 8080; its replies to the victims' sequential
   ephemeral ports read as "18.219.211.138 probed 30 distinct ports". Packets
   carrying ACK now never count as probes — SYN, NULL, FIN and Xmas scans
   carry none, so every port-enumerating scan still counts.
5. **ECN-setup SYNs were not SYNs** (`detectors/base.py`). Three detectors
   tested `flags == 'SYN'`; Windows opens connections with SYN|ECE|CWR, so
   `syn_flood`, `lateral_movement` and `c2_beacon` were blind to new
   connections from every Windows host in the dataset.

A sixth issue was performance, not accuracy: the beacon detector re-read its
whole 30-minute window on every packet, so cost grew with the window. Over the
first ten minutes of the 33 SYN/s FTP connection storm the pipeline ran at
2,706 pkt/s, falling further as the window filled. The mean interval is
`(last − first) / (n − 1)`, so the range check now runs in O(1) before any
statistics; the same ten minutes replay at 44,280 pkt/s. Behaviour is
identical.

Each fix has a regression test in `tests/test_real_traffic_regressions.py`
that fails on the shipped code and passes on the fixed code.

## Round 2: closing the misses

After round 1, four attacks were still invisible. Each had a clear signal on
the wire once measured, and a wide gap to the busiest benign behaviour seen
across all 25 development and held-out-1 captures:

| Attack | Signal | Attack rate | Benign peak | Threshold |
|---|---|---|---|---|
| GoldenEye, HULK (HTTP flood) | HTTP requests, one source to one service, per minute | ~2,650 | 162 | 600 (`http_flood`) |
| Slowloris | Request heads without the closing blank line, per minute | ~1,280 | 39 | 200 (`http_flood`) |
| DVWA login brute force | POSTs to a login path, per 2 minutes | ~108 | 0 | 20 (`brute_force`) |
| Ares botnet | Requests for one external URL path, per 10 minutes | ~1,250 | 52 | 300 (`c2_beacon`) |

- **`http_flood`** is a new detector (T1499.002, Service Exhaustion Flood).
  The handshakes complete, which is why `syn_flood` was right to stay quiet.
- **Login forms** answer a wrong password with HTTP 200, so the failure is
  invisible; volume of submissions to a login path is the only signal.
  `brute_force` treats it like SSH: inferred, confidence capped at 0.85.
- **Fast polling**: Ares checks in every 0.5-2 s, below the 15 s floor the
  jitter test keeps to avoid request/response chatter. `c2_beacon` now also
  flags one internal client requesting the same external URL path hundreds of
  times in ten minutes. Internal destinations are excluded: that is
  monitoring, not C2.

Thresholds were chosen on data that included the development set, so the
development numbers flatter them. Held-out 2 was fetched afterwards — a new
DoS tool and a new host population — to measure them honestly.

## What is left

### False positives: 1.1, 1.3 and 0.4 per host-hour

Round 2 added none. What remains, by cause:

| Cause | Dev | Held-out 1 | Held-out 2 | Verdict |
|---|---|---|---|---|
| Internet RDP credential stuffing / SSH brute force on exposed hosts | 68 | 5 | 0 | **Real attacks the dataset labels benign.** 59 usernames in 5 minutes from one source is not a false positive in any SOC |
| RDP-over-UDP sessions at 40-55 pkt/s, flagged as `udp_flood` / `data_exfil` | 55 | 25 | 0 | Real false positive. 40 pkt/s is the `udp_flood` threshold, too low for interactive traffic. **Deliberately not re-tuned**: it would be tuning to the test set |
| Nmap service probes from the infiltrated host, raised as `credential_attack` (username `nmap`), `tls_anomaly` (SSLv3), `protocol_tunnel` | 25 | 21 | 0 | Caused by the attack, but typed wrong; counted as false positives anyway |
| Long random-looking AWS/CDN hostnames (`rackcdn.com`, 53-char label) | 18 | 13 | 11 | Real false positive, and the only one that reached held-out 2. Needs a resolver allowlist or per-zone baselining, not a looser global threshold |
| Large uploads (S3, admin sessions) | 9 | 2 | 0 | Real false positive; volume alone is a weak exfiltration signal |
| Other: scanner user-agents, a TLS anomaly, periodic TLS sessions | 4 | 4 | 0 | Mixed; the scanners are real |

Counting the unlabelled credential stuffing as the attack it is, the
development rate is about 0.7.

### Attacks: what each one looked like to NetWatch

| Attack | Result (round 2) | Notes |
|---|---|---|
| SSH-Bruteforce | `brute_force` in 50 s | Also raised `data_exfil` for the 13.8 MB the server sent back |
| XSS, SQL injection | `http_anomaly`, both days | Signatures |
| Web brute force (DVWA login) | `brute_force` in under 2 min, both days | New in round 2 |
| DoS-GoldenEye, DoS-Slowloris | `http_flood` in 115 s and 78 s | New in round 2 |
| DoS-Hulk (held-out 2) | `http_flood` in 28 s | First time this tool was seen |
| Infiltration | `port_scan`, `lateral_movement`, both days | From the compromised host's internal nmap |
| Ares botnet | `c2_beacon` on 10 of 10 hosts, ~34 min after the window opens | New in round 2; the bot's polling ramps up slowly |
| FTP-BruteForce | **`syn_flood`**, in 92 s | Not a NetWatch error: the dataset's FTP service was not running. All 19,700 SYNs in a sample 10 minutes got RST/ACK; there was never a 530 to count. NetWatch described the wire correctly |
| DoS-SlowHTTPTest (held-out 2) | **`syn_flood`**, in 20 s | The same dataset flaw: it was aimed at port 21, which was closed, so no HTTP was ever exchanged |

## Caveats

- **The labels are not the truth.** The "benign" traffic contains real internet
  attacks against the exposed hosts. Counting alerts on them as false
  positives understates precision; it is done anyway so the numbers are not
  adjusted by hand.
- **The fixes came from the development set.** That is what the held-out
  sets are for, and they are smaller: 6 attacks and 82 host-hours between
  them. There is no held-out botnet, SSH or FTP brute-force day, because the
  dataset has only one of each. Held-out 1 served round 1 only cleanly: its
  web brute-force miss was known when round 2 was designed.
- **One lab, one year.** 2018 Windows and Ubuntu hosts in AWS. A corporate
  LAN, a home network or a 2026 browser mix would surface different problems.
- **Per-host sensors.** Each host capture is replayed on its own detector, as
  a host-based sensor would see it. A single network tap seeing all hosts
  would aggregate differently, particularly for `network_recon` and
  `lateral_movement`.
