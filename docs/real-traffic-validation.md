# NetWatch on real traffic: CSE-CIC-IDS2018

Every other number in this project comes from synthetic traffic. This is the
answer to "and on real traffic?": 12 million packets from a labelled public
dataset, replayed through the unmodified pipeline, scored against the
dataset's ground truth, with every false positive traced to a cause.

## Results

| | As shipped | After fixes |
|---|---|---|
| **Development set** — 18 host captures, 10.0 M packets, 157 host-hours | | |
| False positives | **374.6 per host-hour** (58,965 alerts) | **1.1 per host-hour** (179 alerts) |
| Alert precision | 3.0% | 65.0% |
| Labelled attacks detected | 16 / 18 (9 with the right threat type) | 11 / 18 (9 with the right threat type) |
| **Held-out set** — 7 host captures, 1.8 M packets, 53 host-hours, never replayed until the fixes were frozen | | |
| False positives | **506.7 per host-hour** (26,783 alerts) | **1.3 per host-hour** (70 alerts) |
| Alert precision | 0.6% | 71.1% |
| Labelled attacks detected | 3 / 4 | 3 / 4 |

**As shipped, NetWatch was unusable on real traffic**: about one false alert
every ten seconds per host. The synthetic suite's "0 false positives across
240,000 benign packets" said nothing about this, because the synthetic
generator never produced the traffic that caused them.

**Five logic bugs, not thresholds, caused 99.7% of them.** Each fix is
described below; no detection threshold in `config.py` was changed. On the
held-out days, which were not looked at until the fixes were frozen, false
positives fell by the same factor (300-400×) and detection was unchanged — so
the fixes generalise rather than fit the data they came from.

**Detection fell from 16 to 11 of 18 on the development set, and that is the
honest number.** All ten botnet hosts were "detected" by the port scan
detector misreading the C2 server's replies as a scan of its own victims —
one of the five bugs. For five of them that was the only alert, so fixing the
bug removed the false credit.

Full per-attack tables: [`eval/cicids2018/results/`](../eval/cicids2018/results/).

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
needs — 3.3 GB instead of 400 GB.

| Set | Day | Captures | Labelled attacks |
|---|---|---|---|
| dev | Wed 14 Feb | FTP/SSH server `.69.25` | FTP-BruteForce, SSH-Bruteforce |
| dev | Thu 15 Feb | web server `.69.25` | DoS-GoldenEye, DoS-Slowloris |
| dev | Thu 22 Feb | DVWA server `.69.28` | Web brute force, XSS, SQL injection |
| dev | Wed 28 Feb | workstation `.69.24` | Infiltration (dropper, then internal nmap) |
| dev | Fri 2 Mar | 14 workstations | Ares botnet on 10 of them; 4 clean controls |
| held-out | Fri 23 Feb | DVWA server + 1 workstation | Web brute force, XSS, SQL injection |
| held-out | Thu 1 Mar | workstation `.69.13` | Infiltration |
| held-out | Wed 21 Feb | 4 workstations | none (benign) |

## Method

```bash
python eval/cicids2018/fetch.py --out data/cicids2018
python eval/cicids2018/fetch.py --out data/cicids2018 --truth eval/cicids2018/holdout.json
python eval/cicids2018/run.py --data data/cicids2018 --out results/dev
python eval/cicids2018/run.py --data data/cicids2018 --out results/holdout \
    --truth eval/cicids2018/holdout.json
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

## The false positives, and why

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

### What is left: 1.1 per host-hour

| Cause | Dev | Held-out | Verdict |
|---|---|---|---|
| Internet RDP credential stuffing / SSH brute force on exposed hosts | 68 | 5 | **Real attacks the dataset labels benign.** 59 usernames in 5 minutes from one source is not a false positive in any SOC |
| RDP-over-UDP sessions at 40-55 pkt/s, flagged as `udp_flood` / `data_exfil` | 55 | 25 | Real false positive. 40 pkt/s is the `udp_flood` threshold, which is too low for interactive traffic. **Deliberately not re-tuned**: it would be tuning to this test set |
| Nmap service probes from the infiltrated host, raised as `credential_attack` (username `nmap`), `tls_anomaly` (SSLv3), `protocol_tunnel` | 25 | 21 | Caused by the attack, but typed wrong; counted as false positives anyway |
| Long random-looking AWS/CDN hostnames (`rackcdn.com`, 53-char label) | 18 | 13 | Real false positive. Needs a resolver allowlist or per-zone baselining, not a looser global threshold |
| Large uploads (S3, admin sessions) | 9 | 2 | Real false positive; volume alone is a weak exfiltration signal |
| Other: scanner user-agents, a TLS anomaly, periodic TLS sessions | 4 | 4 | Mixed; the scanners are real |

Read strictly against the labels it is 1.1 false positives per host-hour;
counting the unlabelled credential stuffing as the attack it is, it is about
0.7.

## What is still missed, and why

| Attack | Result | Why |
|---|---|---|
| FTP-BruteForce | Detected in 92 s — **as `syn_flood`** | Not a NetWatch bug: in the dataset the FTP service was not running. All 19,700 SYNs in a sample 10 minutes got RST/ACK; there was never a 530 to count. NetWatch described the wire correctly |
| SSH-Bruteforce | Detected in 50 s as `brute_force` | Correct; also raised `data_exfil` for the 13.8 MB the server sent back to the attacker |
| DoS-GoldenEye | Only `data_exfil` (5 min in) | No application-layer DoS detector. GoldenEye completes its handshakes, so `syn_flood` correctly stays quiet |
| DoS-Slowloris | **Missed** | Same gap; Slowloris is low-rate by design |
| Web brute force (DVWA login) | **Missed**, both days | Failed form logins return HTTP 200, not 401. Nothing on the wire says "failure" without application knowledge |
| XSS, SQL injection | Detected, right type, both days | `http_anomaly` signatures |
| Infiltration | Detected, right type, both days | `port_scan` and `lateral_movement` from the compromised host |
| Ares botnet | **5 of 10 hosts**, only via `data_exfil`, over an hour late | The bot polls its C2 every 0.5-2 s. `c2_beacon` only considers intervals of 15-900 s, by design, to keep request/response chatter out. A fast poller is outside its model; it needs a rate-based or URI-repetition signal |

## Caveats

- **The labels are not the truth.** The "benign" traffic contains real internet
  attacks against the exposed hosts. Counting alerts on them as false
  positives understates precision; it is done anyway so the numbers are not
  adjusted by hand.
- **The fixes came from the development set.** That is what the held-out set
  is for. It is smaller (4 attacks, 53 host-hours) and only checks the false
  positive rate and the web and infiltration detections; there is no held-out
  botnet or brute-force day.
- **One lab, one year.** 2018 Windows and Ubuntu hosts in AWS. A corporate
  LAN, a home network or a 2026 browser mix would surface different problems.
- **Per-host sensors.** Each host capture is replayed on its own detector, as
  a host-based sensor would see it. A single network tap seeing all hosts
  would aggregate differently, particularly for `network_recon` and
  `lateral_movement`.
