# Suricata + ET Open, as distributed on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 7 (1,763,242 packets, 52.9 host-hours) |
| Attacks detected | **3 / 4** (75%); correct class 0 / 4 |
| Alerts | 230406 — 5444 true positive, 224962 false positive vs labels |
| Alert precision | 2.4% |
| False positives | **4256.1 alerts per host-hour** |
| Incidents (alerts correlated) | 3417 — 61 true, 3356 false: **1523.8 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| Brute Force -Web | — | **no** | no | 0 | — | — |
| Brute Force -XSS | — | yes | no | 3651 | suricata×3651 | +66s |
| SQL Injection | — | yes | no | 16 | suricata×16 | +97s |
| Infilteration | — | yes | no | 1777 | suricata×1777 | -596s |

## False positives by cause

| Cause | Alerts |
|---|---|
| SURICATA IPv4 invalid checksum | 83453 |
| SURICATA UDPv4 invalid checksum | 83078 |
| ET INFO RDP - Response To External Host | 30823 |
| SURICATA STREAM ESTABLISHED packet out of window | 12416 |
| SURICATA STREAM Packet with invalid ack | 5429 |
| SURICATA STREAM ESTABLISHED invalid ack | 5394 |
| ET JA3 Hash - Possible Malware - Fake Firefox Font Update | 1287 |
| GPL NETBIOS SMB-DS IPC$ share access | 900 |
| GPL NETBIOS SMB-DS IPC$ unicode share access | 873 |
| GPL ICMP PING *NIX | 308 |
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 142 |
| ET SCAN Sipvicious Scan | 134 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 1 | 99 |
| ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound) | 94 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 82 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri23_web | 55,101 | 9.2 | 3793 | suricata×3793 |
| fri23_clean_69.13 | 226,777 | 10.2 | 24236 | suricata×24236 |
| thu01_infiltration | 782,254 | 9.2 | 121409 | suricata×121409 |
| wed21_clean_69.4 | 307,828 | 9.0 | 39004 | suricata×39004 |
| wed21_clean_69.9 | 223,726 | 9.0 | 26087 | suricata×26087 |
| wed21_clean_69.11 | 104,327 | 4.3 | 11071 | suricata×11071 |
| wed21_clean_69.19 | 63,229 | 1.9 | 4806 | suricata×4806 |
