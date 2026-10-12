# Suricata + ET Open, without engine anomaly events on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 7 (1,763,242 packets, 52.9 host-hours) |
| Attacks detected | **3 / 4** (75%); correct class 0 / 4 |
| Alerts | 38724 — 3728 true positive, 34996 false positive vs labels |
| Alert precision | 9.6% |
| False positives | **662.1 alerts per host-hour** |
| Incidents (alerts correlated) | 3207 — 44 true, 3163 false: **1436.2 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| Brute Force -Web | — | **no** | no | 0 | — | — |
| Brute Force -XSS | — | yes | no | 3651 | suricata×3651 | +66s |
| SQL Injection | — | yes | no | 16 | suricata×16 | +97s |
| Infilteration | — | yes | no | 61 | suricata×61 | +54s |

## False positives by cause

| Cause | Alerts |
|---|---|
| ET INFO RDP - Response To External Host | 30823 |
| ET JA3 Hash - Possible Malware - Fake Firefox Font Update | 1287 |
| GPL NETBIOS SMB-DS IPC$ share access | 900 |
| GPL NETBIOS SMB-DS IPC$ unicode share access | 873 |
| GPL ICMP PING *NIX | 308 |
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 142 |
| ET SCAN Sipvicious Scan | 134 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 1 | 99 |
| ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound) | 94 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 82 |
| ET USER_AGENTS Microsoft Device Metadata Retrieval Client User-Agent | 66 |
| ET SCAN Suspicious inbound to mySQL port 3306 | 46 |
| GPL ICMP PING BSDtype | 41 |
| ET REMOTE_ACCESS MS Remote Desktop Administrator Login Request | 34 |
| GPL SNMP public access udp | 10 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri23_web | 55,101 | 9.2 | 3752 | suricata×3752 |
| fri23_clean_69.13 | 226,777 | 10.2 | 2551 | suricata×2551 |
| thu01_infiltration | 782,254 | 9.2 | 10377 | suricata×10377 |
| wed21_clean_69.4 | 307,828 | 9.0 | 13742 | suricata×13742 |
| wed21_clean_69.9 | 223,726 | 9.0 | 4741 | suricata×4741 |
| wed21_clean_69.11 | 104,327 | 4.3 | 2455 | suricata×2455 |
| wed21_clean_69.19 | 63,229 | 1.9 | 1106 | suricata×1106 |
