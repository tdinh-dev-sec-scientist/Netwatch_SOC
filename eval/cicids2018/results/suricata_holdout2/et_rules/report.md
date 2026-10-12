# Suricata + ET Open, without engine anomaly events on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 5 (19,538,011 packets, 28.7 host-hours) |
| Attacks detected | **0 / 2** (0%); correct class 0 / 2 |
| Alerts | 13128 — 0 true positive, 13128 false positive vs labels |
| Alert precision | 0.0% |
| False positives | **456.9 alerts per host-hour** |
| Incidents (alerts correlated) | 1272 — 0 true, 1272 false: **1062.4 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| DoS-SlowHTTPTest | — | **no** | no | 0 | — | — |
| DoS-Hulk | — | **no** | no | 0 | — | — |

## False positives by cause

| Cause | Alerts |
|---|---|
| ET INFO RDP - Response To External Host | 8242 |
| ET REMOTE_ACCESS MS Remote Desktop Administrator Login Request | 1546 |
| GPL NETBIOS SMB-DS IPC$ unicode share access | 717 |
| GPL NETBIOS SMB-DS IPC$ share access | 687 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) | 675 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) | 675 |
| ET JA3 Hash - Possible Malware - Fake Firefox Font Update | 301 |
| ET SCAN Sipvicious Scan | 70 |
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 70 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 1 | 52 |
| ET SCAN Suspicious inbound to mySQL port 3306 | 23 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 33 | 12 |
| ET INFO GNU/Linux APT User-Agent Outbound likely related to package management | 12 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 10 |
| ET INFO Vulnerable Java Version 1.8.x Detected | 8 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri16_dos | 18,890,171 | 5.5 | 59 | suricata×59 |
| wed14_dept_66.90 | 269,894 | 9.0 | 3200 | suricata×3200 |
| wed14_dept_66.49 | 58,779 | 2.5 | 1383 | suricata×1383 |
| wed14_dept_64.99 | 58,073 | 2.8 | 917 | suricata×917 |
| wed14_dept_64.106 | 261,094 | 9.0 | 7569 | suricata×7569 |
