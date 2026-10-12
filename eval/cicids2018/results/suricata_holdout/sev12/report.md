# Suricata + ET Open, severity 1-2 only on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 7 (1,763,242 packets, 52.9 host-hours) |
| Attacks detected | **3 / 4** (75%); correct class 0 / 4 |
| Alerts | 4237 — 3670 true positive, 567 false positive vs labels |
| Alert precision | 86.6% |
| False positives | **10.7 alerts per host-hour** |
| Incidents (alerts correlated) | 417 — 4 true, 413 false: **187.5 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| Brute Force -Web | — | **no** | no | 0 | — | — |
| Brute Force -XSS | — | yes | no | 3651 | suricata×3651 | +66s |
| SQL Injection | — | yes | no | 16 | suricata×16 | +97s |
| Infilteration | — | yes | no | 3 | suricata×3 | +54s |

## False positives by cause

| Cause | Alerts |
|---|---|
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 142 |
| ET SCAN Sipvicious Scan | 134 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 1 | 99 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 82 |
| ET SCAN Suspicious inbound to mySQL port 3306 | 46 |
| GPL SNMP public access udp | 10 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 33 | 8 |
| ET SCAN Potential SSH Scan | 8 |
| ET SCAN Suspicious inbound to PostgreSQL port 5432 | 6 |
| ET Threatview.io High Confidence Cobalt Strike C2 IP group 14 | 6 |
| ET COMPROMISED Known Compromised or Hostile Host Traffic group 15 | 4 |
| ET INFO Dropbox.com Offsite File Backup in Use | 3 |
| ET DNS Query for .to TLD | 3 |
| ET Threatview.io High Confidence Cobalt Strike C2 IP group 11 | 3 |
| ET CINS Active Threat Intelligence Poor Reputation IP group 92 | 2 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri23_web | 55,101 | 9.2 | 3752 | suricata×3752 |
| fri23_clean_69.13 | 226,777 | 10.2 | 100 | suricata×100 |
| thu01_infiltration | 782,254 | 9.2 | 98 | suricata×98 |
| wed21_clean_69.4 | 307,828 | 9.0 | 120 | suricata×120 |
| wed21_clean_69.9 | 223,726 | 9.0 | 83 | suricata×83 |
| wed21_clean_69.11 | 104,327 | 4.3 | 68 | suricata×68 |
| wed21_clean_69.19 | 63,229 | 1.9 | 16 | suricata×16 |
