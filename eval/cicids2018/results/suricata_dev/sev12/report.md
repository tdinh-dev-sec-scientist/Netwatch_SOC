# Suricata + ET Open, severity 1-2 only on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 18 (10,022,252 packets, 157.4 host-hours) |
| Attacks detected | **4 / 18** (22%); correct class 0 / 18 |
| Alerts | 3095 — 1968 true positive, 1127 false positive vs labels |
| Alert precision | 63.6% |
| False positives | **7.2 alerts per host-hour** |
| Incidents (alerts correlated) | 800 — 5 true, 795 false: **121.2 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| FTP-BruteForce | — | **no** | no | 0 | — | — |
| SSH-Bruteforce | — | yes | no | 46 | suricata×46 | +50s |
| DoS-GoldenEye | — | **no** | no | 0 | — | — |
| DoS-Slowloris | — | **no** | no | 0 | — | — |
| Brute Force -Web | — | **no** | no | 0 | — | — |
| Brute Force -XSS | — | yes | no | 1912 | suricata×1912 | +101s |
| SQL Injection | — | yes | no | 8 | suricata×8 | +95s |
| Infilteration | — | yes | no | 2 | suricata×2 | -129s |
| Bot | 172.31.69.23 | **no** | no | 0 | — | — |
| Bot | 172.31.69.17 | **no** | no | 0 | — | — |
| Bot | 172.31.69.14 | **no** | no | 0 | — | — |
| Bot | 172.31.69.12 | **no** | no | 0 | — | — |
| Bot | 172.31.69.10 | **no** | no | 0 | — | — |
| Bot | 172.31.69.8 | **no** | no | 0 | — | — |
| Bot | 172.31.69.6 | **no** | no | 0 | — | — |
| Bot | 172.31.69.26 | **no** | no | 0 | — | — |
| Bot | 172.31.69.29 | **no** | no | 0 | — | — |
| Bot | 172.31.69.30 | **no** | no | 0 | — | — |

## False positives by cause

| Cause | Alerts |
|---|---|
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 335 |
| ET SCAN Sipvicious Scan | 304 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 1 | 202 |
| ET SCAN Suspicious inbound to mySQL port 3306 | 119 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 33 |
| GPL SNMP public access udp | 30 |
| ET SCAN Suspicious inbound to PostgreSQL port 5432 | 24 |
| ET VOIP Modified Sipvicious Asterisk PBX User-Agent | 16 |
| ET SNMP Attempt to retrieve Cisco Config via TFTP (CISCO-CONFIG-COPY) | 14 |
| GPL SNMP private access udp | 14 |
| ET SCAN Potential SSH Scan | 10 |
| ET SCAN Suspicious inbound to Oracle SQL port 1521 | 4 |
| ET INFO Dropbox.com Offsite File Backup in Use | 3 |
| ET CINS Active Threat Intelligence Poor Reputation IP group 92 | 3 |
| ET INFO Noction IRP Probe | 3 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| wed14_ftp_ssh | 4,718,327 | 8.9 | 103 | suricata×103 |
| thu15_dos | 424,625 | 9.0 | 54 | suricata×54 |
| thu22_web | 47,714 | 9.1 | 1998 | suricata×1998 |
| wed28_infiltration | 919,537 | 9.3 | 63 | suricata×63 |
| fri02_bot_69.23 | 316,197 | 8.7 | 58 | suricata×58 |
| fri02_bot_69.17 | 275,440 | 8.7 | 53 | suricata×53 |
| fri02_bot_69.14 | 289,396 | 8.7 | 55 | suricata×55 |
| fri02_bot_69.12 | 194,651 | 8.7 | 50 | suricata×50 |
| fri02_bot_69.10 | 328,571 | 8.7 | 52 | suricata×52 |
| fri02_bot_69.8 | 333,702 | 8.7 | 50 | suricata×50 |
| fri02_bot_69.6 | 361,912 | 8.7 | 68 | suricata×68 |
| fri02_bot_69.26 | 228,488 | 7.5 | 60 | suricata×60 |
| fri02_bot_69.29 | 323,651 | 8.7 | 72 | suricata×72 |
| fri02_bot_69.30 | 320,039 | 8.7 | 69 | suricata×69 |
| fri02_clean_69.13 | 245,109 | 8.4 | 68 | suricata×68 |
| fri02_clean_69.9 | 301,971 | 8.7 | 72 | suricata×72 |
| fri02_clean_69.16 | 209,972 | 9.1 | 80 | suricata×80 |
| fri02_clean_69.5 | 182,950 | 8.9 | 70 | suricata×70 |
