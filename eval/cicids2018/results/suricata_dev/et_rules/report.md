# Suricata + ET Open, without engine anomaly events on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 18 (10,022,252 packets, 157.4 host-hours) |
| Attacks detected | **4 / 18** (22%); correct class 0 / 18 |
| Alerts | 99421 — 2038 true positive, 97383 false positive vs labels |
| Alert precision | 2.1% |
| False positives | **618.7 alerts per host-hour** |
| Incidents (alerts correlated) | 7858 — 55 true, 7803 false: **1189.8 false incidents per host-day** |

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
| Infilteration | — | yes | no | 72 | suricata×72 | -174s |
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
| ET INFO RDP - Response To External Host | 84091 |
| GPL NETBIOS SMB-DS IPC$ share access | 4494 |
| GPL NETBIOS SMB-DS IPC$ unicode share access | 4419 |
| ET JA3 Hash - Possible Malware - Fake Firefox Font Update | 1779 |
| ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound) | 495 |
| ET USER_AGENTS Microsoft Device Metadata Retrieval Client User-Agent | 468 |
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 335 |
| ET SCAN Sipvicious Scan | 304 |
| GPL ICMP PING *NIX | 271 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 1 | 202 |
| ET REMOTE_ACCESS MS Remote Desktop Administrator Login Request | 126 |
| ET SCAN Suspicious inbound to mySQL port 3306 | 119 |
| GPL ICMP PING BSDtype | 60 |
| ET INFO Windows OS Submitting USB Metadata to Microsoft | 34 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 33 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| wed14_ftp_ssh | 4,718,327 | 8.9 | 104 | suricata×104 |
| thu15_dos | 424,625 | 9.0 | 55 | suricata×55 |
| thu22_web | 47,714 | 9.1 | 2000 | suricata×2000 |
| wed28_infiltration | 919,537 | 9.3 | 6995 | suricata×6995 |
| fri02_bot_69.23 | 316,197 | 8.7 | 8144 | suricata×8144 |
| fri02_bot_69.17 | 275,440 | 8.7 | 3582 | suricata×3582 |
| fri02_bot_69.14 | 289,396 | 8.7 | 3199 | suricata×3199 |
| fri02_bot_69.12 | 194,651 | 8.7 | 7239 | suricata×7239 |
| fri02_bot_69.10 | 328,571 | 8.7 | 7194 | suricata×7194 |
| fri02_bot_69.8 | 333,702 | 8.7 | 3997 | suricata×3997 |
| fri02_bot_69.6 | 361,912 | 8.7 | 12714 | suricata×12714 |
| fri02_bot_69.26 | 228,488 | 7.5 | 2434 | suricata×2434 |
| fri02_bot_69.29 | 323,651 | 8.7 | 4526 | suricata×4526 |
| fri02_bot_69.30 | 320,039 | 8.7 | 9104 | suricata×9104 |
| fri02_clean_69.13 | 245,109 | 8.4 | 3346 | suricata×3346 |
| fri02_clean_69.9 | 301,971 | 8.7 | 15412 | suricata×15412 |
| fri02_clean_69.16 | 209,972 | 9.1 | 4689 | suricata×4689 |
| fri02_clean_69.5 | 182,950 | 8.9 | 4687 | suricata×4687 |
