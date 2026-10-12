# Suricata + ET Open, as distributed on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 18 (10,022,252 packets, 157.4 host-hours) |
| Attacks detected | **14 / 18** (78%); correct class 0 / 18 |
| Alerts | 441695 — 4540 true positive, 437155 false positive vs labels |
| Alert precision | 1.0% |
| False positives | **2777.3 alerts per host-hour** |
| Incidents (alerts correlated) | 8438 — 99 true, 8339 false: **1271.5 false incidents per host-day** |

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
| Infilteration | — | yes | no | 1559 | suricata×1559 | -194s |
| Bot | 172.31.69.23 | yes | no | 125 | suricata×125 | +2054s |
| Bot | 172.31.69.17 | yes | no | 128 | suricata×128 | +2054s |
| Bot | 172.31.69.14 | yes | no | 106 | suricata×106 | +2053s |
| Bot | 172.31.69.12 | yes | no | 59 | suricata×59 | +2054s |
| Bot | 172.31.69.10 | yes | no | 119 | suricata×119 | +2053s |
| Bot | 172.31.69.8 | yes | no | 140 | suricata×140 | +2054s |
| Bot | 172.31.69.6 | yes | no | 112 | suricata×112 | +2053s |
| Bot | 172.31.69.26 | yes | no | 63 | suricata×63 | +15173s |
| Bot | 172.31.69.29 | yes | no | 58 | suricata×58 | +4802s |
| Bot | 172.31.69.30 | yes | no | 105 | suricata×105 | +2054s |

## False positives by cause

| Cause | Alerts |
|---|---|
| SURICATA IPv4 invalid checksum | 158024 |
| SURICATA UDPv4 invalid checksum | 156633 |
| ET INFO RDP - Response To External Host | 84091 |
| SURICATA STREAM ESTABLISHED packet out of window | 14113 |
| SURICATA STREAM Packet with invalid ack | 5308 |
| SURICATA STREAM ESTABLISHED invalid ack | 5281 |
| GPL NETBIOS SMB-DS IPC$ share access | 4494 |
| GPL NETBIOS SMB-DS IPC$ unicode share access | 4419 |
| ET JA3 Hash - Possible Malware - Fake Firefox Font Update | 1779 |
| ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound) | 495 |
| ET USER_AGENTS Microsoft Device Metadata Retrieval Client User-Agent | 468 |
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 335 |
| ET SCAN Sipvicious Scan | 304 |
| GPL ICMP PING *NIX | 271 |
| SURICATA STREAM ESTABLISHED SYNACK resend | 240 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| wed14_ftp_ssh | 4,718,327 | 8.9 | 150 | suricata×150 |
| thu15_dos | 424,625 | 9.0 | 120 | suricata×120 |
| thu22_web | 47,714 | 9.1 | 2042 | suricata×2042 |
| wed28_infiltration | 919,537 | 9.3 | 35996 | suricata×35996 |
| fri02_bot_69.23 | 316,197 | 8.7 | 31198 | suricata×31198 |
| fri02_bot_69.17 | 275,440 | 8.7 | 16410 | suricata×16410 |
| fri02_bot_69.14 | 289,396 | 8.7 | 32585 | suricata×32585 |
| fri02_bot_69.12 | 194,651 | 8.7 | 17196 | suricata×17196 |
| fri02_bot_69.10 | 328,571 | 8.7 | 24519 | suricata×24519 |
| fri02_bot_69.8 | 333,702 | 8.7 | 77644 | suricata×77644 |
| fri02_bot_69.6 | 361,912 | 8.7 | 35300 | suricata×35300 |
| fri02_bot_69.26 | 228,488 | 7.5 | 11546 | suricata×11546 |
| fri02_bot_69.29 | 323,651 | 8.7 | 23799 | suricata×23799 |
| fri02_bot_69.30 | 320,039 | 8.7 | 23145 | suricata×23145 |
| fri02_clean_69.13 | 245,109 | 8.4 | 28779 | suricata×28779 |
| fri02_clean_69.9 | 301,971 | 8.7 | 33499 | suricata×33499 |
| fri02_clean_69.16 | 209,972 | 9.1 | 24089 | suricata×24089 |
| fri02_clean_69.5 | 182,950 | 8.9 | 23678 | suricata×23678 |
