# NetWatch on CSE-CIC-IDS2018

Config: `shipped defaults`

| | |
|---|---|
| Captures replayed | 18 (10,022,252 packets, 157.4 host-hours) |
| Attacks detected | **11 / 18** (61%); correct class 9 / 18 |
| Alerts | 512 — 333 true positive, 179 false positive vs labels |
| Alert precision | 65.0% |
| False positives | **1.1 per host-hour** (60 distinct incidents) |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| FTP-BruteForce | — | yes | no | 97 | syn_flood×97 | +92s |
| SSH-Bruteforce | — | yes | yes | 62 | brute_force×46, data_exfil×9, protocol_tunnel×7 | +50s |
| DoS-GoldenEye | — | yes | no | 2 | data_exfil×2 | +277s |
| DoS-Slowloris | — | **no** | no | 0 | — | — |
| Brute Force -Web | — | **no** | no | 0 | — | — |
| Brute Force -XSS | — | yes | yes | 37 | http_anomaly×37 | +101s |
| SQL Injection | — | yes | yes | 5 | http_anomaly×5 | +232s |
| Infilteration | — | yes | yes | 121 | port_scan×99, lateral_movement×22 | -216s |
| Bot | 172.31.69.23 | yes | yes | 2 | data_exfil×2 | +3857s |
| Bot | 172.31.69.17 | yes | yes | 2 | data_exfil×2 | +3856s |
| Bot | 172.31.69.14 | **no** | no | 0 | — | — |
| Bot | 172.31.69.12 | yes | yes | 2 | data_exfil×2 | +3857s |
| Bot | 172.31.69.10 | **no** | no | 0 | — | — |
| Bot | 172.31.69.8 | yes | yes | 2 | data_exfil×2 | +3674s |
| Bot | 172.31.69.6 | **no** | no | 0 | — | — |
| Bot | 172.31.69.26 | yes | yes | 1 | data_exfil×1 | +15446s |
| Bot | 172.31.69.29 | **no** | no | 0 | — | — |
| Bot | 172.31.69.30 | **no** | no | 0 | — | — |

## False positives by cause

| Cause | Alerts |
|---|---|
| credential_attack: unlabelled internet brute force / credential stuffing against an exposed service | 66 |
| udp_flood: RDP-over-UDP remote desktop session (40-55 pkt/s) | 50 |
| dns_tunnel: long, random-looking cloud/CDN hostnames | 18 |
| credential_attack: attack traffic from the compromised host, raised as an unexpected type | 13 |
| data_exfil: large legitimate upload (cloud storage, admin session) | 9 |
| tls_anomaly: attack traffic from the compromised host, raised as an unexpected type | 6 |
| protocol_tunnel: attack traffic from the compromised host, raised as an unexpected type | 6 |
| data_exfil: RDP-over-UDP remote desktop session (40-55 pkt/s) | 5 |
| http_anomaly: unlabelled internet scanner/exploit probe | 3 |
| brute_force: unlabelled internet brute force / credential stuffing against an exposed service | 2 |
| tls_anomaly: legacy/no-SNI TLS client (non-RDP) | 1 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri02_bot_69.10 | 328,571 | 8.7 | 4 | credential_attack×2, udp_flood×2 |
| fri02_bot_69.12 | 194,651 | 8.7 | 2 | data_exfil×2 |
| fri02_bot_69.14 | 289,396 | 8.7 | 7 | data_exfil×1, udp_flood×6 |
| fri02_bot_69.17 | 275,440 | 8.7 | 4 | data_exfil×2, udp_flood×2 |
| fri02_bot_69.23 | 316,197 | 8.7 | 8 | data_exfil×2, dns_tunnel×1, udp_flood×5 |
| fri02_bot_69.26 | 228,488 | 7.5 | 1 | data_exfil×1 |
| fri02_bot_69.29 | 323,651 | 8.7 | 4 | dns_tunnel×2, udp_flood×2 |
| fri02_bot_69.30 | 320,039 | 8.7 | 2 | udp_flood×2 |
| fri02_bot_69.6 | 361,912 | 8.7 | 4 | udp_flood×4 |
| fri02_bot_69.8 | 333,702 | 8.7 | 5 | data_exfil×3, udp_flood×2 |
| fri02_clean_69.13 | 245,109 | 8.4 | 7 | dns_tunnel×4, http_anomaly×1, udp_flood×2 |
| fri02_clean_69.16 | 209,972 | 9.1 | 13 | credential_attack×8, data_exfil×1, dns_tunnel×4 |
| fri02_clean_69.5 | 182,950 | 8.9 | 2 | data_exfil×1, dns_tunnel×1 |
| fri02_clean_69.9 | 301,971 | 8.7 | 62 | credential_attack×56, data_exfil×1, dns_tunnel×4, tls_anomaly×1 |
| thu15_dos | 424,625 | 9.0 | 5 | data_exfil×4, http_anomaly×1 |
| thu22_web | 47,714 | 9.1 | 45 | brute_force×2, http_anomaly×43 |
| wed14_ftp_ssh | 4,718,327 | 8.9 | 160 | brute_force×46, data_exfil×10, protocol_tunnel×7, syn_flood×97 |
| wed28_infiltration | 919,537 | 9.3 | 177 | credential_attack×13, data_exfil×6, dns_tunnel×2, lateral_movement×22, port_scan×99, protocol_tunnel×6, tls_anomaly×6, udp_flood×23 |
