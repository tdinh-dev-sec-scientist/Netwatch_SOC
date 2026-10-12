# NetWatch on CSE-CIC-IDS2018

Config: `shipped defaults`

| | |
|---|---|
| Captures replayed | 18 (10,022,252 packets, 157.4 host-hours) |
| Attacks detected | **16 / 18** (89%); correct class 9 / 18 |
| Alerts | 60770 — 1805 true positive, 58965 false positive vs labels |
| Alert precision | 3.0% |
| False positives | **374.6 alerts per host-hour** |
| Incidents (alerts correlated) | 1998 — 82 true, 1916 false: **292.1 false incidents per host-day** |

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
| Bot | 172.31.69.23 | yes | yes | 159 | port_scan×157, data_exfil×2 | +1557s |
| Bot | 172.31.69.17 | yes | yes | 161 | port_scan×159, data_exfil×2 | +1388s |
| Bot | 172.31.69.14 | yes | no | 159 | port_scan×159 | +1270s |
| Bot | 172.31.69.12 | yes | yes | 34 | port_scan×32, data_exfil×2 | +1325s |
| Bot | 172.31.69.10 | yes | no | 167 | port_scan×167 | +406s |
| Bot | 172.31.69.8 | yes | yes | 159 | port_scan×157, data_exfil×2 | +1650s |
| Bot | 172.31.69.6 | yes | no | 165 | port_scan×165 | +583s |
| Bot | 172.31.69.26 | yes | yes | 154 | port_scan×153, data_exfil×1 | +2028s |
| Bot | 172.31.69.29 | yes | no | 154 | port_scan×154 | +1980s |
| Bot | 172.31.69.30 | yes | no | 169 | port_scan×169 | +187s |

## False positives by cause

| Cause | Alerts |
|---|---|
| protocol_tunnel: TLS inside RDP on 3389 (standard RDP security upgrade) | 48904 |
| tls_anomaly: legacy TLS ClientHello from internet RDP clients on 3389 | 9412 |
| c2_beacon: periodic keep-alive to a benign service | 400 |
| protocol_tunnel: attack traffic from the compromised host, raised as an unexpected type | 76 |
| credential_attack: unlabelled internet brute force / credential stuffing against an exposed service | 66 |
| udp_flood: RDP-over-UDP remote desktop session (40-55 pkt/s) | 50 |
| dns_tunnel: long, random-looking cloud/CDN hostnames | 18 |
| credential_attack: attack traffic from the compromised host, raised as an unexpected type | 13 |
| data_exfil: large legitimate upload (cloud storage, admin session) | 9 |
| tls_anomaly: attack traffic from the compromised host, raised as an unexpected type | 6 |
| data_exfil: RDP-over-UDP remote desktop session (40-55 pkt/s) | 5 |
| http_anomaly: unlabelled internet scanner/exploit probe | 3 |
| brute_force: unlabelled internet brute force / credential stuffing against an exposed service | 2 |
| tls_anomaly: legacy/no-SNI TLS client (non-RDP) | 1 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri02_bot_69.10 | 328,571 | 8.7 | 4427 | credential_attack×2, port_scan×167, protocol_tunnel×3456, tls_anomaly×800, udp_flood×2 |
| fri02_bot_69.12 | 194,651 | 8.7 | 4538 | data_exfil×2, port_scan×32, protocol_tunnel×3928, tls_anomaly×576 |
| fri02_bot_69.14 | 289,396 | 8.7 | 2184 | data_exfil×1, port_scan×159, protocol_tunnel×1709, tls_anomaly×309, udp_flood×6 |
| fri02_bot_69.17 | 275,440 | 8.7 | 2742 | data_exfil×2, port_scan×159, protocol_tunnel×2075, tls_anomaly×504, udp_flood×2 |
| fri02_bot_69.23 | 316,197 | 8.7 | 5013 | c2_beacon×70, data_exfil×2, dns_tunnel×1, port_scan×157, protocol_tunnel×4201, tls_anomaly×577, udp_flood×5 |
| fri02_bot_69.26 | 228,488 | 7.5 | 1822 | data_exfil×1, port_scan×153, protocol_tunnel×1290, tls_anomaly×378 |
| fri02_bot_69.29 | 323,651 | 8.7 | 1960 | dns_tunnel×2, port_scan×154, protocol_tunnel×1551, tls_anomaly×251, udp_flood×2 |
| fri02_bot_69.30 | 320,039 | 8.7 | 5457 | port_scan×169, protocol_tunnel×4588, tls_anomaly×698, udp_flood×2 |
| fri02_bot_69.6 | 361,912 | 8.7 | 7857 | port_scan×165, protocol_tunnel×6795, tls_anomaly×893, udp_flood×4 |
| fri02_bot_69.8 | 333,702 | 8.7 | 3023 | data_exfil×3, port_scan×157, protocol_tunnel×2295, tls_anomaly×566, udp_flood×2 |
| fri02_clean_69.13 | 245,109 | 8.4 | 530 | dns_tunnel×4, http_anomaly×1, protocol_tunnel×432, tls_anomaly×91, udp_flood×2 |
| fri02_clean_69.16 | 209,972 | 9.1 | 3662 | c2_beacon×104, credential_attack×8, data_exfil×1, dns_tunnel×4, protocol_tunnel×2700, tls_anomaly×845 |
| fri02_clean_69.5 | 182,950 | 8.9 | 2932 | c2_beacon×82, data_exfil×1, dns_tunnel×1, protocol_tunnel×2120, tls_anomaly×728 |
| fri02_clean_69.9 | 301,971 | 8.7 | 9257 | c2_beacon×104, credential_attack×56, data_exfil×1, dns_tunnel×4, protocol_tunnel×7862, tls_anomaly×1230 |
| thu15_dos | 424,625 | 9.0 | 5 | data_exfil×4, http_anomaly×1 |
| thu22_web | 47,714 | 9.1 | 45 | brute_force×2, http_anomaly×43 |
| wed14_ftp_ssh | 4,718,327 | 8.9 | 160 | brute_force×46, data_exfil×10, protocol_tunnel×7, syn_flood×97 |
| wed28_infiltration | 919,537 | 9.3 | 5156 | c2_beacon×40, credential_attack×13, data_exfil×6, dns_tunnel×2, lateral_movement×22, port_scan×99, protocol_tunnel×3978, tls_anomaly×973, udp_flood×23 |
