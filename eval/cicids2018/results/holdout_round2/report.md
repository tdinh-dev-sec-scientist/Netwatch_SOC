# NetWatch on CSE-CIC-IDS2018

Config: `shipped defaults`

| | |
|---|---|
| Captures replayed | 7 (1,763,242 packets, 52.9 host-hours) |
| Attacks detected | **4 / 4** (100%); correct class 4 / 4 |
| Alerts | 271 — 201 true positive, 70 false positive vs labels |
| Alert precision | 74.2% |
| False positives | **1.3 alerts per host-hour** |
| Incidents (alerts correlated) | 86 — 58 true, 28 false: **12.7 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| Brute Force -Web | — | yes | yes | 29 | brute_force×29 | +113s |
| Brute Force -XSS | — | yes | yes | 69 | http_anomaly×69 | +66s |
| SQL Injection | — | yes | yes | 7 | http_anomaly×7 | +180s |
| Infilteration | — | yes | yes | 96 | port_scan×79, lateral_movement×17 | +776s |

## False positives by cause

| Cause | Alerts |
|---|---|
| udp_flood: RDP-over-UDP remote desktop session (40-55 pkt/s) | 22 |
| dns_tunnel: long, random-looking cloud/CDN hostnames | 13 |
| credential_attack: attack traffic from the compromised host, raised as an unexpected type | 10 |
| credential_attack: unlabelled internet brute force / credential stuffing against an exposed service | 5 |
| tls_anomaly: attack traffic from the compromised host, raised as an unexpected type | 4 |
| dns_tunnel: attack traffic from the compromised host, raised as an unexpected type | 4 |
| c2_beacon: periodic keep-alive to a benign service | 3 |
| data_exfil: RDP-over-UDP remote desktop session (40-55 pkt/s) | 3 |
| protocol_tunnel: attack traffic from the compromised host, raised as an unexpected type | 3 |
| data_exfil: large legitimate upload (cloud storage, admin session) | 2 |
| protocol_tunnel: protocol/port mismatch (non-RDP) | 1 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri23_clean_69.13 | 226,777 | 10.2 | 7 | credential_attack×3, dns_tunnel×4 |
| fri23_web | 55,101 | 9.2 | 108 | brute_force×29, c2_beacon×3, http_anomaly×76 |
| thu01_infiltration | 782,254 | 9.2 | 148 | credential_attack×12, data_exfil×4, dns_tunnel×7, lateral_movement×17, port_scan×79, protocol_tunnel×3, tls_anomaly×4, udp_flood×22 |
| wed21_clean_69.11 | 104,327 | 4.3 | 1 | protocol_tunnel×1 |
| wed21_clean_69.19 | 63,229 | 1.9 | 2 | dns_tunnel×2 |
| wed21_clean_69.4 | 307,828 | 9.0 | 3 | dns_tunnel×3 |
| wed21_clean_69.9 | 223,726 | 9.0 | 2 | data_exfil×1, dns_tunnel×1 |
