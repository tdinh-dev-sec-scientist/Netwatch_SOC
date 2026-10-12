# NetWatch on CSE-CIC-IDS2018

Config: `shipped defaults`

| | |
|---|---|
| Captures replayed | 7 (1,763,242 packets, 52.9 host-hours) |
| Attacks detected | **3 / 4** (75%); correct class 3 / 4 |
| Alerts | 26955 — 172 true positive, 26783 false positive vs labels |
| Alert precision | 0.6% |
| False positives | **506.7 alerts per host-hour** |
| Incidents (alerts correlated) | 1258 — 57 true, 1201 false: **545.3 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| Brute Force -Web | — | **no** | no | 0 | — | — |
| Brute Force -XSS | — | yes | yes | 69 | http_anomaly×69 | +66s |
| SQL Injection | — | yes | yes | 7 | http_anomaly×7 | +180s |
| Infilteration | — | yes | yes | 96 | port_scan×79, lateral_movement×17 | +776s |

## False positives by cause

| Cause | Alerts |
|---|---|
| protocol_tunnel: TLS inside RDP on 3389 (standard RDP security upgrade) | 19997 |
| tls_anomaly: legacy TLS ClientHello from internet RDP clients on 3389 | 6386 |
| c2_beacon: periodic keep-alive to a benign service | 278 |
| protocol_tunnel: attack traffic from the compromised host, raised as an unexpected type | 58 |
| udp_flood: RDP-over-UDP remote desktop session (40-55 pkt/s) | 22 |
| dns_tunnel: long, random-looking cloud/CDN hostnames | 13 |
| credential_attack: attack traffic from the compromised host, raised as an unexpected type | 10 |
| credential_attack: unlabelled internet brute force / credential stuffing against an exposed service | 5 |
| tls_anomaly: attack traffic from the compromised host, raised as an unexpected type | 4 |
| dns_tunnel: attack traffic from the compromised host, raised as an unexpected type | 4 |
| data_exfil: RDP-over-UDP remote desktop session (40-55 pkt/s) | 3 |
| data_exfil: large legitimate upload (cloud storage, admin session) | 2 |
| protocol_tunnel: protocol/port mismatch (non-RDP) | 1 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri23_clean_69.13 | 226,777 | 10.2 | 1753 | credential_attack×3, dns_tunnel×4, protocol_tunnel×1222, tls_anomaly×524 |
| fri23_web | 55,101 | 9.2 | 79 | c2_beacon×3, http_anomaly×76 |
| thu01_infiltration | 782,254 | 9.2 | 8305 | credential_attack×12, data_exfil×4, dns_tunnel×7, lateral_movement×17, port_scan×79, protocol_tunnel×6078, tls_anomaly×2086, udp_flood×22 |
| wed21_clean_69.11 | 104,327 | 4.3 | 2300 | c2_beacon×48, protocol_tunnel×1612, tls_anomaly×640 |
| wed21_clean_69.19 | 63,229 | 1.9 | 1120 | c2_beacon×22, dns_tunnel×2, protocol_tunnel×768, tls_anomaly×328 |
| wed21_clean_69.4 | 307,828 | 9.0 | 9391 | c2_beacon×103, dns_tunnel×3, protocol_tunnel×7627, tls_anomaly×1658 |
| wed21_clean_69.9 | 223,726 | 9.0 | 4007 | c2_beacon×102, data_exfil×1, dns_tunnel×1, protocol_tunnel×2749, tls_anomaly×1154 |
