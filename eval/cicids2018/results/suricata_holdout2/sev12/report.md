# Suricata + ET Open, severity 1-2 only on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 5 (19,538,011 packets, 28.7 host-hours) |
| Attacks detected | **0 / 2** (0%); correct class 0 / 2 |
| Alerts | 1614 — 0 true positive, 1614 false positive vs labels |
| Alert precision | 0.0% |
| False positives | **56.2 alerts per host-hour** |
| Incidents (alerts correlated) | 851 — 0 true, 851 false: **710.8 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| DoS-SlowHTTPTest | — | **no** | no | 0 | — | — |
| DoS-Hulk | — | **no** | no | 0 | — | — |

## False positives by cause

| Cause | Alerts |
|---|---|
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) | 675 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) | 675 |
| ET SCAN Sipvicious Scan | 70 |
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 70 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 1 | 52 |
| ET SCAN Suspicious inbound to mySQL port 3306 | 23 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 33 | 12 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 10 |
| ET INFO Vulnerable Java Version 1.8.x Detected | 8 |
| ET EXPLOIT ETERNALBLUE Probe Vulnerable System Response MS17-010 | 5 |
| ET SCAN Potential SSH Scan | 3 |
| ET Threatview.io High Confidence Cobalt Strike C2 IP group 14 | 3 |
| GPL SNMP public access udp | 2 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 2 |
| ET SCAN Suspicious inbound to Oracle SQL port 1521 | 1 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri16_dos | 18,890,171 | 5.5 | 46 | suricata×46 |
| wed14_dept_66.90 | 269,894 | 9.0 | 461 | suricata×461 |
| wed14_dept_66.49 | 58,779 | 2.5 | 304 | suricata×304 |
| wed14_dept_64.99 | 58,073 | 2.8 | 269 | suricata×269 |
| wed14_dept_64.106 | 261,094 | 9.0 | 534 | suricata×534 |
