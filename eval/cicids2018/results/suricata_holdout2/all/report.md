# Suricata + ET Open, as distributed on CSE-CIC-IDS2018

Config: `/tmp/claude-0/-home-user-Netwatch-SOC/56b49ed9-d091-5fbb-9c58-028dcf25e911/scratchpad/suri/suricata.rules`

| | |
|---|---|
| Captures replayed | 5 (19,538,011 packets, 28.7 host-hours) |
| Attacks detected | **0 / 2** (0%); correct class 0 / 2 |
| Alerts | 44000 — 0 true positive, 44000 false positive vs labels |
| Alert precision | 0.0% |
| False positives | **1531.2 alerts per host-hour** |
| Incidents (alerts correlated) | 1379 — 0 true, 1379 false: **1151.8 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| DoS-SlowHTTPTest | — | **no** | no | 0 | — | — |
| DoS-Hulk | — | **no** | no | 0 | — | — |

## False positives by cause

| Cause | Alerts |
|---|---|
| SURICATA UDPv4 invalid checksum | 13943 |
| SURICATA IPv4 invalid checksum | 13500 |
| ET INFO RDP - Response To External Host | 8242 |
| SURICATA STREAM ESTABLISHED packet out of window | 2779 |
| ET REMOTE_ACCESS MS Remote Desktop Administrator Login Request | 1546 |
| GPL NETBIOS SMB-DS IPC$ unicode share access | 717 |
| GPL NETBIOS SMB-DS IPC$ share access | 687 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) | 675 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) | 675 |
| ET JA3 Hash - Possible Malware - Fake Firefox Font Update | 301 |
| SURICATA HTTP unable to match response to request | 238 |
| SURICATA STREAM Packet with invalid ack | 201 |
| SURICATA STREAM ESTABLISHED invalid ack | 198 |
| ET SCAN Sipvicious Scan | 70 |
| ET SCAN Sipvicious User-Agent Detected (friendly-scanner) | 70 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri16_dos | 18,890,171 | 5.5 | 97 | suricata×97 |
| wed14_dept_66.90 | 269,894 | 9.0 | 18426 | suricata×18426 |
| wed14_dept_66.49 | 58,779 | 2.5 | 2958 | suricata×2958 |
| wed14_dept_64.99 | 58,073 | 2.8 | 3589 | suricata×3589 |
| wed14_dept_64.106 | 261,094 | 9.0 | 18930 | suricata×18930 |
