# NetWatch on CSE-CIC-IDS2018

Config: `shipped defaults`

| | |
|---|---|
| Captures replayed | 5 (19,538,011 packets, 28.7 host-hours) |
| Attacks detected | **2 / 2** (100%); correct class 1 / 2 |
| Alerts | 69 — 58 true positive, 11 false positive vs labels |
| Alert precision | 84.1% |
| False positives | **0.4 alerts per host-hour** |
| Incidents (alerts correlated) | 9 — 2 true, 7 false: **5.8 false incidents per host-day** |

## Per attack

| Attack | Victim | Detected | Right class | Alerts | Types | First alert |
|---|---|---|---|---|---|---|
| DoS-SlowHTTPTest | — | yes | no | 53 | syn_flood×53 | +20s |
| DoS-Hulk | — | yes | yes | 5 | http_flood×3, data_exfil×2 | +28s |

## False positives by cause

| Cause | Alerts |
|---|---|
| dns_tunnel: long, random-looking cloud/CDN hostnames | 11 |

## Per capture

| Capture | Packets | Hours | Alerts | By type |
|---|---|---|---|---|
| fri16_dos | 18,890,171 | 5.5 | 58 | data_exfil×2, http_flood×3, syn_flood×53 |
| wed14_dept_64.106 | 261,094 | 9.0 | 5 | dns_tunnel×5 |
| wed14_dept_64.99 | 58,073 | 2.8 | 0 |  |
| wed14_dept_66.49 | 58,779 | 2.5 | 1 | dns_tunnel×1 |
| wed14_dept_66.90 | 269,894 | 9.0 | 5 | dns_tunnel×5 |
