# REST API

Every endpoint the dashboard and integrations read from. Back to the [README](../Readme.MD).

## REST API — 25 endpoints

All read from PostgreSQL. Empty database returns empty collections, never filler.
Invalid parameters return `400` with a message; unknown resources return `404`.

| Method | Route | Notes |
|---|---|---|
| GET | `/api/health` | Schema, index count, row counts, engine state |
| GET | `/api/stats/overview` | Live counters |
| GET | `/api/stats/throughput` | `?minutes=1..10080` |
| GET | `/api/stats/protocols` | `?minutes=` |
| GET | `/api/stats/severity` | `?hours=1..720` |
| GET | `/api/stats/timeline` | `?hours=`, `?bucket_s=` |
| GET | `/api/alerts` | `?limit&offset&severity&threat_type&src_ip&acknowledged` |
| GET | `/api/alerts/<id>` | Detail + techniques + related packets |
| POST | `/api/alerts/<id>/acknowledge` | |
| GET | `/api/alerts/stats` | Grouped by threat type |
| GET | `/api/incidents` | Alerts correlated into incidents: `?hours&gap_min&limit` |
| GET | `/api/threats/summary` | Aggregated per source + threat type |
| GET | `/api/threats/types` | Detector catalog joined with live counts |
| GET | `/api/mitre/techniques` | Catalog + observed counts |
| GET | `/api/mitre/techniques/<id>` | Detail, detectors, recent alerts |
| GET | `/api/mitre/coverage` | Grouped by tactic |
| GET | `/api/hosts/top` | `?order=packets_sent\|bytes_sent\|threat_score\|alert_count` |
| GET | `/api/hosts/<ip>` | Protocols, peers, alerts |
| GET | `/api/geo` | Country rollup |
| GET | `/api/connections` | `?order&src_ip&limit` |
| GET | `/api/packets` | `?protocol&src_ip&dst_ip&malicious_only` |
| GET | `/api/performance` | Measured history + live counters |
| GET | `/api/detectors` | Per-detector counters |
| GET | `/api/protocols` | Supported protocols + parse counts |
| GET | `/api/scenarios` | Replayable attack scenarios |

All filters are parameterised; `test_sql_injection_in_filters_is_parameterised`
confirms injection attempts are treated as literal values.
