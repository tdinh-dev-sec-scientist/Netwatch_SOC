"""
Incident correlation: from many alerts to the few things an analyst works.

Detector cooldowns stop one detector repeating itself every packet, but on real
traffic one attack still raises a stream of alerts: an FTP connection storm
re-alerts every minute for two hours, an SSH brute force also trips the
exfiltration detector with the server's replies. An analyst works incidents,
not alerts.

Two alerts belong to the same incident when they involve the same pair of
hosts, in either direction, and the later one arrives within `gap_s` of the
incident's most recent alert. Floods are grouped by victim instead, because
their sources are often spoofed and would otherwise split one attack into an
incident per address.

Works on plain dicts — rows from the `alerts` table, replay.py's JSON lines,
or another tool's alerts mapped to the same keys (`ts`, `threat_type`,
`src_ip`, `dst_ip`, optionally `severity`, `techniques`, `id`) — so the same
grouping can be applied to NetWatch and to a reference IDS when comparing them.
"""

SEVERITY_RANK = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

# Threat types whose source address carries no identity: group by victim.
VICTIM_KEYED = frozenset({'syn_flood', 'udp_flood', 'amplification'})

DEFAULT_GAP_S = 1800


def entity(alert):
    """The hosts an alert is about, as a hashable, direction-free key."""
    if alert.get('threat_type') in VICTIM_KEYED:
        return ('victim', alert.get('dst_ip'))
    pair = sorted(ip for ip in (alert.get('src_ip'), alert.get('dst_ip'))
                  if ip)
    return ('pair',) + tuple(pair)


def correlate(alerts, gap_s=DEFAULT_GAP_S):
    """Group alerts into incidents. Returns a list of incident dicts, newest
    activity first. Each alert dict gains an `_incident` key referring to the
    incident it joined.
    """
    open_by_entity = {}
    incidents = []
    for alert in sorted(alerts, key=lambda a: a['ts']):
        key = entity(alert)
        current = open_by_entity.get(key)
        if current is None or alert['ts'] - current['last_ts'] > gap_s:
            current = {
                'entity': list(key[1:]),
                'grouped_by': key[0],
                'first_ts': alert['ts'],
                'last_ts': alert['ts'],
                'alert_count': 0,
                'threat_types': {},
                'techniques': set(),
                'severity': 'INFO',
                'alert_ids': [],
            }
            open_by_entity[key] = current
            incidents.append(current)
        current['last_ts'] = alert['ts']
        current['alert_count'] += 1
        kind = alert.get('threat_type')
        current['threat_types'][kind] = current['threat_types'].get(kind, 0) + 1
        current['techniques'].update(alert.get('techniques') or ())
        severity = alert.get('severity') or 'INFO'
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK[current['severity']]:
            current['severity'] = severity
        if alert.get('id') is not None:
            current['alert_ids'].append(alert['id'])
        alert['_incident'] = current

    for inc in incidents:
        inc['techniques'] = sorted(inc['techniques'])
        inc['duration_s'] = round(inc['last_ts'] - inc['first_ts'], 3)
        # Most frequent type first: what the incident is mostly about.
        inc['threat_types'] = dict(sorted(inc['threat_types'].items(),
                                          key=lambda kv: (-kv[1], kv[0])))
        inc['primary_type'] = next(iter(inc['threat_types']), None)
    incidents.sort(key=lambda inc: inc['last_ts'], reverse=True)
    for index, inc in enumerate(incidents):
        inc['id'] = index
    return incidents
