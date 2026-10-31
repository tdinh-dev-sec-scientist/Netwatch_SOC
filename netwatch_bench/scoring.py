"""
Score normalized findings against a pack's ground truth.

The rules here are the metric contract (docs/bench/metric-contract.md) in
code. In short:

* A finding is a **true positive** if it falls inside a scenario window and
  involves one of its attackers and one of its victims, in either direction;
  or, for a scenario with a `pivot` (a compromised internal host), if it goes
  from the pivot to an internal address and its techniques match the
  scenario's. A finding with no techniques gets the benefit of the doubt.
  A finding that names only one address matches if it is an attacker.
* Every other finding is a **false positive against the labels**. Findings
  that match an annotation (known but unlabelled activity) are still false
  positives, but are reported as explained.
* A scenario unit is **detected** if at least one finding matches it, and
  **correctly classified** if one of those findings carries a technique that
  is, or is a sub-technique of, one the scenario lists.
* **Host-hours** are the summed duration of every capture times its hosts.
* **Incidents** group findings on the same pair of hosts (or the same victim,
  for `group_by: victim`) with gaps under 30 minutes; an incident is true if
  any finding in it is.
"""

import collections

from . import stats
from .pack import techniques_match

INCIDENT_GAP_S = 1800


def match(finding, pack, scenarios=None):
    """Return (scenario, victim) for the first scenario a finding belongs to."""
    ts = finding['ts']
    src, dst = finding.get('src_ip'), finding.get('dst_ip')
    ends = {src, dst} - {None}
    for sc in pack.scenarios if scenarios is None else scenarios:
        if not sc.in_window(ts):
            continue
        if ends & set(sc.attackers):
            victims = ends & set(sc.victims)
            if victims:
                return sc, (dst if dst in victims else src)
            # A one-sided alert ("this host is brute forcing"), as Zeek's
            # aggregate notices are, names only the attacker. It counts for
            # every victim of a non-per-victim scenario, but cannot say which
            # victim of a per-victim one it hit.
            if (src is None) != (dst is None) and not sc.per_victim:
                return sc, sc.victims[0]
        if (sc.pivot and src == sc.pivot and pack.is_internal(dst)
                and (not finding['techniques']
                     or techniques_match(finding['techniques'],
                                         sc.techniques))):
            return sc, sc.pivot
    return None, None


def correlate(findings, gap_s=INCIDENT_GAP_S):
    """Group findings into incidents; returns a list of lists of findings."""
    open_by_key, incidents = {}, []
    for f in sorted(findings, key=lambda f: f['ts']):
        if f['group_by'] == 'victim':
            key = ('victim', f.get('dst_ip'))
        else:
            key = ('pair',) + tuple(sorted(
                ip for ip in (f.get('src_ip'), f.get('dst_ip')) if ip))
        current = open_by_key.get(key)
        if current is None or f['ts'] - current[-1]['ts'] > gap_s:
            current = []
            open_by_key[key] = current
            incidents.append(current)
        current.append(f)
    return incidents


def _rate(k, n):
    return {'k': k, 'n': n, 'rate': (k / n) if n else None,
            'ci95': stats.wilson(k, n)}


def score(pack, findings, captures):
    """Build a scorecard.

    `findings` are normalized findings (any order); `captures` is the list of
    capture descriptions from captures.describe(), one per pack capture.
    """
    by_capture = collections.defaultdict(list)
    for f in findings:
        by_capture[f['capture']].append(f)
    unknown = set(by_capture) - {c.id for c in pack.captures}
    if unknown:
        raise ValueError('findings name captures the pack does not have: %s'
                         % ', '.join(sorted(unknown)))

    hits = collections.defaultdict(list)          # (scenario id, unit) -> []
    false_positives = []
    tp_incidents = fp_incidents = 0
    for capture in pack.captures:
        mine = by_capture.get(capture.id, [])
        for f in mine:
            sc, victim = match(f, pack)
            f['_tp'] = sc is not None
            if sc is None:
                false_positives.append(f)
            else:
                unit = victim if sc.per_victim else None
                hits[(sc.id, unit)].append(f)
        for incident in correlate(mine):
            if any(f['_tp'] for f in incident):
                tp_incidents += 1
            else:
                fp_incidents += 1

    rows = []
    for sc in pack.scenarios:
        for unit in sc.units():
            found = sorted(hits.get((sc.id, unit), []), key=lambda f: f['ts'])
            typed = [f for f in found if f['techniques']]
            if not found:
                correct = False
            elif not typed:
                correct = None              # the engine attributes nothing
            else:
                correct = any(techniques_match(f['techniques'], sc.techniques)
                              for f in typed)
            rows.append({
                'scenario': sc.id, 'label': sc.label, 'victim': unit,
                'expected_techniques': list(sc.techniques),
                'detected': bool(found),
                'correct_class': correct,
                'alerts': len(found),
                'rules': dict(collections.Counter(
                    f['name'] for f in found).most_common(5)),
                'techniques_seen': sorted({t for f in found
                                           for t in f['techniques']}),
                'first_alert_after_s': (round(found[0]['ts'] - sc.onset, 1)
                                        if found else None),
            })

    explained = collections.Counter()
    for f in false_positives:
        sc, _v = match(f, pack, pack.annotations)
        explained[sc.id if sc else None] += 1
    host_hours = sum(c['host_hours'] for c in captures)
    total = sum(len(v) for v in by_capture.values())
    tp_alerts = total - len(false_positives)
    units = len(rows)
    detected = sum(r['detected'] for r in rows)
    assessable = [r for r in rows if r['correct_class'] is not None]
    fp = len(false_positives)

    return {
        'pack': {'id': pack.id, 'title': pack.title},
        'exposure': {
            'captures': len(captures),
            'packets': sum(c['packets'] for c in captures),
            'host_hours': round(host_hours, 3),
        },
        'detection': _rate(detected, units),
        'classification': dict(
            _rate(sum(1 for r in assessable if r['correct_class']),
                  len(assessable)),
            not_assessable=units - len(assessable)),
        'alerts': {
            'total': total, 'true_positive': tp_alerts, 'false_positive': fp,
            'precision': _rate(tp_alerts, total),
        },
        'noise': {
            'false_alerts': fp,
            'false_alerts_per_host_hour': (fp / host_hours
                                           if host_hours else None),
            'false_alerts_per_host_hour_ci95': stats.poisson_rate_ci(
                fp, host_hours),
            'incidents': tp_incidents + fp_incidents,
            'true_incidents': tp_incidents,
            'false_incidents': fp_incidents,
            'false_incidents_per_host_day': (fp_incidents / host_hours * 24
                                             if host_hours else None),
            'without_addresses': sum(
                1 for f in false_positives
                if not (f.get('src_ip') or f.get('dst_ip'))),
            'explained_by_annotations': {k: v for k, v in explained.items()
                                         if k is not None},
            'top_false_positive_rules': dict(collections.Counter(
                f['name'] for f in false_positives).most_common(10)),
        },
        'scenarios': rows,
        'captures': captures,
    }
