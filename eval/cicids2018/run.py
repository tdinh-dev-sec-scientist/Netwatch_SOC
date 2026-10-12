"""
Replay CSE-CIC-IDS2018 captures through NetWatch and score the alerts.

    python eval/cicids2018/fetch.py --out data/cicids2018
    python eval/cicids2018/run.py --data data/cicids2018 --out eval/cicids2018/results

Each capture in `ground_truth.json` is replayed on its own detector instance
(they are separate hosts' sensors), in parallel. Every alert is then matched
against the labelled attack scenarios:

* An alert is a **true positive** when it falls inside a scenario's window and
  links an attacker to a victim (either direction), or, for scenarios with a
  `pivot`, originates from the compromised host towards an internal address.
* Every other alert is a **false positive against the labels** — including
  alerts on real but unlabelled internet attacks hitting the exposed victims.
  The report breaks false positives down by cause so the two can be told apart.

A scenario is **detected** if at least one alert matches it; it is
**classified correctly** if one of those alerts is of an expected threat type.
Scenarios marked `per_victim` (the botnet) count each victim separately.

Writes `report.md`, `summary.json` and the raw alerts per capture to --out.
"""

import argparse
import collections
import datetime as dt
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import config as config_module  # noqa: E402
import replay  # noqa: E402
from detectors.base import is_internal  # noqa: E402
from fetch import member_filename  # noqa: E402


def _epoch(text):
    return dt.datetime.fromisoformat(text).replace(
        tzinfo=dt.timezone.utc).timestamp()


def _replay_capture(job):
    name, paths, config_path, out_dir = job
    cfg = config_module.load(config_path)
    alerts_path = os.path.join(out_dir, 'alerts', name + '.jsonl')
    with open(alerts_path, 'w', encoding='utf-8') as fh:
        summary = replay.replay(
            paths, cfg, on_finding=lambda r: fh.write(json.dumps(r) + '\n'))
    summary['files'] = [os.path.basename(p) for p in paths]
    summary['name'] = name
    return summary


# ── matching ─────────────────────────────────────────────────────────────────

def match_scenario(alert, scenarios):
    """Return (scenario, victim) for the first scenario the alert belongs to."""
    ts = alert['ts']
    ends = {alert['src_ip'], alert['dst_ip']}
    for sc in scenarios:
        if not any(lo <= ts <= hi for lo, hi in sc['_windows']):
            continue
        attackers = ends & set(sc['attackers'])
        victims = ends & set(sc['victims'])
        if attackers and victims:
            return sc, victims.pop()
        # From the compromised host, only the behaviour the scenario names
        # counts: that host also carries its ordinary traffic, and an alert
        # on that must not be credited to the attack.
        pivot = sc.get('pivot')
        if (pivot and alert['src_ip'] == pivot
                and is_internal(alert['dst_ip'])
                and alert['threat_type'] in sc['expected']):
            return sc, pivot
    return None, None


def fp_cause(alert, scenarios=()):
    """Bucket a label-level false positive by what actually triggered it.

    Purely descriptive: these rules sort the alerts so the report can explain
    them; they play no part in scoring.
    """
    t = alert['threat_type']
    ports = {alert.get('src_port'), alert.get('dst_port')}
    src, dst = alert['src_ip'], alert['dst_ip']
    inbound = src and not is_internal(src) and is_internal(dst)
    for sc in scenarios:
        if (sc.get('pivot') == src and is_internal(dst)
                and any(lo <= alert['ts'] <= hi for lo, hi in sc['_windows'])):
            return ('%s: attack traffic from the compromised host, raised as '
                    'an unexpected type' % t)
    if t == 'protocol_tunnel' and 3389 in ports:
        return 'protocol_tunnel: TLS inside RDP on 3389 (standard RDP security upgrade)'
    if t == 'tls_anomaly' and 3389 in ports:
        return 'tls_anomaly: legacy TLS ClientHello from internet RDP clients on 3389'
    if t == 'tls_anomaly':
        return 'tls_anomaly: legacy/no-SNI TLS client (non-RDP)'
    if t in ('brute_force', 'credential_attack') and inbound:
        return ('%s: unlabelled internet brute force / credential stuffing '
                'against an exposed service' % t)
    if t == 'http_anomaly' and inbound:
        return 'http_anomaly: unlabelled internet scanner/exploit probe'
    if t in ('udp_flood', 'data_exfil') and 3389 in ports \
            and alert.get('protocol') == 'UDP':
        return '%s: RDP-over-UDP remote desktop session (40-55 pkt/s)' % t
    if t == 'data_exfil':
        return 'data_exfil: large legitimate upload (cloud storage, admin session)'
    if t == 'dns_tunnel':
        return 'dns_tunnel: long, random-looking cloud/CDN hostnames'
    if t == 'c2_beacon':
        return 'c2_beacon: periodic keep-alive to a benign service'
    if t == 'protocol_tunnel':
        return 'protocol_tunnel: protocol/port mismatch (non-RDP)'
    if t == 'port_scan' and src and not is_internal(src):
        return 'port_scan: external server replying to many ephemeral ports'
    return '%s: other' % t


# ── scoring ──────────────────────────────────────────────────────────────────

def score(truth, summaries, out_dir):
    scenarios = truth['scenarios']
    for sc in scenarios:
        sc['_windows'] = [(_epoch(a), _epoch(b)) for a, b in sc['windows_utc']]

    tp = collections.defaultdict(list)       # (scenario id, victim) -> alerts
    fps = []
    for s in summaries:
        path = os.path.join(out_dir, 'alerts', s['name'] + '.jsonl')
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                alert = json.loads(line)
                alert['capture'] = s['name']
                sc, victim = match_scenario(alert, scenarios)
                if sc:
                    tp[(sc['id'], victim)].append(alert)
                else:
                    fps.append(alert)

    rows = []
    for sc in scenarios:
        units = sc['victims'] if sc.get('per_victim') else [None]
        for victim in units:
            if victim is None:
                hits = [a for (sid, _v), al in tp.items() if sid == sc['id']
                        for a in al]
            else:
                hits = tp.get((sc['id'], victim), [])
            hits.sort(key=lambda a: a['ts'])
            types = collections.Counter(a['threat_type'] for a in hits)
            start = sc['_windows'][0][0] + 600   # undo the 10-minute pad
            rows.append({
                'scenario': sc['id'], 'label': sc['label'],
                'victim': victim,
                'detected': bool(hits),
                'correct_class': any(t in sc['expected'] for t in types),
                'alerts': len(hits),
                'alert_types': dict(types),
                'first_alert_after_s': (round(hits[0]['ts'] - start)
                                        if hits else None),
            })

    hours = sum(s['capture_hours'] for s in summaries)
    packets = sum(s['packets'] for s in summaries)
    total_alerts = sum(s['alerts'] for s in summaries)
    tp_alerts = sum(len(v) for v in tp.values())
    causes = collections.Counter(fp_cause(a, scenarios) for a in fps)
    fp_incidents = {(a['threat_type'], json.dumps(a['incident_key']))
                    for a in fps}

    units = len(rows)
    result = {
        'captures': len(summaries),
        'packets': packets,
        'capture_host_hours': round(hours, 2),
        'alerts': total_alerts,
        'true_positive_alerts': tp_alerts,
        'false_positive_alerts': len(fps),
        'alert_precision': round(tp_alerts / total_alerts, 4)
        if total_alerts else None,
        'false_positives_per_host_hour': round(len(fps) / hours, 2)
        if hours else None,
        'false_positive_incidents': len(fp_incidents),
        'attack_units': units,
        'attack_units_detected': sum(r['detected'] for r in rows),
        'attack_units_correct_class': sum(r['correct_class'] for r in rows),
        'detection_rate': round(sum(r['detected'] for r in rows) / units, 4),
        'false_positive_causes': dict(causes.most_common()),
        'scenarios': rows,
        'per_capture': [{k: s[k] for k in (
            'name', 'packets', 'capture_hours', 'alerts', 'alerts_by_type',
            'parse_errors', 'detector_errors', 'pkt_per_s')}
            for s in summaries],
    }
    return result


def render(result, config_path):
    r = result
    out = ['# NetWatch on CSE-CIC-IDS2018', '',
           'Config: `%s`' % (config_path or 'shipped defaults'), '',
           '| | |', '|---|---|',
           '| Captures replayed | %d (%s packets, %.1f host-hours) |'
           % (r['captures'], format(r['packets'], ','), r['capture_host_hours']),
           '| Attacks detected | **%d / %d** (%.0f%%); correct class %d / %d |'
           % (r['attack_units_detected'], r['attack_units'],
              100 * r['detection_rate'], r['attack_units_correct_class'],
              r['attack_units']),
           '| Alerts | %d — %d true positive, %d false positive vs labels |'
           % (r['alerts'], r['true_positive_alerts'],
              r['false_positive_alerts']),
           '| Alert precision | %.1f%% |' % (100 * (r['alert_precision'] or 0)),
           '| False positives | **%.1f per host-hour** (%d distinct incidents) |'
           % (r['false_positives_per_host_hour'],
              r['false_positive_incidents']),
           '', '## Per attack', '',
           '| Attack | Victim | Detected | Right class | Alerts | Types | '
           'First alert |', '|---|---|---|---|---|---|---|']
    for row in r['scenarios']:
        first = row['first_alert_after_s']
        out.append('| %s | %s | %s | %s | %d | %s | %s |' % (
            row['label'], row['victim'] or '—',
            'yes' if row['detected'] else '**no**',
            'yes' if row['correct_class'] else 'no',
            row['alerts'],
            ', '.join('%s×%d' % kv for kv in row['alert_types'].items()) or '—',
            '%+ds' % first if first is not None else '—'))
    out += ['', '## False positives by cause', '',
            '| Cause | Alerts |', '|---|---|']
    for cause, n in r['false_positive_causes'].items():
        out.append('| %s | %d |' % (cause, n))
    out += ['', '## Per capture', '',
            '| Capture | Packets | Hours | Alerts | By type |',
            '|---|---|---|---|---|']
    for c in r['per_capture']:
        out.append('| %s | %s | %.1f | %d | %s |' % (
            c['name'], format(c['packets'], ','), c['capture_hours'],
            c['alerts'], ', '.join('%s×%d' % kv
                                   for kv in c['alerts_by_type'].items())))
    return '\n'.join(out) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--data', required=True, help='directory fetch.py wrote')
    ap.add_argument('--out', required=True, help='results directory')
    ap.add_argument('--truth', default=os.path.join(HERE, 'ground_truth.json'),
                    help='ground_truth.json (development) or holdout.json')
    ap.add_argument('--config', help='JSON threshold overrides')
    ap.add_argument('--jobs', type=int, default=os.cpu_count() or 1)
    ap.add_argument('--score-only', action='store_true',
                    help='re-score the alerts already in --out')
    args = ap.parse_args(argv)

    with open(args.truth, encoding='utf-8') as fh:
        truth = json.load(fh)
    os.makedirs(os.path.join(args.out, 'alerts'), exist_ok=True)
    summaries_path = os.path.join(args.out, 'captures.json')

    if args.score_only:
        with open(summaries_path, encoding='utf-8') as fh:
            summaries = json.load(fh)
    else:
        jobs = []
        for cap in truth['captures']:
            paths = [os.path.join(args.data, member_filename(cap['day'], m))
                     for m in cap['members']]
            missing = [p for p in paths if not os.path.exists(p)]
            if missing:
                raise SystemExit('missing %s — run fetch.py first' % missing[0])
            jobs.append((cap['name'], paths, args.config, args.out))
        # Largest first, so the long captures do not end up running last.
        jobs.sort(key=lambda j: -sum(os.path.getsize(p) for p in j[1]))
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            summaries = list(pool.map(_replay_capture, jobs))
        summaries.sort(key=lambda s: s['name'])
        with open(summaries_path, 'w', encoding='utf-8') as fh:
            json.dump(summaries, fh, indent=1)

    result = score(truth, summaries, args.out)
    result['config'] = args.config
    with open(os.path.join(args.out, 'summary.json'), 'w',
              encoding='utf-8') as fh:
        json.dump(result, fh, indent=1)
    report = render(result, args.config)
    with open(os.path.join(args.out, 'report.md'), 'w', encoding='utf-8') as fh:
        fh.write(report)
    print(report)
    return 0


if __name__ == '__main__':
    sys.exit(main())
