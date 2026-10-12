"""
Run Suricata over the same captures and score it the same way as NetWatch.

    python eval/cicids2018/suricata.py --data data/cicids2018 \\
        --rules suricata.rules --out results/suricata-dev \\
        --captures results/dev/captures.json

A reference point, so NetWatch's numbers mean something: the same pcaps, the
same ground truth, the same scoring and the same incident correlation, applied
to a production IDS with the community ruleset.

Rules: ET Open (Proofpoint Emerging Threats). `suricata-update` fetches them
into /var/lib/suricata/rules/suricata.rules; the `jasonish/suricata` image
ships a copy at the same path, which is where the published comparison's
ruleset (ET Open as of 2024-12-11, 54,399 rules) came from.

Scoring differences, both in Suricata's favour:
* Its alert types do not map onto NetWatch's, so "right class" is not scored,
  and every alert from an infiltration pivot inside its window is credited.
* `--min-severity 2` drops severity-3 (informational) signatures, the usual
  first tuning step; both the full and the tuned set are reported.

`--captures` reuses NetWatch's captures.json for capture durations, so the
per-host-hour rates divide by identical denominators.
"""

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

import run  # noqa: E402
from fetch import member_filename  # noqa: E402

SEVERITY = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW', 4: 'INFO'}


def alerts_only_config(config, workdir):
    """A copy of suricata.yaml whose only output is EVE alerts.

    The stock config also logs every flow, HTTP transaction and DNS query;
    over a 19-million-packet HTTP flood that is gigabytes nobody reads.
    """
    import yaml
    with open(config, encoding='utf-8') as fh:
        text = fh.read()
    body = text.split('\n', 1)[1] if text.startswith('%YAML') else text
    conf = yaml.safe_load(body)
    for output in conf.get('outputs', []):
        (name, settings), = output.items()
        if not isinstance(settings, dict):
            continue
        if name == 'eve-log':
            settings['enabled'] = True
            settings['types'] = [{'alert': {'tagged-packets': False}}]
        else:
            settings['enabled'] = False
    path = os.path.join(workdir, 'suricata.yaml')
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('%YAML 1.1\n---\n' + yaml.safe_dump(conf))
    return path


def run_suricata(binary, rules, config, pcap, workdir):
    """Run Suricata offline over one pcap; return the path of its eve.json."""
    config = alerts_only_config(config, workdir)
    cmd = [binary, '-c', config, '-S', rules, '-r', pcap, '-l', workdir,
           '-k', 'none']
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True)
    if proc.returncode != 0:
        raise SystemExit('suricata failed on %s:\n%s' % (pcap, proc.stdout))
    return os.path.join(workdir, 'eve.json')


def eve_alerts(path, source):
    """Suricata EVE alert events as NetWatch-shaped alert records."""
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            event = json.loads(line)
            if event.get('event_type') != 'alert':
                continue
            alert = event['alert']
            ts = dt.datetime.strptime(event['timestamp'],
                                      '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
            yield {
                'ts': ts,
                'threat_type': 'suricata',
                'signature': alert.get('signature'),
                'category': alert.get('category'),
                'severity': SEVERITY.get(alert.get('severity'), 'INFO'),
                'suricata_severity': alert.get('severity'),
                'src_ip': event.get('src_ip'), 'dst_ip': event.get('dest_ip'),
                'src_port': event.get('src_port'),
                'dst_port': event.get('dest_port'),
                'protocol': event.get('proto'),
                'techniques': [], 'incident_key': None, 'source': source,
            }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--data', required=True)
    ap.add_argument('--rules', required=True, help='suricata.rules file')
    ap.add_argument('--out', required=True)
    ap.add_argument('--captures', required=True,
                    help="NetWatch's captures.json for the same captures")
    ap.add_argument('--truth', default=os.path.join(HERE, 'ground_truth.json'))
    ap.add_argument('--suricata', default='suricata')
    ap.add_argument('--config', default='/etc/suricata/suricata.yaml')
    ap.add_argument('--score-only', action='store_true')
    args = ap.parse_args(argv)

    with open(args.truth, encoding='utf-8') as fh:
        truth = json.load(fh)
    with open(args.captures, encoding='utf-8') as fh:
        durations = {c['name']: c for c in json.load(fh)}
    full_dir = os.path.join(args.out, 'all')
    os.makedirs(os.path.join(full_dir, 'alerts'), exist_ok=True)

    if not args.score_only:
        for cap in truth['captures']:
            out_path = os.path.join(full_dir, 'alerts', cap['name'] + '.jsonl')
            with open(out_path, 'w', encoding='utf-8') as out:
                for member in cap['members']:
                    pcap = os.path.join(args.data,
                                        member_filename(cap['day'], member))
                    work = tempfile.mkdtemp(prefix='suricata-')
                    try:
                        eve = run_suricata(args.suricata, args.rules,
                                           args.config, pcap, work)
                        for record in eve_alerts(eve, cap['name']):
                            out.write(json.dumps(record) + '\n')
                    finally:
                        shutil.rmtree(work, ignore_errors=True)
            print('suricata: %s done' % cap['name'], flush=True)

    reports = []
    for label, min_sev in (('all', 4), ('sev12', 2)):
        target = os.path.join(args.out, label)
        os.makedirs(os.path.join(target, 'alerts'), exist_ok=True)
        summaries = []
        for cap in truth['captures']:
            src = os.path.join(full_dir, 'alerts', cap['name'] + '.jsonl')
            kept = []
            with open(src, encoding='utf-8') as fh:
                for line in fh:
                    record = json.loads(line)
                    if record['suricata_severity'] <= min_sev:
                        kept.append(line)
            if target != full_dir:
                with open(os.path.join(target, 'alerts', cap['name'] + '.jsonl'),
                          'w', encoding='utf-8') as fh:
                    fh.writelines(kept)
            base = durations[cap['name']]
            summaries.append({
                'name': cap['name'], 'packets': base['packets'],
                'capture_hours': base['capture_hours'], 'alerts': len(kept),
                'alerts_by_type': {'suricata': len(kept)},
                'parse_errors': 0, 'detector_errors': 0, 'pkt_per_s': 0,
            })
        result = run.score(truth, summaries, target, pivot_any_type=True)
        result['false_positive_causes'] = top_signatures(target, truth)
        name = ('Suricata + ET Open' if label == 'all'
                else 'Suricata + ET Open, severity 1-2')
        report = run.render(result, args.rules, tool=name)
        with open(os.path.join(target, 'report.md'), 'w',
                  encoding='utf-8') as fh:
            fh.write(report)
        with open(os.path.join(target, 'summary.json'), 'w',
                  encoding='utf-8') as fh:
            json.dump(result, fh, indent=1)
        reports.append(report)
    print('\n\n'.join(reports))
    return 0


def top_signatures(target, truth, limit=15):
    """False-positive alerts grouped by signature, for the report."""
    import collections
    scenarios = truth['scenarios']
    counts = collections.Counter()
    alerts_dir = os.path.join(target, 'alerts')
    for name in os.listdir(alerts_dir):
        with open(os.path.join(alerts_dir, name), encoding='utf-8') as fh:
            for line in fh:
                record = json.loads(line)
                sc, _victim = run.match_scenario(record, scenarios, True)
                if not sc:
                    counts[record['signature']] += 1
    return dict(counts.most_common(limit))


if __name__ == '__main__':
    sys.exit(main())
