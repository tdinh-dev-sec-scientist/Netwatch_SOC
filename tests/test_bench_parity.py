"""
The engine-neutral packs score NetWatch exactly as the v1 scorer did.

eval/cicids2018/run.py produced every published number, matching alerts by
NetWatch threat type. The packs replace threat types with ATT&CK techniques.
This replays the same randomly generated alerts through both scorers, on all
three splits, and requires identical results scenario by scenario, so the
move to an engine-neutral answer key changes no published number.
"""

import json
import os
import random
import sys

import pytest

import detectors
from netwatch_bench import pack as pack_module
from netwatch_bench import scoring
from netwatch_bench.engines.netwatch import to_finding
from netwatch_bench.findings import normalize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL = os.path.join(ROOT, 'eval', 'cicids2018')
sys.path.insert(0, EVAL)
import run as v1  # noqa: E402

# Every technique tuple a NetWatch threat type can carry, including the
# narrower ones single findings use (credential_attack also emits T1078
# alone, brute_force T1110 alone).
TECHNIQUES = {cls.threat_type: [cls.techniques] for cls, _ in detectors.REGISTRY}
TECHNIQUES['credential_attack'].append(('T1078',))
TECHNIQUES['brute_force'].append(('T1110',))

SPLITS = [('ground_truth.json', 'cicids2018-dev'),
          ('holdout.json', 'cicids2018-holdout'),
          ('holdout2.json', 'cicids2018-holdout2')]


def synthetic_alerts(truth, rng, per_capture=12):
    """Alerts aimed at the hard cases: window edges, pivots, both directions,
    wrong types, flood grouping, unrelated hosts.

    Sparse on purpose: with only a few alerts per scoring unit, a single
    wrongly credited technique flips the unit's classification, so a loose
    answer key cannot hide behind a unit that is detected many times over.
    """
    scenarios = truth['scenarios']
    addresses = sorted({ip for sc in scenarios
                        for ip in sc['attackers'] + sc['victims']}
                       | {sc['pivot'] for sc in scenarios if sc.get('pivot')})
    noise = ['172.31.69.%d' % i for i in range(1, 6)] + ['8.8.8.8',
                                                         '52.1.2.3']
    out = {}
    for cap in truth['captures']:
        alerts = []
        for _ in range(per_capture):
            sc = rng.choice(scenarios)
            lo, hi = rng.choice([(v1._epoch(a), v1._epoch(b))
                                 for a, b in sc['windows_utc']])
            ts = rng.choice([lo, hi, rng.uniform(lo, hi), rng.uniform(lo, hi),
                             lo - rng.uniform(1, 900), hi + rng.uniform(1, 900),
                             rng.uniform(lo - 7200, hi + 7200)])
            aimed = rng.random() < 0.6
            if aimed and sc.get('pivot') and rng.random() < 0.5:
                src, dst = sc['pivot'], rng.choice(noise)
            elif aimed:
                src = rng.choice(sc['attackers'])
                dst = rng.choice(sc['victims'])
                if rng.random() < 0.5:
                    src, dst = dst, src
            else:
                src = rng.choice(addresses + noise)
                dst = rng.choice(addresses + noise)
            kind = rng.choice(sorted(TECHNIQUES))
            alerts.append({
                'ts': ts, 'threat_type': kind,
                'techniques': list(rng.choice(TECHNIQUES[kind])),
                'severity': rng.choice(['LOW', 'MEDIUM', 'HIGH']),
                'src_ip': src, 'dst_ip': dst, 'src_port': 1234,
                'dst_port': rng.choice([21, 22, 80, 3389, 445]),
                'protocol': 'TCP', 'incident_key': None, 'source': cap['name'],
            })
        alerts.sort(key=lambda a: a['ts'])
        out[cap['name']] = alerts
    return out


@pytest.mark.parametrize('truth_file, pack_id', SPLITS)
@pytest.mark.parametrize('seed', range(12))
def test_pack_scoring_matches_v1(tmp_path, truth_file, pack_id, seed):
    with open(os.path.join(EVAL, truth_file), encoding='utf-8') as fh:
        truth = json.load(fh)
    alerts = synthetic_alerts(truth, random.Random(seed))

    os.makedirs(tmp_path / 'alerts')
    summaries, facts, findings = [], [], []
    for name, records in alerts.items():
        with open(tmp_path / 'alerts' / (name + '.jsonl'), 'w') as fh:
            for record in records:
                fh.write(json.dumps(record) + '\n')
        summaries.append({'name': name, 'packets': 1000, 'capture_hours': 2.5,
                          'alerts': len(records), 'alerts_by_type': {},
                          'parse_errors': 0, 'detector_errors': 0,
                          'pkt_per_s': 0})
        facts.append({'id': name, 'packets': 1000, 'host_hours': 2.5})
        findings += [normalize(to_finding(r, name)) for r in records]

    old = v1.score(json.loads(json.dumps(truth)), summaries, str(tmp_path))
    pack = pack_module.load(os.path.join(ROOT, 'packs', pack_id))
    new = scoring.score(pack, findings, facts)

    assert old['true_positive_alerts'] > 0, 'the fixture must exercise TPs'
    assert new['alerts']['true_positive'] == old['true_positive_alerts']
    assert new['alerts']['false_positive'] == old['false_positive_alerts']
    assert new['noise']['true_incidents'] == old['true_positive_incidents']
    assert new['noise']['false_incidents'] == old['false_positive_incidents']
    assert new['detection']['k'] == old['attack_units_detected']
    assert new['detection']['n'] == old['attack_units']
    assert new['classification']['k'] == old['attack_units_correct_class']
    for a, b in zip(old['scenarios'], new['scenarios']):
        assert (a['scenario'], a['victim']) == (b['scenario'], b['victim'])
        assert a['detected'] == b['detected']
        assert a['alerts'] == b['alerts']
        assert a['correct_class'] == bool(b['correct_class']), a['scenario']
        # v1 rounds latency to whole seconds, v2 to tenths.
        if a['first_alert_after_s'] is None:
            assert b['first_alert_after_s'] is None
        else:
            assert abs(a['first_alert_after_s']
                       - b['first_alert_after_s']) <= 0.5
