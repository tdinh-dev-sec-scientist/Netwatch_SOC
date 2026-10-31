"""The metric contract (docs/bench/metric-contract.md), case by case."""

import json

import pytest

from netwatch_bench import pack as pack_module
from netwatch_bench import scoring
from netwatch_bench.findings import Filter, FindingError, normalize

T0 = 1_600_000_000.0
ATTACKER, VICTIM, PIVOT = '203.0.113.5', '10.0.0.2', '10.0.0.9'
BOTS = ['10.0.1.1', '10.0.1.2']


@pytest.fixture
def pack(tmp_path):
    raw = {
        'schema': 'netwatch-bench/pack/v0', 'id': 'unit',
        'captures': [{'id': 'a', 'files': ['a.pcap']},
                     {'id': 'b', 'files': ['b.pcap'], 'hosts': 2}],
        'scenarios': [
            {'id': 'brute', 'techniques': ['T1110'],
             'attackers': [ATTACKER], 'victims': [VICTIM],
             'windows': [[T0, T0 + 3600]], 'onset': T0 + 600},
            {'id': 'infil', 'techniques': ['T1046'],
             'attackers': ['198.51.100.7'], 'victims': [PIVOT],
             'pivot': PIVOT, 'windows': [[T0, T0 + 3600]]},
            {'id': 'bot', 'techniques': ['T1071.001'],
             'attackers': ['198.51.100.99'], 'victims': BOTS,
             'per_victim': True, 'windows': [[T0, T0 + 7200]]},
        ],
        'annotations': [
            {'id': 'scanner', 'techniques': ['T1595'],
             'attackers': ['192.0.2.50'], 'victims': [VICTIM],
             'windows': [[T0, T0 + 7200]]},
        ],
    }
    (tmp_path / 'pack.json').write_text(json.dumps(raw))
    return pack_module.load(str(tmp_path))


def f(ts, src, dst, techniques=('T1110',), capture='a', **extra):
    return normalize(dict(ts=T0 + ts, src_ip=src, dst_ip=dst,
                          techniques=list(techniques), capture=capture,
                          engine='test', rule='r', **extra))


FACTS = [{'id': 'a', 'packets': 100, 'host_hours': 2.0},
         {'id': 'b', 'packets': 50, 'host_hours': 2.0}]


def row(card, scenario, victim=None):
    return next(r for r in card['scenarios']
                if r['scenario'] == scenario and r['victim'] == victim)


def test_a_finding_matches_in_either_direction(pack):
    card = scoring.score(pack, [f(700, VICTIM, ATTACKER)], FACTS)
    r = row(card, 'brute')
    assert r['detected'] and r['correct_class']
    assert r['first_alert_after_s'] == 100.0          # measured from onset


def test_outside_the_window_is_a_false_positive(pack):
    card = scoring.score(pack, [f(3601, ATTACKER, VICTIM)], FACTS)
    assert not row(card, 'brute')['detected']
    assert card['noise']['false_alerts'] == 1


def test_wrong_technique_detects_but_does_not_classify(pack):
    card = scoring.score(pack, [f(10, ATTACKER, VICTIM, ['T1190'])], FACTS)
    r = row(card, 'brute')
    assert r['detected'] and r['correct_class'] is False


def test_untyped_findings_are_not_assessable_rather_than_wrong(pack):
    card = scoring.score(pack, [f(10, ATTACKER, VICTIM, [])], FACTS)
    assert row(card, 'brute')['correct_class'] is None
    assert card['classification']['not_assessable'] == 1
    assert card['classification']['n'] == 3     # missed units count as wrong


def test_pivot_findings_need_a_matching_technique(pack):
    lateral = f(10, PIVOT, '10.0.0.50', ['T1046'])
    unrelated = f(20, PIVOT, '10.0.0.51', ['T1041'])
    untyped = f(30, PIVOT, '10.0.0.52', [])
    outbound = f(40, PIVOT, '8.8.8.8', ['T1046'])
    card = scoring.score(pack, [lateral, unrelated, untyped, outbound], FACTS)
    assert row(card, 'infil')['alerts'] == 2          # lateral + untyped
    assert card['noise']['false_alerts'] == 2


def test_per_victim_scenarios_score_each_victim(pack):
    card = scoring.score(pack, [f(10, BOTS[0], '198.51.100.99',
                                  ['T1071.001'])], FACTS)
    assert row(card, 'bot', BOTS[0])['detected']
    assert not row(card, 'bot', BOTS[1])['detected']
    assert card['detection']['n'] == 4                # brute, infil, 2 bots


def test_annotations_explain_but_do_not_excuse(pack):
    card = scoring.score(pack, [f(10, '192.0.2.50', VICTIM, ['T1595'])],
                         FACTS)
    assert card['noise']['false_alerts'] == 1
    assert card['noise']['explained_by_annotations'] == {'scanner': 1}


def test_host_hours_and_rates(pack):
    fps = [f(10 + i, '192.0.2.%d' % i, VICTIM, capture='b')
           for i in range(1, 9)]
    card = scoring.score(pack, fps, FACTS)
    assert card['exposure']['host_hours'] == 4.0
    assert card['noise']['false_alerts_per_host_hour'] == 2.0
    low, high = card['noise']['false_alerts_per_host_hour_ci95']
    assert low < 2.0 < high


def test_incidents_group_pairs_and_victims(pack):
    same_pair = [f(10, ATTACKER, VICTIM), f(100, VICTIM, ATTACKER)]
    gap = [f(100 + scoring.INCIDENT_GAP_S + 1, ATTACKER, VICTIM)]
    flood = [f(10, '192.0.2.%d' % i, '10.0.0.77', group_by='victim')
             for i in range(5)]
    incidents = scoring.correlate(same_pair + gap + flood)
    assert sorted(len(i) for i in incidents) == [1, 2, 5]


def test_findings_without_addresses_are_counted_as_noise(pack):
    bare = normalize({'ts': T0 + 10, 'capture': 'a', 'name': 'decoder'})
    card = scoring.score(pack, [bare, f(10, ATTACKER, VICTIM)], FACTS)
    assert card['noise']['false_alerts'] == 1
    assert card['noise']['without_addresses'] == 1
    assert row(card, 'brute')['detected']


def test_unknown_capture_is_an_error(pack):
    with pytest.raises(ValueError, match='captures the pack does not have'):
        scoring.score(pack, [f(10, ATTACKER, VICTIM, capture='zzz')], FACTS)


def test_normalize_rejects_what_cannot_be_scored():
    with pytest.raises(FindingError, match='ts'):
        normalize({'src_ip': '1.2.3.4', 'capture': 'a'})
    with pytest.raises(FindingError, match='capture'):
        normalize({'ts': 1, 'src_ip': '1.2.3.4'})
    with pytest.raises(FindingError, match='severity'):
        normalize({'ts': 1, 'capture': 'a', 'src_ip': 'x',
                   'severity': 'urgent'})
    out = normalize({'ts': '5', 'capture': 'a', 'src_ip': 'x',
                     'techniques': 't1110', 'severity': 'high'})
    assert out['ts'] == 5.0 and out['techniques'] == ['T1110']
    assert out['severity'] == 'HIGH' and out['group_by'] == 'pair'


def test_filter():
    keep = Filter(min_severity='MEDIUM', exclude_name_prefixes=['SURICATA '],
                  exclude_rules=['sid:9'])
    base = {'severity': 'HIGH', 'name': 'ET SCAN x', 'rule': 'sid:1'}
    assert keep(base)
    assert not keep(dict(base, severity='LOW'))
    assert not keep(dict(base, name='SURICATA STREAM bad'))
    assert not keep(dict(base, rule='sid:9'))
    assert Filter().describe() == {}
    with pytest.raises(FindingError):
        Filter(min_severity='loud')
