"""Tests for the PCAP replay validation harness itself.

The harness produces the numbers that end up in docs/VALIDATION.md, so its
arithmetic and its ground-truth handling need to be as tested as the detectors
it scores. These tests use small, hand-built corpora rather than the full
150k-packet one, which is replayed by `python -m tests.replay`.
"""

import json
import os

import pytest

import config as config_module
import pcap_io
from PacketSimulator import TrafficGenerator
from tests import replay
from tools import make_pcaps


# ── scoring arithmetic ───────────────────────────────────────────────────────

def _row(cls, tp, fp, fn, alerts=0, scenario='x'):
    return {
        'file': '%s/%s.pcap' % (cls, scenario), 'class': cls,
        'scenario': scenario, 'packets': 100, 'parse_errors': 0,
        'tp': tp, 'fp': fp, 'fn': fn, 'alerts_total': alerts,
        'true_positives': ['t'] * tp, 'false_positives': ['f'] * fp,
        'false_negatives': ['m'] * fn, 'techniques': [], 'passed': not (fp+fn),
    }


def test_rates_use_the_documented_formulas():
    rows = [_row('attack', tp=3, fp=1, fn=1)]
    rates = replay._rates(rows)
    assert rates['true_positives'] == 3
    assert rates['precision_pct'] == 75.0        # 3 / (3 + 1)
    assert rates['recall_pct'] == 75.0           # 3 / (3 + 1)
    assert rates['true_positive_rate_pct'] == rates['recall_pct']
    assert rates['expected_detections'] == 4     # TP + FN


def test_perfect_and_empty_scores_do_not_divide_by_zero():
    assert replay._rates([])['precision_pct'] == 0.0
    perfect = replay._rates([_row('attack', tp=2, fp=0, fn=0)])
    assert perfect['precision_pct'] == 100.0
    assert perfect['true_positive_rate_pct'] == 100.0


def test_primary_and_evasion_are_scored_separately():
    """A miss on an evasion capture must not move the primary TPR."""
    rows = [_row('attack', tp=2, fp=0, fn=0),
            _row('benign', tp=0, fp=0, fn=0),
            _row('evasion', tp=0, fp=0, fn=1)]
    summary = replay.aggregate(rows, 'tuned', 'test')
    assert summary['primary']['true_positive_rate_pct'] == 100.0
    assert summary['evasion']['true_positive_rate_pct'] == 0.0
    # Combined folds both together.
    assert summary['combined']['true_positive_rate_pct'] == round(
        2 / 3 * 100, 2)
    assert summary['evasions_missed'] == ['x']


def test_benign_alerts_count_as_false_positives():
    entry = {'file': 'benign/b.pcap', 'class': 'benign', 'scenario': None,
             'expected_threats': [], 'sha256': 'x'}

    class Fake:
        threat_type = 'port_scan'
        severity = 'HIGH'
        techniques = ('T1046',)

    row = replay.score_capture(entry, {
        'packets_read': 10, 'packets_parsed': 10, 'parse_errors': 0,
        'elapsed_s': 0.1, 'alerts': [Fake(), Fake()]})
    assert row['fp'] == 1          # one distinct threat type, twice
    assert row['alerts_total'] == 2
    assert not row['passed']


def test_expected_but_absent_threat_is_a_false_negative():
    entry = {'file': 'attack/a.pcap', 'class': 'attack', 'scenario': 'a',
             'expected_threats': ['port_scan'], 'sha256': 'x'}
    row = replay.score_capture(entry, {
        'packets_read': 10, 'packets_parsed': 10, 'parse_errors': 0,
        'elapsed_s': 0.1, 'alerts': []})
    assert row['fn'] == 1 and row['tp'] == 0
    assert row['false_negatives'] == ['port_scan']


# ── replay against real captures ─────────────────────────────────────────────

@pytest.fixture
def mini_corpus(tmp_path):
    """A two-capture corpus: one attack, one benign."""
    root = str(tmp_path / 'pcaps')
    entries = []
    for name, kind, frames in (
            ('port_scan', 'attack', make_pcaps.build_attack('port_scan', 5)),
            ('baseline-5', 'benign', TrafficGenerator(seed=5).background(
                800, start_ts=make_pcaps.BASE_TS))):
        path = os.path.join(root, kind, '%s.pcap' % name)
        pcap_io.write_pcap(path, frames)
        summary = pcap_io.pcap_summary(path)
        entries.append({
            'file': os.path.relpath(path, root), 'class': kind,
            'scenario': name if kind != 'benign' else None,
            'expected_threats': ['port_scan'] if kind == 'attack' else [],
            'seed': 5, 'packets': summary['packets'],
            'duration_s': summary['duration_s'],
            'file_bytes': summary['file_bytes'], 'sha256': summary['sha256'],
        })
    manifest = {'base_ts': make_pcaps.BASE_TS, 'captures': entries,
                'totals': {'files': 2}}
    with open(os.path.join(root, 'manifest.json'), 'w',
              encoding='utf-8') as fh:
        json.dump(manifest, fh)
    return root


def test_replay_detects_the_attack_and_stays_quiet_on_benign(mini_corpus):
    summary, rows = replay.run(root=mini_corpus, verbose=False)
    by_class = {r['class']: r for r in rows}
    assert 'port_scan' in by_class['attack']['true_positives']
    assert by_class['benign']['alerts_total'] == 0
    assert summary['false_negatives'] == 0
    assert summary['true_positive_rate_pct'] == 100.0


def test_replay_is_deterministic(mini_corpus):
    """The same corpus and profile must score identically every time."""
    first, _rows = replay.run(root=mini_corpus, verbose=False)
    second, _rows2 = replay.run(root=mini_corpus, verbose=False)
    for key in ('true_positives', 'false_positives', 'false_negatives',
                'alerts_total', 'true_positive_rate_pct'):
        assert first[key] == second[key], key


def test_replay_isolates_state_between_captures(mini_corpus):
    """Detector state from one capture must not leak into the next."""
    _summary, rows = replay.run(root=mini_corpus, verbose=False)
    benign = [r for r in rows if r['class'] == 'benign'][0]
    assert benign['observed_threats'] == []


def test_replay_records_the_corpus_digest(mini_corpus):
    summary, _rows = replay.run(root=mini_corpus, verbose=False)
    assert summary['corpus'].startswith('manifest:')
    # A changed corpus must produce a different identifier.
    other, _r = replay.run(root=mini_corpus, verbose=False)
    assert summary['corpus'] == other['corpus']


def test_untuned_profile_is_selectable(mini_corpus):
    summary, _rows = replay.run(root=mini_corpus, profile='untuned',
                                verbose=False)
    assert summary['profile'] == 'untuned'


def test_summary_is_json_serialisable(mini_corpus):
    summary, rows = replay.run(root=mini_corpus, verbose=False)
    json.dumps({'summary': summary, 'captures': rows}, default=str)


def test_replay_result_persists_to_the_database(db, mini_corpus):
    """The harness's own output round-trips through validation_runs."""
    summary, _rows = replay.run(root=mini_corpus, verbose=False)
    run_id = db.record_validation_run({
        'kind': 'replay', 'profile': summary['profile'],
        'corpus': summary['corpus'], 'pcap_count': summary['captures'],
        'packets': summary['packets'],
        'true_positives': summary['true_positives'],
        'false_positives': summary['false_positives'],
        'false_negatives': summary['false_negatives'],
        'tpr_pct': summary['true_positive_rate_pct'],
        'alerts_total': summary['alerts_total'], 'detail': summary,
    })
    stored = db.get_validation_runs(kind='replay')[0]
    assert stored['id'] == run_id
    assert stored['tpr_pct'] == summary['true_positive_rate_pct']


# ── ground truth ─────────────────────────────────────────────────────────────

def test_every_capture_class_is_known():
    for name in TrafficGenerator.ALL_SCENARIOS:
        assert TrafficGenerator.scenario_class(name) in ('attack', 'evasion')


def test_evasion_ground_truth_matches_the_attack_it_varies():
    """An evasion must claim the same threat as the attack it is a variant of.

    Otherwise a miss could be hidden by relabelling rather than detecting.
    """
    pairs = {
        'slow_port_scan': 'port_scan',
        'jittered_beacon': 'c2_beacon',
        'fragmented_dns_tunnel': 'dns_tunnel',
        'distributed_exfil': 'data_exfil',
        'throttled_syn_flood': 'syn_flood',
        'slow_brute_force': 'brute_force',
    }
    for evasion, canonical in pairs.items():
        expected = set(TrafficGenerator.expected_threats(evasion))
        assert set(TrafficGenerator.expected_threats(canonical)) <= expected


def test_config_profiles_differ_only_in_documented_sections():
    """Every untuned override must correspond to a real DEFAULTS key."""
    for section, key, untuned_value, tuned_value in \
            config_module.profile_diff('untuned'):
        assert key in config_module.DEFAULTS[section]
        assert untuned_value != tuned_value, \
            '%s.%s is listed as an override but matches DEFAULTS' \
            % (section, key)
