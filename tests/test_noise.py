"""Tests for the alert-noise experiment and the config profiles it compares."""

import pytest

import config as config_module
import detectors
from PacketSimulator import TrafficGenerator
from ThreatDetector import ThreatDetector
from tools import noise_experiment

from conftest import BASE_TS, SEED, run_scenario


# ── arithmetic ───────────────────────────────────────────────────────────────

def _profile(name, total, benign, attack, tp, fn, types, by_type,
             benign_packets=1000):
    return {
        'profile': name, 'alerts_total': total, 'alerts_on_benign': benign,
        'alerts_on_attack': attack, 'benign_packets': benign_packets,
        'packets': 10_000, 'true_positives': tp, 'false_negatives': fn,
        'false_positives': 0,
        'true_positive_rate_pct': round(tp / (tp + fn) * 100, 2) if tp + fn
        else 0.0,
        'threat_types_detected': types, 'alerts_by_type': by_type,
        'captures': 4,
    }


def test_reduction_uses_the_documented_formula():
    before = _profile('untuned', 1000, 800, 200, 5, 0, ['a'], {'a': 1000})
    after = _profile('tuned', 250, 0, 250, 5, 0, ['a'], {'a': 250})
    delta = noise_experiment.compare(before, after)
    assert delta['total_reduction_pct'] == 75.0     # (1000-250)/1000
    assert delta['benign_reduction_pct'] == 100.0
    assert delta['attack_reduction_pct'] == -25.0   # volume went up here
    assert delta['formula'] == 'reduction = (before - after) / before * 100'


def test_zero_before_does_not_divide_by_zero():
    quiet = _profile('untuned', 0, 0, 0, 0, 0, [], {})
    delta = noise_experiment.compare(quiet, quiet)
    assert delta['total_reduction_pct'] == 0.0


def test_lost_detection_is_flagged_not_hidden():
    """Quieter is not better if a threat type stopped being detected."""
    before = _profile('untuned', 500, 400, 100, 4, 0, ['a', 'b'],
                      {'a': 400, 'b': 100})
    after = _profile('tuned', 10, 0, 10, 3, 1, ['a'], {'a': 10})
    delta = noise_experiment.compare(before, after)
    assert delta['detection_preserved'] is False
    assert delta['threat_types_lost_to_tuning'] == ['b']


def test_contributors_attribute_the_reduction():
    before = _profile('untuned', 1000, 900, 100, 2, 0, ['a'],
                      {'a': 900, 'b': 100})
    after = _profile('tuned', 100, 0, 100, 2, 0, ['a'], {'a': 50, 'b': 50})
    rows = noise_experiment.contributors(before, after)
    assert rows[0]['threat_type'] == 'a'
    assert rows[0]['alerts_removed'] == 850
    assert sum(r['share_of_reduction_pct'] for r in rows) == pytest.approx(
        100.0, abs=0.5)


def test_false_positive_rate_is_normalised_per_packet():
    before = _profile('untuned', 100, 100, 0, 1, 0, ['a'], {'a': 100},
                      benign_packets=10_000)
    after = _profile('tuned', 1, 1, 0, 1, 0, ['a'], {'a': 1},
                     benign_packets=10_000)
    delta = noise_experiment.compare(before, after)
    assert delta['false_positives_per_10k_benign_packets_before'] == 100.0
    assert delta['false_positives_per_10k_benign_packets_after'] == 1.0


# ── the profiles themselves ──────────────────────────────────────────────────

def test_both_profiles_load_and_build_every_detector():
    for name in config_module.PROFILES:
        cfg = config_module.load(profile=name)
        engine = ThreatDetector(cfg=cfg)
        assert len(engine.detectors) == len(detectors.REGISTRY)


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        config_module.load(profile='does-not-exist')


def test_tuned_profile_is_defaults_unchanged():
    assert config_module.load(profile='tuned') == config_module.load()


def test_untuned_overrides_only_touch_existing_keys():
    """A typo in the profile would silently create a key nothing reads."""
    for section, overrides in config_module.PROFILES['untuned'].items():
        assert section in config_module.DEFAULTS, section
        for key in overrides:
            assert key in config_module.DEFAULTS[section], \
                '%s.%s is not a real threshold' % (section, key)


def test_untuned_profile_deduplicates_rather_than_alerting_per_packet():
    """The baseline must be a plausible first pass, not a worst case.

    With no cooldown at all, every rule alerts once per qualifying packet and
    the comparison measures nothing but that. The untuned profile therefore
    carries a flat dedup timer on every rule.
    """
    cfg = config_module.load(profile='untuned')
    for section, values in cfg.items():
        if isinstance(values, dict) and 'cooldown_s' in values:
            assert values['cooldown_s'] > 0, \
                '%s has no dedup in the untuned profile' % section


def test_untuned_profile_is_noisier_on_benign_traffic(analyzer):
    """The premise of the experiment, asserted directly on benign traffic."""
    generator = TrafficGenerator(seed=SEED)
    frames = generator.background(6000, start_ts=BASE_TS)

    counts = {}
    for name in ('untuned', 'tuned'):
        engine = ThreatDetector(cfg=config_module.load(profile=name))
        found = []
        for ts, frame in frames:
            pkt = analyzer.safe_parse(frame, ts)
            if pkt is not None:
                found.extend(engine.analyze(pkt))
        counts[name] = len(found)

    assert counts['tuned'] == 0, \
        'tuned profile raised %d alerts on benign traffic' % counts['tuned']
    assert counts['untuned'] > 0, \
        'untuned profile is not actually noisier — the comparison is empty'


@pytest.mark.parametrize('scenario', sorted(TrafficGenerator.SCENARIOS))
def test_tuning_did_not_cost_a_canonical_detection(analyzer, scenario):
    """Every canonical attack must still fire under the tuned profile."""
    engine = ThreatDetector(cfg=config_module.load(profile='tuned'))
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            scenario)
    observed = {f.threat_type for f in findings}
    expected = set(TrafficGenerator.expected_threats(scenario))
    assert expected & observed, \
        '%s no longer detected: expected %s, saw %s' % (
            scenario, sorted(expected), sorted(observed))
