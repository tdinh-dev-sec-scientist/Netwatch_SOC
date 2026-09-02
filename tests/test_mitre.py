"""ATT&CK catalog integrity and end-to-end mapping tests."""

import re

from conftest import run_scenario

from netwatch import mitre
from netwatch.analysis.rules import ThreatDetector
from netwatch.capture.generator import TrafficGenerator

TECHNIQUE_ID = re.compile(r'^T\d{4}(\.\d{3})?$')


def test_catalog_has_at_least_twelve_techniques():
    assert mitre.technique_count() >= 12


def test_technique_ids_are_well_formed():
    for tid, tech in mitre.TECHNIQUES.items():
        assert TECHNIQUE_ID.match(tid), 'malformed technique id %r' % tid
        assert tech.id == tid
        assert tech.name and tech.tactic
        assert tech.url.startswith('https://attack.mitre.org/techniques/')
        # Sub-techniques live at .../T1071/004/ rather than .../T1071.004/
        assert tid.split('.')[0] in tech.url


def test_every_technique_explains_its_mapping():
    """Guards against arbitrary mappings: each needs a stated rationale."""
    for tech in mitre.all_techniques():
        assert len(tech.rationale) > 60, \
            '%s rationale is too thin to defend' % tech.id


def test_every_catalogued_technique_is_reachable_from_a_detector(engine):
    """No technique may exist in the catalog without a detector behind it."""
    reachable = set(engine.techniques_covered())
    orphans = set(mitre.TECHNIQUES) - reachable
    assert not orphans, 'techniques no detector can emit: %s' % sorted(orphans)


def test_every_detector_technique_exists_in_catalog(engine):
    for det in engine.detectors:
        for tid in det.techniques:
            assert mitre.get(tid) is not None, \
                '%s emits unknown technique %s' % (det.name, tid)


def test_tactics_are_ordered_and_non_empty():
    tactics = mitre.tactics()
    assert len(tactics) >= 6
    assert 'Discovery' in tactics
    assert 'Command and Control' in tactics
    assert 'Exfiltration' in tactics


def test_scenarios_collectively_exercise_twelve_techniques(analyzer, cfg):
    """Running every attack must actually produce >=12 distinct techniques."""
    observed = set()
    for name in TrafficGenerator.SCENARIOS:
        engine = ThreatDetector(cfg=cfg)
        for finding in run_scenario(engine, analyzer,
                                    TrafficGenerator(seed=11), name):
            observed.update(finding.techniques)
    assert len(observed) >= 12, \
        'only %d techniques observed: %s' % (len(observed), sorted(observed))


def test_mapping_is_specific_not_blanket(engine):
    """A single technique must not be attached to nearly every detector."""
    counts = {}
    for det in engine.detectors:
        for tid in det.techniques:
            counts[tid] = counts.get(tid, 0) + 1
    worst = max(counts.values())
    assert worst <= len(engine.detectors) // 2, \
        'one technique is mapped too broadly: %s' % counts


def test_expected_pairings_are_correct(engine):
    """Spot-check that detectors map to the technique a analyst would expect."""
    expected = {
        'port_scan': 'T1046',
        'network_recon': 'T1595',
        'brute_force': 'T1110',
        'dns_tunnel': 'T1071.004',
        'c2_beacon': 'T1071.001',
        'data_exfil': 'T1041',
        'lateral_movement': 'T1021',
        'arp_spoof': 'T1557.002',
        'icmp_tunnel': 'T1572',
        'syn_flood': 'T1498',
        'udp_flood': 'T1498',
        'amplification': 'T1498.002',
        'http_anomaly': 'T1190',
        'tls_anomaly': 'T1573',
    }
    for detector_name, technique_id in expected.items():
        det = engine.get(detector_name)
        assert det is not None, 'missing detector %s' % detector_name
        assert technique_id in det.techniques, \
            '%s should map to %s, maps to %s' % (detector_name, technique_id,
                                                 det.techniques)


def test_catalog_persists_into_the_database(repo):
    rows = repo.get_mitre_techniques()
    assert len(rows) == mitre.technique_count()
    ids = {r['technique_id'] for r in rows}
    assert ids == set(mitre.TECHNIQUES)
    for row in rows:
        assert row['rationale']
        assert row['tactic']


def _scalar(engine_, sql):
    from sqlalchemy import text
    with engine_.connect() as conn:
        return conn.execute(text(sql)).scalar()


def test_alerts_link_to_techniques_in_the_database(populated_engine):
    assert _scalar(populated_engine,
                   'SELECT COUNT(*) FROM alert_techniques') > 0

    # Every link must resolve to both a real alert and a catalogued technique.
    orphaned = _scalar(populated_engine, """
        SELECT COUNT(*) FROM alert_techniques at
        LEFT JOIN alerts a ON a.id = at.alert_id
        LEFT JOIN mitre_techniques t ON t.technique_id = at.technique_id
        WHERE a.id IS NULL OR t.technique_id IS NULL""")
    assert orphaned == 0

    # And no alert may exist without at least one technique attached.
    unmapped = _scalar(populated_engine, """
        SELECT COUNT(*) FROM alerts a
        WHERE NOT EXISTS (SELECT 1 FROM alert_techniques at
                          WHERE at.alert_id = a.id)""")
    assert unmapped == 0


def test_observed_technique_count_in_database(populated_engine):
    observed = _scalar(
        populated_engine,
        'SELECT COUNT(DISTINCT technique_id) FROM alert_techniques')
    assert observed >= 12, 'only %d techniques observed in DB' % observed
