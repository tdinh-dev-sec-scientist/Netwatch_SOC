"""Detection engine tests: every detector, plus false-positive control."""

import collections

import pytest

import config as config_module
import detectors
import frames as F
import mitre
from PacketSimulator import TrafficGenerator
from ThreatDetector import ThreatDetector

from conftest import BASE_TS, SEED, run_scenario

ALL_SCENARIOS = sorted(TrafficGenerator.SCENARIOS)


def test_registry_covers_at_least_fifteen_threat_types():
    types = {cls.threat_type for cls, _ in detectors.REGISTRY}
    assert len(types) >= 15, 'only %d threat types: %s' % (len(types),
                                                           sorted(types))


def test_every_detector_declares_metadata():
    for cls, section in detectors.REGISTRY:
        assert cls.name and cls.threat_type
        assert cls.description, '%s has no description' % cls.name
        assert cls.techniques, '%s maps to no technique' % cls.name
        assert section in config_module.DEFAULTS


def test_resume_named_categories_all_present():
    """The specific categories the project claims to cover."""
    required = {
        'port_scan', 'brute_force', 'dns_tunnel', 'c2_beacon', 'data_exfil',
        'lateral_movement', 'arp_spoof', 'icmp_tunnel', 'suspicious_dns',
        'syn_flood', 'udp_flood', 'http_anomaly', 'tls_anomaly',
        'credential_attack', 'network_recon',
    }
    assert required <= set(detectors.THREAT_TYPES)


@pytest.mark.parametrize('scenario', ALL_SCENARIOS)
def test_scenario_triggers_expected_detector(engine, analyzer, gen, scenario):
    findings = run_scenario(engine, analyzer, gen, scenario)
    fired = {f.threat_type for f in findings}
    expected = TrafficGenerator.expected_threats(scenario)
    for want in expected:
        assert want in fired, \
            '%s produced %s, expected %s' % (scenario, sorted(fired), want)


@pytest.mark.parametrize('scenario', ALL_SCENARIOS)
def test_findings_are_well_formed(engine, analyzer, gen, scenario):
    for finding in run_scenario(engine, analyzer, gen, scenario):
        assert finding.severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW',
                                    'INFO')
        assert 0.0 <= finding.confidence <= 1.0
        assert finding.reason and len(finding.reason) > 20
        assert finding.techniques
        assert finding.detector and finding.threat_type
        assert finding.ts >= BASE_TS
        assert finding.evidence, 'no supporting evidence recorded'
        for tid in finding.techniques:
            assert mitre.get(tid) is not None


def test_no_false_positives_on_benign_background(engine, analyzer):
    """20k packets of ordinary enterprise traffic must stay silent."""
    generator = TrafficGenerator(seed=99)
    fired = collections.Counter()
    for ts, frame in generator.background(20000, start_ts=BASE_TS):
        pkt = analyzer.safe_parse(frame, ts)
        if pkt is not None:
            for finding in engine.analyze(pkt):
                fired[finding.threat_type] += 1
    assert not fired, 'false positives on benign traffic: %s' % dict(fired)
    assert analyzer.parse_errors == 0


def test_background_exercises_many_protocols(analyzer):
    generator = TrafficGenerator(seed=5)
    for ts, frame in generator.background(5000, start_ts=BASE_TS):
        analyzer.safe_parse(frame, ts)
    assert len(analyzer.stats) >= 15


# ── per-detector behaviour and thresholds ────────────────────────────────────

def test_port_scan_needs_the_configured_port_count(analyzer, cfg):
    threshold = cfg['port_scan']['distinct_ports']
    generator = TrafficGenerator(seed=SEED)

    quiet = ThreatDetector(cfg=cfg)
    below = run_scenario(quiet, analyzer, generator, 'port_scan',
                         ports=threshold - 1)
    assert not [f for f in below if f.threat_type == 'port_scan']

    loud = ThreatDetector(cfg=cfg)
    above = run_scenario(loud, analyzer, TrafficGenerator(seed=SEED),
                         'port_scan', ports=threshold + 5)
    assert [f for f in above if f.threat_type == 'port_scan']


def test_thresholds_are_configurable(analyzer):
    """Raising a threshold must actually suppress a formerly-firing scan."""
    tuned = config_module.load()
    # Both time scales have to be raised: port_scan alerts on a burst inside
    # the short window *or* a slow accumulation inside the long one.
    tuned['port_scan']['distinct_ports'] = 500
    tuned['port_scan']['long_distinct_ports'] = 500
    engine = ThreatDetector(cfg=tuned)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'port_scan', ports=60)
    assert not [f for f in findings if f.threat_type == 'port_scan']


def test_brute_force_attributes_alert_to_the_client(engine, analyzer, gen):
    """The 530 travels server -> client, but the client is the attacker."""
    findings = [f for f in run_scenario(engine, analyzer, gen, 'brute_force')
                if f.threat_type == 'brute_force']
    assert findings
    assert findings[0].src_ip == '45.33.32.156'
    assert findings[0].dst_ip == '10.0.2.12'


def test_brute_force_success_escalates_to_critical(analyzer, cfg):
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'brute_force', attempts=12, succeed=True)
    criticals = [f for f in findings if f.severity == 'CRITICAL']
    assert criticals
    assert any('T1078' in f.techniques for f in criticals)


def test_beacon_requires_low_jitter(analyzer, cfg):
    """Same callback count, but irregular timing must not alert."""
    steady = ThreatDetector(cfg=cfg)
    assert [f for f in run_scenario(
        steady, analyzer, TrafficGenerator(seed=SEED), 'c2_beacon',
        callbacks=14, interval=60.0, jitter=0.01)
        if f.threat_type == 'c2_beacon']

    erratic = ThreatDetector(cfg=cfg)
    assert not [f for f in run_scenario(
        erratic, analyzer, TrafficGenerator(seed=SEED), 'c2_beacon',
        callbacks=14, interval=60.0, jitter=0.85)
        if f.threat_type == 'c2_beacon']


def test_dns_tunnel_ignores_ordinary_long_hostnames(engine, analyzer):
    """Long but low-entropy names (CDN style) must not trip the detector."""
    ts = BASE_TS
    fired = []
    for i in range(80):
        name = 'content-delivery-edge-node-%03d.assets.example.com' % i
        pkt = analyzer.safe_parse(
            F.udp_frame(F.dns_query(name, 'A'), '10.0.1.31', '8.8.8.8',
                        40000 + i, 53), ts)
        fired.extend(f for f in engine.analyze(pkt)
                     if f.threat_type == 'dns_tunnel')
        ts += 0.4
    assert not fired


def test_icmp_tunnel_ignores_normal_pings(engine, analyzer):
    ts = BASE_TS
    fired = []
    for i in range(60):
        pkt = analyzer.safe_parse(
            F.icmp_frame(bytes(range(56)), '10.0.1.27', '10.0.2.10',
                         ident=1, seq=i), ts)
        fired.extend(f for f in engine.analyze(pkt)
                     if f.threat_type == 'icmp_tunnel')
        ts += 1.0
    assert not fired


def test_syn_flood_ignores_completed_handshakes(engine, analyzer, cfg):
    """High SYN volume that is answered is real load, not a flood."""
    ts = BASE_TS
    fired = []
    for i in range(cfg['syn_flood']['syn_rate'] * 2):
        for flags in ('SYN', 'ACK'):
            pkt = analyzer.safe_parse(
                F.tcp_frame(b'', '10.0.1.%d' % (i % 200 + 10), '10.0.2.10',
                            40000 + i, 80, flags), ts)
            fired.extend(f for f in engine.analyze(pkt)
                         if f.threat_type == 'syn_flood')
        ts += 0.01
    assert not fired


def test_data_exfil_ignores_inbound_downloads(engine, analyzer):
    """Same byte volume, but external -> internal is a download."""
    ts = BASE_TS
    fired = []
    for _ in range(4500):
        pkt = analyzer.safe_parse(
            F.tcp_frame(F.tls_application_data(1400), '95.163.1.20',
                        '10.0.1.25', 443, 44000, 'PSH|ACK'), ts)
        fired.extend(f for f in engine.analyze(pkt)
                     if f.threat_type == 'data_exfil')
        ts += 0.02
    assert not fired


def test_lateral_movement_ignores_single_file_server(engine, analyzer):
    ts = BASE_TS
    fired = []
    for i in range(200):
        pkt = analyzer.safe_parse(
            F.tcp_frame(b'', '10.0.1.15', '10.0.2.12', 40000 + i, 445, 'SYN'),
            ts)
        fired.extend(f for f in engine.analyze(pkt)
                     if f.threat_type == 'lateral_movement')
        ts += 0.5
    assert not fired


def test_arp_spoof_detects_binding_conflict(engine, analyzer, gen):
    findings = [f for f in run_scenario(engine, analyzer, gen, 'arp_spoof')
                if f.threat_type == 'arp_spoof']
    patterns = {f.evidence.get('pattern') for f in findings}
    assert 'binding_conflict' in patterns
    assert any(f.severity == 'CRITICAL' for f in findings)


def test_http_anomaly_classifies_attack_categories(engine, analyzer, gen):
    findings = [f for f in run_scenario(engine, analyzer, gen, 'http_attack')
                if f.threat_type == 'http_anomaly']
    categories = set()
    for finding in findings:
        categories.update(finding.evidence.get('categories', []))
    assert {'SQLi', 'Traversal'} <= categories


def test_http_anomaly_survives_url_encoding(engine, analyzer):
    encoded = '/p?id=1%2527%2520UNION%2520ALL%2520SELECT%2520pw%2520FROM%2520users'
    pkt = analyzer.safe_parse(
        F.tcp_frame(F.http_request('GET', encoded, 'shop.local'),
                    '45.33.32.156', '10.0.2.10', 40000, 80), BASE_TS)
    assert [f for f in engine.analyze(pkt) if f.threat_type == 'http_anomaly']


def test_http_anomaly_ignores_benign_requests(engine, analyzer):
    for uri in ('/', '/index.html', '/api/v1/orders?page=2&sort=date',
                '/assets/app.min.js', '/search?q=selective+attention'):
        pkt = analyzer.safe_parse(
            F.tcp_frame(F.http_request('GET', uri, 'shop.local'),
                        '10.0.1.20', '10.0.2.10', 40000, 80), BASE_TS)
        assert not [f for f in engine.analyze(pkt)
                    if f.threat_type == 'http_anomaly']


def test_cleartext_credentials_never_logged(engine, analyzer):
    """Evidence must record that a password was seen, never its value."""
    user = analyzer.safe_parse(
        F.tcp_frame(F.line_protocol('USER alice'), '10.0.1.20',
                    '10.0.2.12', 40000, 21), BASE_TS)
    engine.analyze(user)
    pwd = analyzer.safe_parse(
        F.tcp_frame(F.line_protocol('PASS hunter2'), '10.0.1.20',
                    '10.0.2.12', 40000, 21), BASE_TS + 1)
    cleartext = [f for f in engine.analyze(pwd)
                 if f.evidence.get('pattern') == 'cleartext_credentials']
    assert cleartext
    finding = cleartext[0]
    # The username is operationally useful; the password must never appear.
    assert finding.evidence['username'] == 'alice'
    assert finding.evidence['password_length'] == len('hunter2')
    blob = repr(finding.evidence) + finding.reason
    assert 'hunter2' not in blob


def test_http_basic_credentials_are_detected(engine, analyzer):
    import base64
    header = 'Basic ' + base64.b64encode(b'svc_backup:Tr0ub4dor').decode()
    pkt = analyzer.safe_parse(
        F.tcp_frame(F.http_request('GET', '/admin', 'intranet.local',
                                   authorization=header),
                    '10.0.1.20', '10.0.2.10', 40000, 80), BASE_TS)
    cleartext = [f for f in engine.analyze(pkt)
                 if f.evidence.get('pattern') == 'cleartext_credentials']
    assert cleartext
    assert cleartext[0].evidence['username'] == 'svc_backup'
    assert 'Tr0ub4dor' not in repr(cleartext[0].evidence)


# ── engine behaviour ─────────────────────────────────────────────────────────

def test_engine_rejects_unknown_technique_ids(cfg, monkeypatch):
    class Rogue(detectors.Detector):
        name = threat_type = 'rogue'
        techniques = ('T9999',)

        def inspect(self, pkt):
            return []

    monkeypatch.setattr(detectors, 'REGISTRY',
                        detectors.REGISTRY + [(Rogue, 'port_scan')])
    with pytest.raises(ValueError, match='unknown ATT&CK'):
        ThreatDetector(cfg=cfg)


def test_one_broken_detector_does_not_stop_the_others(engine, analyzer):
    class Exploding:
        name = threat_type = 'boom'
        techniques = ('T1046',)
        packets_seen = findings_emitted = 0

        def inspect(self, pkt):
            raise RuntimeError('detector bug')

        def expire(self, now):
            pass

    engine.detectors.insert(0, Exploding())
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'port_scan')
    assert [f for f in findings if f.threat_type == 'port_scan']
    assert engine.detector_errors > 0


def test_state_is_bounded_by_expiry(engine, analyzer):
    """Detector state must not grow without limit over a long run."""
    generator = TrafficGenerator(seed=3)
    for ts, frame in generator.background(6000, start_ts=BASE_TS):
        pkt = analyzer.safe_parse(frame, ts)
        if pkt is not None:
            engine.analyze(pkt)
    engine.expire(BASE_TS + 86400)
    scan = engine.get('port_scan')
    assert len(scan._ports) == 0
    assert len(scan._last_alert) == 0


def test_packet_without_timestamp_is_stamped(engine, analyzer):
    pkt = analyzer.parse(F.tcp_frame(b'', '10.0.1.5', '10.0.2.5', 40000, 80,
                                     'SYN'))
    assert pkt['ts'] is None
    engine.analyze(pkt)
    assert pkt['ts'] is not None


def test_engine_reports_covered_techniques(engine):
    covered = engine.techniques_covered()
    assert len(covered) >= 12
    assert all(mitre.get(t) for t in covered)


def test_cooldown_suppresses_duplicate_alerts(analyzer, cfg):
    """A sustained scan must not emit one alert per packet."""
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'port_scan', ports=400)
    scans = [f for f in findings if f.threat_type == 'port_scan']
    assert 1 <= len(scans) <= 5, 'expected deduplication, got %d' % len(scans)


# ── evasion variants: the detection boundary ─────────────────────────────────
#
# Each of these is the same attack shaped to sit under a per-window threshold.
# The positive cases prove the second time scale (or the aggregate signal)
# closes the gap; the negative cases prove it did not do so by simply lowering
# the bar for benign traffic.

EVASIONS = sorted(TrafficGenerator.EVASIONS)


@pytest.mark.parametrize('scenario', EVASIONS)
def test_evasion_variant_is_scored_against_the_attack_it_hides(
        engine, analyzer, gen, scenario):
    """Every evasion declares the threat it is a variant of.

    Whether the engine catches it is measured by tests/replay.py; what is
    asserted here is that the ground truth exists, so a miss is recorded as a
    false negative rather than silently going unscored.
    """
    expected = TrafficGenerator.expected_threats(scenario)
    assert expected
    findings = run_scenario(engine, analyzer, gen, scenario)
    for finding in findings:
        assert finding.confidence <= 1.0


def test_slow_port_scan_is_caught_by_the_long_window(analyzer, cfg):
    """A scan paced across windows still accumulates against the slow bar."""
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'slow_port_scan')
    scans = [f for f in findings if f.threat_type == 'port_scan']
    assert scans, 'slow scan evaded both time scales'
    assert scans[0].evidence['pace'] == 'slow'
    # Slower evidence is weaker evidence, and the score says so.
    assert scans[0].confidence <= 0.85


def test_long_window_scan_still_needs_its_own_threshold(analyzer, cfg):
    """Ordinary multi-service traffic must not reach the slow-scan bar."""
    cfg['port_scan']['long_distinct_ports'] = 500
    cfg['port_scan']['distinct_ports'] = 500
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'slow_port_scan')
    assert not [f for f in findings if f.threat_type == 'port_scan']


def test_slow_brute_force_is_caught_by_the_long_window(analyzer, cfg):
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'slow_brute_force')
    hits = [f for f in findings if f.threat_type == 'brute_force']
    assert hits
    assert hits[0].evidence['pace'] == 'slow'


def test_throttled_syn_flood_is_caught_over_a_minute(analyzer, cfg):
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'throttled_syn_flood')
    hits = [f for f in findings if f.threat_type == 'syn_flood']
    assert hits
    assert hits[0].evidence['pace'] == 'throttled'


def test_throttled_flood_still_requires_incomplete_handshakes(analyzer, cfg):
    """The slower window must not drop the handshake-completion guard."""
    engine = ThreatDetector(cfg=cfg)
    findings = []
    ts = BASE_TS
    for i in range(1200):
        # Every SYN is answered by a completed handshake, so this is load.
        for frame in (F.tcp_frame(b'', '10.0.1.%d' % (i % 200 + 10),
                                  '10.0.2.10', 40000 + i, 80, 'SYN'),
                      F.tcp_frame(b'', '10.0.1.%d' % (i % 200 + 10),
                                  '10.0.2.10', 40000 + i, 80, 'ACK')):
            pkt = analyzer.safe_parse(frame, ts)
            findings.extend(engine.analyze(pkt))
        ts += 0.04
    assert not [f for f in findings if f.threat_type == 'syn_flood']


def test_distributed_exfil_is_caught_by_the_per_source_total(analyzer, cfg):
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'distributed_exfil')
    hits = [f for f in findings if f.threat_type == 'data_exfil']
    assert hits
    assert hits[0].evidence['pattern'] == 'distributed'
    assert hits[0].evidence['distinct_peers'] >= 3


def test_per_source_exfil_still_requires_peer_fan_out(analyzer, cfg):
    """One big transfer to one peer must not double-count as distributed."""
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'data_exfil')
    hits = [f for f in findings if f.threat_type == 'data_exfil']
    assert hits
    assert all(f.evidence['pattern'] == 'single_destination' for f in hits)


def test_fragmented_dns_tunnel_is_caught_by_the_label_run(analyzer, cfg):
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'fragmented_dns_tunnel')
    hits = [f for f in findings if f.threat_type == 'dns_tunnel']
    assert hits
    assert hits[0].evidence['encoded_labels'] >= 3


def test_label_run_does_not_fire_on_ordinary_hostnames(engine, analyzer):
    """Multi-label detection must not catch normal three-label domains."""
    findings = []
    for i in range(200):
        frame = F.udp_frame(
            F.dns_query('static%d.assets.cdn.example.com' % i, 'A'),
            '10.0.1.20', '8.8.8.8', 40000 + i, 53)
        pkt = analyzer.safe_parse(frame, BASE_TS + i * 0.2)
        findings.extend(engine.analyze(pkt))
    assert not [f for f in findings if f.threat_type == 'dns_tunnel']


def test_high_jitter_beacon_is_a_known_miss(analyzer, cfg):
    """Documented limitation: CV scoring cannot see through heavy jitter.

    Asserted rather than left implicit so that if a future change does catch
    it, this test fails and the limitation gets removed from the docs instead
    of quietly going stale.
    """
    engine = ThreatDetector(cfg=cfg)
    findings = run_scenario(engine, analyzer, TrafficGenerator(seed=SEED),
                            'jittered_beacon')
    assert not [f for f in findings if f.threat_type == 'c2_beacon']
