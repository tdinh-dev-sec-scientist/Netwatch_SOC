"""Tests for the Splunk HEC forwarder.

Not collected by the repo's default `pytest` run (pytest.ini sets
testpaths = tests). Run explicitly:

    pytest integrations/splunk -q

The fidelity test is the important one: it runs the real detection engine and
asserts that the correlation key this forwarder derives from stored columns
partitions the alerts exactly as the engine's own unpersisted
`Finding.incident_key` does.
"""

import json
import os
import sqlite3
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

import netwatch_hec as hec              # noqa: E402

SEED = 1337


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def findings_and_db(tmp_path_factory):
    """Run the real engine over a deterministic corpus; return findings + db."""
    import config
    from DB_Manager import DatabaseManager
    from PacketSimulator import PacketSimulator, TrafficGenerator
    from ProtocolAnalyzer import ProtocolAnalyzer
    from ThreatDetector import ThreatDetector

    cfg = config.load()
    path = str(tmp_path_factory.mktemp('hec') / 'netwatch.db')
    db = DatabaseManager(path)
    sim = PacketSimulator(db, ThreatDetector(db, cfg=cfg),
                          ProtocolAnalyzer(), seed=SEED, cfg=cfg)
    gen = TrafficGenerator(seed=SEED)
    end = time.time()
    findings = sim.run_frames(gen.history(end - 90 * 60, end, rate_pps=20.0))
    sim.flush()
    db.close()
    return findings, path


@pytest.fixture(scope='module')
def rows(findings_and_db):
    _findings, path = findings_and_db
    conn = hec.open_db(path)
    out = conn.execute('SELECT * FROM alerts ORDER BY id').fetchall()
    conn.close()
    return out


class _Args:
    index, sourcetype, source, host = 'netwatch', 'netwatch:incident', 's', 'h'


# ── the claim the README makes ──────────────────────────────────────────────

def test_derived_key_partitions_exactly_like_the_engine_key(findings_and_db):
    """No two distinct incidents merge, and no incident splits.

    The engine's key is detector-specific and never written to SQLite, so the
    forwarder reconstructs one from stored columns. If this test fails, the
    reconstruction has drifted and `stats by incident_key` in Splunk would
    miscount incidents.
    """
    findings, _path = findings_and_db
    assert findings, 'corpus produced no findings'

    merged, split = {}, {}
    for f in findings:
        row = {'detector': f.detector, 'threat_type': f.threat_type,
               'src_ip': f.src_ip, 'dst_ip': f.dst_ip}
        derived = hec.incident_key(row, f.evidence)
        real = (f.detector, f.threat_type, f.incident_key)
        merged.setdefault(derived, set()).add(real)
        split.setdefault(real, set()).add(derived)

    assert not [k for k, v in merged.items() if len(v) > 1], \
        'derived key merged distinct incidents'
    assert not [k for k, v in split.items() if len(v) > 1], \
        'derived key split one incident'
    assert len(merged) == len(split)


def test_alert_rows_are_post_dedup(findings_and_db):
    """Every row written is already cooldown-gated, one per incident here."""
    findings, _path = findings_and_db
    incidents = {(f.detector, f.threat_type, f.incident_key) for f in findings}
    assert len(findings) == len(incidents)


# ── timestamp mapping ───────────────────────────────────────────────────────

def test_hec_time_is_the_detection_time_not_now(rows):
    now = time.time()
    for row in rows:
        env = hec.build_event(row, [], _Args)
        assert env['time'] == row['ts']
        assert env['time'] < now, 'event timestamped at or after ingest time'


def test_backfilled_alerts_keep_their_past_timestamps(rows):
    """The corpus spans 90 minutes; events must not collapse onto one time."""
    times = [hec.build_event(r, [], _Args)['time'] for r in rows]
    assert max(times) - min(times) > 600


# ── payload shape ───────────────────────────────────────────────────────────

def test_every_stored_column_is_forwarded_unmodified(rows):
    row = rows[0]
    event = hec.build_event(row, [], _Args)['event']
    for column in ('severity', 'threat_type', 'detector', 'src_ip', 'dst_ip',
                   'src_port', 'dst_port', 'protocol', 'confidence',
                   'description'):
        assert event[column] == row[column], column
    assert event['alert_id'] == row['id']


def test_evidence_is_parsed_into_an_object(rows):
    for row in rows:
        event = hec.build_event(row, [], _Args)['event']
        assert isinstance(event['evidence'], dict)


def test_malformed_evidence_does_not_crash():
    row = {'id': 1, 'ts': 1.0, 'severity': 'LOW', 'threat_type': 't',
           'detector': 'd', 'src_ip': None, 'dst_ip': None, 'src_port': None,
           'dst_port': None, 'protocol': None, 'confidence': 0.5,
           'description': 'x', 'evidence': 'not json', 'acknowledged': 0,
           'ack_ts': None}
    event = hec.build_event(row, [], _Args)['event']
    assert event['evidence']['_unparsed'] == 'not json'


def test_envelope_routes_to_index_and_sourcetype(rows):
    env = hec.build_event(rows[0], [], _Args)
    assert env['index'] == 'netwatch'
    assert env['sourcetype'] == 'netwatch:incident'


def test_techniques_and_tactics_are_flattened(rows):
    techs = [{'technique_id': 'T1046', 'name': 'Network Service Discovery',
              'tactic': 'Discovery', 'url': 'u'}]
    event = hec.build_event(rows[0], techs, _Args)['event']
    assert event['technique_ids'] == ['T1046']
    assert event['tactics'] == ['Discovery']


# ── secret handling ─────────────────────────────────────────────────────────

def test_dry_run_needs_no_token(findings_and_db, monkeypatch, capsys):
    _findings, path = findings_and_db
    monkeypatch.delenv('SPLUNK_HEC_TOKEN', raising=False)
    assert hec.main(['--db', path, '--dry-run', '--limit', '1']) == 0
    assert '"sourcetype": "netwatch:incident"' in capsys.readouterr().out


def test_send_without_token_exits_nonzero_and_says_so(findings_and_db,
                                                      monkeypatch, capsys):
    _findings, path = findings_and_db
    monkeypatch.delenv('SPLUNK_HEC_TOKEN', raising=False)
    assert hec.main(['--db', path, '--no-state']) == 2
    assert 'SPLUNK_HEC_TOKEN' in capsys.readouterr().err


def test_token_never_appears_in_dry_run_output(findings_and_db, monkeypatch,
                                               capsys):
    _findings, path = findings_and_db
    monkeypatch.setenv('SPLUNK_HEC_TOKEN', 'SUPER-SECRET-TOKEN-VALUE')
    hec.main(['--db', path, '--dry-run'])
    captured = capsys.readouterr()
    assert 'SUPER-SECRET-TOKEN-VALUE' not in captured.out
    assert 'SUPER-SECRET-TOKEN-VALUE' not in captured.err


# ── checkpointing ───────────────────────────────────────────────────────────

def test_state_roundtrip_and_resume(tmp_path):
    state = str(tmp_path / 'state.json')
    assert hec.read_state(state) == {'last_alert_id': 0, 'events_forwarded': 0}
    hec.write_state(state, 17, 17)
    assert hec.read_state(state) == {'last_alert_id': 17,
                                     'events_forwarded': 17}
    hec.write_state(state, 20, 20)
    assert hec.read_state(state)['last_alert_id'] == 20
    assert 'SPLUNK_HEC_TOKEN' not in open(state).read()


def test_corrupt_state_file_resets_rather_than_crashing(tmp_path):
    state = str(tmp_path / 'bad.json')
    open(state, 'w').write('{ truncated')
    assert hec.read_state(state)['last_alert_id'] == 0


def test_fetch_alerts_resumes_after_an_id(findings_and_db):
    _findings, path = findings_and_db
    conn = hec.open_db(path)
    everything = hec.fetch_alerts(conn)
    tail = hec.fetch_alerts(conn, since_id=everything[0]['id'])
    conn.close()
    assert len(tail) == len(everything) - 1
    assert all(r['id'] > everything[0]['id'] for r in tail)


# ── read-only safety ────────────────────────────────────────────────────────

def test_connection_cannot_write(findings_and_db):
    _findings, path = findings_and_db
    conn = hec.open_db(path)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO alerts (ts,severity,threat_type,detector,"
                     "confidence,description) VALUES (1,'LOW','x','y',0.1,'z')")
    conn.close()


def test_missing_database_is_a_clean_error(tmp_path):
    with pytest.raises(SystemExit):
        hec.open_db(str(tmp_path / 'nope.db'))


def test_tactic_technique_pairing_survives_multi_technique_alerts(rows):
    """Two techniques in different tactics must stay paired, not cross-join."""
    techs = [{'technique_id': 'T1048', 'name': 'Exfil Over Alt Protocol',
              'tactic': 'Exfiltration', 'url': 'u'},
             {'technique_id': 'T1572', 'name': 'Protocol Tunneling',
              'tactic': 'Command and Control', 'url': 'u'}]
    event = hec.build_event(rows[0], techs, _Args)['event']
    assert event['tactic_technique'] == ['Exfiltration|T1048',
                                         'Command and Control|T1572']
    # the flat lists alone would allow 2x2 = 4 tactic/technique combinations
    assert len(event['tactic_technique']) == 2


def test_real_multi_technique_alerts_exist_in_the_corpus(findings_and_db):
    """Guards the test above against becoming vacuous."""
    findings, _path = findings_and_db
    assert any(len(f.techniques) > 1 for f in findings)


# ── the dashboard and alerts must reference fields that actually exist ──────

def _flatten(obj, prefix=''):
    out = set()
    for key, value in obj.items():
        name = prefix + key
        if isinstance(value, dict):
            out |= _flatten(value, name + '.')
        else:
            out.add(name)
            if isinstance(value, list):
                out.add(name + '{}')
    return out


# Created at search time by props.conf, not by the forwarder.
SPLUNK_SIDE_FIELDS = {'severity_rank', 'src_zone', 'dst_zone', 'dest_ip',
                      'dest_port', 'transport', '_time'}


def test_spl_only_references_fields_the_forwarder_actually_sends(rows):
    """Catches a typo in the dashboard or an alert before Splunk does.

    A misspelled field in SPL is not an error in Splunk -- the panel simply
    renders empty, which looks like "no detections" rather than a bug.
    """
    import re

    available = set(SPLUNK_SIDE_FIELDS)
    for row in rows:
        available |= _flatten(hec.build_event(row, [], _Args)['event'])

    text = ''
    for name in ('savedsearches.conf', 'netwatch_dashboard.xml'):
        with open(os.path.join(HERE, name)) as fh:
            text += fh.read()

    referenced = set(re.findall(r"'(evidence\.[a-z_]+(?:\{\})?)'", text))
    referenced |= set(re.findall(r"\b(evidence\.[a-z_]+)\b", text))
    for field in ('severity', 'threat_type', 'detector', 'src_ip', 'dst_ip',
                  'protocol', 'confidence', 'description', 'incident_key',
                  'alert_id', 'severity_rank', 'src_zone', 'dst_zone'):
        if field in text:
            referenced.add(field)
    for field in ('tactics{}', 'tactic_technique{}', 'technique_ids{}'):
        if field in text:
            referenced.add(field)

    missing = sorted(f for f in referenced if f not in available)
    assert not missing, 'SPL references fields no event carries: %s' % missing
    assert len(referenced) > 15, 'field extraction regex matched almost nothing'


def test_dashboard_is_well_formed_xml_with_the_five_required_panels():
    import xml.etree.ElementTree as ET

    root = ET.parse(os.path.join(HERE, 'netwatch_dashboard.xml')).getroot()
    titles = ' '.join((p.findtext('title') or '').lower()
                      for p in root.iter('panel'))
    for required in ('tactic trend', 'top source hosts', 'coverage',
                     'severity', 'recent incidents'):
        assert required in titles, 'missing panel: %s' % required


def test_every_saved_search_is_scheduled_and_suppressed():
    import configparser

    parser = configparser.ConfigParser(strict=True, interpolation=None)
    parser.read(os.path.join(HERE, 'savedsearches.conf'))
    assert len(parser.sections()) >= 3
    for name in parser.sections():
        stanza = parser[name]
        assert stanza.get('search'), name
        assert stanza.get('cron_schedule'), name
        assert stanza.get('enableSched') == '1', name
        # Without suppression a re-alerting detector reopens the same ticket
        # every cron cycle.
        assert stanza.get('alert.suppress') == '1', name
        assert stanza.get('alert.suppress.fields'), name
        assert 'index=netwatch' in stanza['search'], name
        assert 'sourcetype=netwatch:incident' in stanza['search'], name
