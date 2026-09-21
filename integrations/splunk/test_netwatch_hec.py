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
def corpus_end():
    """One end timestamp for every corpus in this module.

    The backends are compared row for row, so they have to be generated over
    the same span -- calling time.time() twice would shift every `ts`.
    """
    return time.time()


def _write_corpus(target, end):
    """Run the real engine over the deterministic corpus into `target`."""
    import config
    from DB_Manager import DatabaseManager
    from PacketSimulator import PacketSimulator, TrafficGenerator
    from ProtocolAnalyzer import ProtocolAnalyzer
    from ThreatDetector import ThreatDetector

    cfg = config.load()
    db = DatabaseManager(target)
    sim = PacketSimulator(db, ThreatDetector(db, cfg=cfg),
                          ProtocolAnalyzer(), seed=SEED, cfg=cfg)
    gen = TrafficGenerator(seed=SEED)
    findings = sim.run_frames(gen.history(end - 90 * 60, end, rate_pps=20.0))
    sim.flush()
    db.close()
    return findings


@pytest.fixture(scope='module')
def findings_and_db(tmp_path_factory, corpus_end):
    """Run the real engine over a deterministic corpus; return findings + db."""
    path = str(tmp_path_factory.mktemp('hec') / 'netwatch.db')
    return _write_corpus(path, corpus_end), path


@pytest.fixture(scope='module')
def rows(findings_and_db):
    _findings, path = findings_and_db
    reader = hec.open_db(path)
    out = reader.execute('SELECT * FROM alerts ORDER BY id')
    reader.close()
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
    reader = hec.open_db(path)
    everything = hec.fetch_alerts(reader)
    tail = hec.fetch_alerts(reader, since_id=everything[0]['id'])
    reader.close()
    assert len(tail) == len(everything) - 1
    assert all(r['id'] > everything[0]['id'] for r in tail)


# ── read-only safety ────────────────────────────────────────────────────────

def test_connection_cannot_write(findings_and_db):
    _findings, path = findings_and_db
    reader = hec.open_db(path)
    with pytest.raises(sqlite3.OperationalError):
        reader.execute("INSERT INTO alerts (ts,severity,threat_type,detector,"
                       "confidence,description) VALUES (1,'LOW','x','y',0.1,'z')")
    reader.close()


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


# ── PostgreSQL, the deployed backend ────────────────────────────────────────
#
# These skip unless a server is reachable. Point them at one with
# TEST_DATABASE_URL (or DATABASE_URL), or `docker compose up -d postgres`,
# whose defaults tests/conftest.py already matches.

DEFAULT_PG_URL = 'postgresql://netwatch:netwatch@localhost:5432/netwatch'


def _pg_url():
    return (os.environ.get('TEST_DATABASE_URL')
            or os.environ.get('DATABASE_URL')
            or DEFAULT_PG_URL)


@pytest.fixture(scope='module')
def pg_db(corpus_end):
    """The same corpus, written to a scratch PostgreSQL database."""
    import db_backends

    try:
        import psycopg                                 # noqa: F401
    except ImportError:
        pytest.skip('psycopg is not installed')

    dsn = db_backends.with_database(_pg_url(), 'netwatch_hec_test')
    try:
        db_backends.create_database(dsn)
    except Exception as exc:
        pytest.skip('no PostgreSQL available: %s' % exc)

    try:
        _write_corpus(dsn, corpus_end)
        yield dsn
    finally:
        db_backends.drop_database(dsn)


def test_postgres_events_match_sqlite_exactly(pg_db, findings_and_db):
    """The backend must not be observable in what lands in Splunk.

    This is the whole point of reading through `db_backends`: `evidence` is
    TEXT on SQLite and JSONB on PostgreSQL, and `acknowledged` is an int on
    one and a bool on the other. If either leaked through, these envelopes
    would differ.
    """
    _findings, sqlite_path = findings_and_db
    args = _Args()

    def envelopes(target):
        reader = hec.open_db(target)
        try:
            rows = hec.fetch_alerts(reader)
            techs = hec.fetch_techniques(reader, [r['id'] for r in rows])
            return [hec.build_event(r, techs.get(r['id'], []), args)
                    for r in rows]
        finally:
            reader.close()

    from_pg, from_sqlite = envelopes(pg_db), envelopes(sqlite_path)
    assert from_pg, 'no alerts written to PostgreSQL'
    assert len(from_pg) == len(from_sqlite)
    assert from_pg == from_sqlite


def test_postgres_evidence_arrives_parsed(pg_db):
    """jsonb comes back from psycopg as an object, not a string to re-parse."""
    reader = hec.open_db(pg_db)
    try:
        rows = hec.fetch_alerts(reader, limit=1)
        event = hec.build_event(rows[0], [], _Args())['event']
    finally:
        reader.close()
    assert isinstance(event['evidence'], dict)
    assert '_unparsed' not in event['evidence']


def test_postgres_connection_cannot_write(pg_db):
    """Read-only is enforced by the server, not by this script's good manners."""
    import psycopg
    reader = hec.open_db(pg_db)
    try:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            reader.execute(
                "INSERT INTO alerts (ts,severity,threat_type,detector,"
                "confidence,description) VALUES (1,'LOW','x','y',0.1,'z')")
    finally:
        reader.close()


def test_postgres_resumes_after_an_id(pg_db):
    reader = hec.open_db(pg_db)
    try:
        everything = hec.fetch_alerts(reader)
        tail = hec.fetch_alerts(reader, since_id=everything[0]['id'])
    finally:
        reader.close()
    assert len(tail) == len(everything) - 1
    assert all(r['id'] > everything[0]['id'] for r in tail)


def test_technique_chunking_is_backend_independent(pg_db):
    """A backlog larger than one parameter chunk must join identically."""
    reader = hec.open_db(pg_db)
    try:
        ids = [r['id'] for r in hec.fetch_alerts(reader)]
        whole = hec.fetch_techniques(reader, ids)
        reader.max_params = 2          # force many chunks
        chunked = hec.fetch_techniques(reader, ids)
    finally:
        reader.close()
    assert whole == chunked
    assert whole, 'no technique links found'
