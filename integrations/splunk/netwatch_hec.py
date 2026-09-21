#!/usr/bin/env python3
"""
Forward NetWatch detections from SQLite to Splunk HTTP Event Collector.

WHAT IT FORWARDS
    One event per row of the `alerts` table. That table already holds the
    engine's *post-deduplication* output: every detector gates emission on
    `Detector._cooled_down()` before a finding is ever written, so the raw
    pre-cooldown volume never reaches SQLite. On the benchmark corpus the
    shipped tuning writes 25 rows for 25 distinct incidents (ratio 1.00).
    See README.md for the measurement and its caveat.

TIMESTAMPS
    The HEC `time` field is set from `alerts.ts` — the detection time carried
    from the packet, not the time this script ran. A backfilled alert lands in
    Splunk at its own time. README.md has the SPL that proves it.

SECURITY
    The HEC token is read from $SPLUNK_HEC_TOKEN and from nowhere else. It is
    never logged, never echoed, and never written to the state file. --dry-run
    does not require it.

Standard library + requests. Read-only on the database: opened with
`mode=ro`, so it is safe to run against the live engine's file.
"""

import argparse
import json
import os
import sqlite3
import sys
import time

try:
    import requests
except ImportError:                                    # pragma: no cover
    requests = None

DEFAULT_INDEX = 'netwatch'
DEFAULT_SOURCETYPE = 'netwatch:incident'
DEFAULT_URL = 'https://localhost:8088'
DEFAULT_SOURCE = 'netwatch:engine'
HEC_PATH = '/services/collector/event'

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT_DB = os.environ.get('NETWATCH_DB', os.path.join(REPO, 'netwatch.db'))
DEFAULT_STATE = os.path.join(HERE, '.hec_state.json')

# Evidence keys that distinguish two incidents the stored columns alone would
# merge -- e.g. five http_anomaly incidents from one source to one target that
# differ only by attack category. First key present wins; order is significant
# and is the order the fidelity measurement in README.md was taken with.
DISCRIMINATORS = ('pattern', 'categories', 'sweep_type', 'vector', 'zone',
                  'identified_protocol', 'target', 'service')


# ── correlation key ─────────────────────────────────────────────────────────

def _discriminator(evidence):
    """One stable string from the evidence blob, or '' if none applies."""
    for key in DISCRIMINATORS:
        value = evidence.get(key)
        if value in (None, '', [], ()):
            continue
        if isinstance(value, (list, tuple)):
            return '%s=%s' % (key, ','.join(str(v) for v in value))
        return '%s=%s' % (key, value)
    return ''


def incident_key(row, evidence):
    """A Splunk-side correlation field derived from stored columns only.

    This is NOT the engine's `Finding.incident_key`: that value is detector-
    specific and is not persisted, so it cannot be read back out of SQLite.
    This key is a reconstruction for `stats by` / `transaction` in SPL. On the
    benchmark corpus it groups the alert rows into exactly the same partition
    as the engine's own key (25 groups, 0 merged, 0 split) -- README.md shows
    how that was measured and how to re-measure it.
    """
    return '|'.join([
        row['detector'] or '-',
        row['threat_type'] or '-',
        row['src_ip'] or '-',
        row['dst_ip'] or '-',
        _discriminator(evidence) or '-',
    ])


# ── database (read-only) ────────────────────────────────────────────────────

def open_db(path):
    if not os.path.exists(path):
        raise SystemExit('database not found: %s' % path)
    conn = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_alerts(conn, since_id=0, since_ts=None, limit=None):
    sql = ['SELECT * FROM alerts WHERE id > ?']
    params = [since_id]
    if since_ts is not None:
        sql.append('AND ts >= ?')
        params.append(since_ts)
    sql.append('ORDER BY id ASC')
    if limit:
        sql.append('LIMIT ?')
        params.append(limit)
    return conn.execute(' '.join(sql), params).fetchall()


def fetch_techniques(conn, alert_ids):
    """{alert_id: [{technique_id, name, tactic, url}, ...]} for these alerts."""
    out = {}
    if not alert_ids:
        return out
    # Chunked so a large backlog cannot exceed SQLite's variable limit.
    for start in range(0, len(alert_ids), 500):
        chunk = alert_ids[start:start + 500]
        rows = conn.execute(
            """SELECT at.alert_id, t.technique_id, t.name, t.tactic, t.url
               FROM alert_techniques at
               JOIN mitre_techniques t ON t.technique_id = at.technique_id
               WHERE at.alert_id IN (%s)
               ORDER BY at.alert_id, t.technique_id"""
            % ','.join('?' * len(chunk)), chunk).fetchall()
        for r in rows:
            out.setdefault(r['alert_id'], []).append(
                {'technique_id': r['technique_id'], 'name': r['name'],
                 'tactic': r['tactic'], 'url': r['url']})
    return out


# ── event construction ──────────────────────────────────────────────────────

def build_event(row, techniques, args):
    """One HEC envelope. Every stored column is forwarded raw and unmodified.

    Added on top of the raw columns, and only these:
      incident_key  correlation field (see incident_key() docstring)
      technique_ids / technique_names / tactics / tactic_technique
                    flattened from the alert_techniques join
      evidence      parsed from its stored JSON string into a real object
    No attacker/victim attribution is computed here: src_ip is forwarded as
    the engine recorded it, which for some detectors is the responder rather
    than the initiator. Classify in SPL.
    """
    try:
        evidence = json.loads(row['evidence']) if row['evidence'] else {}
    except (ValueError, TypeError):
        evidence = {'_unparsed': row['evidence']}
    if not isinstance(evidence, dict):
        evidence = {'_value': evidence}

    event = {
        'alert_id': row['id'],
        'ts': row['ts'],
        'severity': row['severity'],
        'threat_type': row['threat_type'],
        'detector': row['detector'],
        'src_ip': row['src_ip'],
        'dst_ip': row['dst_ip'],
        'src_port': row['src_port'],
        'dst_port': row['dst_port'],
        'protocol': row['protocol'],
        'confidence': row['confidence'],
        'description': row['description'],
        'acknowledged': bool(row['acknowledged']),
        'ack_ts': row['ack_ts'],
        'evidence': evidence,
        'incident_key': incident_key(row, evidence),
        'technique_ids': [t['technique_id'] for t in techniques],
        'technique_names': [t['name'] for t in techniques],
        'tactics': sorted({t['tactic'] for t in techniques}),
        # technique_ids and tactics are parallel lists, so an alert mapping to
        # two techniques in different tactics loses the pairing once Splunk
        # turns each into an independent multivalue field. This keeps it: one
        # "tactic|technique" string per mapping, which the coverage panel
        # splits back apart. Without it the tactic x technique matrix
        # cross-joins and invents cells that no alert produced.
        'tactic_technique': ['%s|%s' % (t['tactic'], t['technique_id'])
                             for t in techniques],
    }
    return {
        'time': row['ts'],            # detection time, NOT ingest time
        'host': args.host,
        'source': args.source,
        'sourcetype': args.sourcetype,
        'index': args.index,
        'event': event,
    }


# ── transport ───────────────────────────────────────────────────────────────

def post_batch(session, url, token, envelopes, timeout, verify):
    """POST a batch as newline-delimited HEC envelopes. Returns the response."""
    body = '\n'.join(json.dumps(e, separators=(',', ':'), default=str)
                     for e in envelopes)
    return session.post(
        url.rstrip('/') + HEC_PATH,
        data=body.encode('utf-8'),
        headers={'Authorization': 'Splunk %s' % token,
                 'Content-Type': 'application/json'},
        timeout=timeout, verify=verify)


def read_state(path):
    """Returns {'last_alert_id': int, 'events_forwarded': int}."""
    try:
        with open(path) as fh:
            data = json.load(fh)
        return {'last_alert_id': int(data.get('last_alert_id', 0)),
                'events_forwarded': int(data.get('events_forwarded', 0))}
    except (IOError, OSError, ValueError, TypeError):
        return {'last_alert_id': 0, 'events_forwarded': 0}


def write_state(path, last_id, total_forwarded):
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        json.dump({'last_alert_id': last_id,
                   'events_forwarded': total_forwarded,
                   'updated': time.time()}, fh, indent=2)
        fh.write('\n')
    os.replace(tmp, path)


# ── cli ─────────────────────────────────────────────────────────────────────

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description='Forward NetWatch detections to Splunk HEC.',
        epilog='Token is read from $SPLUNK_HEC_TOKEN only; never pass it on '
               'the command line, where it would land in your shell history.')
    p.add_argument('--db', default=DEFAULT_DB, help='SQLite path (read-only)')
    p.add_argument('--url', default=DEFAULT_URL, help='HEC base URL')
    p.add_argument('--index', default=DEFAULT_INDEX)
    p.add_argument('--sourcetype', default=DEFAULT_SOURCETYPE)
    p.add_argument('--source', default=DEFAULT_SOURCE)
    p.add_argument('--host', default='netwatch', help='Splunk host field')
    p.add_argument('--dry-run', action='store_true',
                   help='print envelopes to stdout, send nothing, no token needed')
    p.add_argument('--since-ts', type=float, default=None,
                   help='only alerts with ts >= this epoch value')
    p.add_argument('--limit', type=int, default=None)
    p.add_argument('--batch-size', type=int, default=100)
    p.add_argument('--timeout', type=float, default=30.0)
    p.add_argument('--state-file', default=DEFAULT_STATE,
                   help='checkpoint of the last forwarded alert id')
    p.add_argument('--no-state', action='store_true',
                   help='ignore and do not update the checkpoint')
    p.add_argument('--ca-cert', default=None,
                   help='CA bundle for the Splunk cert (preferred over --insecure)')
    p.add_argument('--insecure', action='store_true',
                   help='skip TLS verification (self-signed lab Splunk only)')
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    token = os.environ.get('SPLUNK_HEC_TOKEN')
    if not args.dry_run and not token:
        sys.stderr.write(
            'error: SPLUNK_HEC_TOKEN is not set.\n'
            '  export SPLUNK_HEC_TOKEN=...   (or use --dry-run)\n')
        return 2
    if not args.dry_run and requests is None:
        sys.stderr.write('error: the requests package is required to send\n')
        return 2

    state = ({'last_alert_id': 0, 'events_forwarded': 0}
             if (args.no_state or args.dry_run) else read_state(args.state_file))
    since_id = state['last_alert_id']

    conn = open_db(args.db)
    try:
        rows = fetch_alerts(conn, since_id, args.since_ts, args.limit)
        techniques = fetch_techniques(conn, [r['id'] for r in rows])
    finally:
        conn.close()

    if not rows:
        sys.stderr.write('nothing to forward (last_alert_id=%d)\n' % since_id)
        return 0

    envelopes = [build_event(r, techniques.get(r['id'], []), args) for r in rows]

    if args.dry_run:
        for e in envelopes:
            print(json.dumps(e, indent=2, default=str))
        sys.stderr.write(
            '\ndry-run: %d event(s), alert ids %d..%d, nothing sent\n'
            % (len(envelopes), rows[0]['id'], rows[-1]['id']))
        return 0

    verify = args.ca_cert or (not args.insecure)
    if args.insecure:
        sys.stderr.write('warning: TLS verification disabled (--insecure)\n')
        try:
            import urllib3
            urllib3.disable_warnings()
        except ImportError:
            pass

    session = requests.Session()
    sent = 0
    for start in range(0, len(envelopes), args.batch_size):
        batch = envelopes[start:start + args.batch_size]
        try:
            resp = post_batch(session, args.url, token, batch,
                              args.timeout, verify)
        except requests.exceptions.RequestException as exc:
            sys.stderr.write('error: HEC request failed: %s\n' % exc)
            break
        if resp.status_code != 200:
            # resp.text is Splunk's error body; it does not contain the token.
            sys.stderr.write('error: HEC returned %d: %s\n'
                             % (resp.status_code, resp.text[:300]))
            break
        sent += len(batch)

    last_id = rows[sent - 1]['id'] if sent else since_id
    if sent and not args.no_state:
        write_state(args.state_file, last_id,
                    state['events_forwarded'] + sent)

    sys.stderr.write('forwarded %d/%d event(s); last_alert_id=%d\n'
                     % (sent, len(envelopes), last_id))
    return 0 if sent == len(envelopes) else 1


if __name__ == '__main__':
    sys.exit(main())
