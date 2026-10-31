"""
The normalized finding: what every engine adapter emits and the scorer reads.

One JSON object per line. Only `ts`, `capture` and at least one address are
required; everything else improves the report but not the score.

    {"ts": 1518618120.5,            epoch seconds, capture clock
     "capture": "wed14_ftp_ssh",    the pack capture this alert came from
     "engine": "suricata",
     "rule": "sid:2001219",         stable rule identifier within the engine
     "name": "ET SCAN Potential SSH Scan",
     "severity": "MEDIUM",          INFO | LOW | MEDIUM | HIGH | CRITICAL
     "techniques": ["T1110"],       ATT&CK ids the engine attributes, if any
     "src_ip": "...", "dst_ip": "...", "src_port": 22, "dst_port": 51234,
     "protocol": "TCP",
     "group_by": "pair"}            "victim" for floods with spoofed sources

`techniques` is what makes "detected as the right kind of attack" scorable.
An engine that attributes none is still scored on detection and noise; its
classification is reported as not assessable rather than as wrong.
"""

import json

SEVERITIES = ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


class FindingError(ValueError):
    pass


def normalize(record, default_capture=None, where='finding'):
    """Validate one finding dict and fill defaults. Returns a new dict."""
    if not isinstance(record, dict):
        raise FindingError('%s: expected a JSON object' % where)
    try:
        ts = float(record['ts'])
    except (KeyError, TypeError, ValueError):
        raise FindingError('%s: ts (epoch seconds) is required' % where)
    capture = record.get('capture') or default_capture
    if not capture:
        raise FindingError('%s: capture is required when the pack has more '
                           'than one capture' % where)
    if not (record.get('src_ip') or record.get('dst_ip')):
        raise FindingError('%s: src_ip or dst_ip is required' % where)
    severity = str(record.get('severity') or 'INFO').upper()
    if severity not in SEVERITY_RANK:
        raise FindingError('%s: unknown severity %r' % (where, severity))
    techniques = record.get('techniques') or []
    if isinstance(techniques, str):
        techniques = [techniques]
    group_by = record.get('group_by') or 'pair'
    if group_by not in ('pair', 'victim'):
        raise FindingError('%s: group_by must be pair or victim' % where)
    out = dict(record)
    out.update({
        'ts': ts, 'capture': capture,
        'engine': record.get('engine') or 'unknown',
        'rule': str(record.get('rule') or record.get('name') or 'unknown'),
        'name': str(record.get('name') or record.get('rule') or 'unknown'),
        'severity': severity,
        'techniques': sorted({str(t).strip().upper() for t in techniques}),
        'group_by': group_by,
    })
    return out


def read_jsonl(path, default_capture=None):
    """Yield normalized findings from a JSON-lines file."""
    with open(path, encoding='utf-8') as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise FindingError('%s:%d: %s' % (path, lineno, exc))
            yield normalize(record, default_capture, '%s:%d' % (path, lineno))


def write_jsonl(findings, path):
    count = 0
    with open(path, 'w', encoding='utf-8') as fh:
        for f in findings:
            fh.write(json.dumps(f, sort_keys=True, default=str) + '\n')
            count += 1
    return count


class Filter:
    """Select a subset of findings to score, e.g. the usual first tuning steps.

    Recorded in the scorecard, so a filtered result is never mistaken for the
    engine as distributed.
    """

    def __init__(self, min_severity=None, exclude_name_prefixes=(),
                 exclude_rules=()):
        if min_severity is not None:
            min_severity = min_severity.upper()
            if min_severity not in SEVERITY_RANK:
                raise FindingError('unknown severity %r' % min_severity)
        self.min_severity = min_severity
        self.exclude_name_prefixes = tuple(exclude_name_prefixes or ())
        self.exclude_rules = frozenset(exclude_rules or ())

    def __call__(self, finding):
        if (self.min_severity and SEVERITY_RANK[finding['severity']]
                < SEVERITY_RANK[self.min_severity]):
            return False
        if any(finding['name'].startswith(p)
               for p in self.exclude_name_prefixes):
            return False
        return finding['rule'] not in self.exclude_rules

    def describe(self):
        out = {}
        if self.min_severity:
            out['min_severity'] = self.min_severity
        if self.exclude_name_prefixes:
            out['exclude_name_prefixes'] = list(self.exclude_name_prefixes)
        if self.exclude_rules:
            out['exclude_rules'] = sorted(self.exclude_rules)
        return out
