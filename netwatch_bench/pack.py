"""
Scenario packs: labelled traffic plus the ground truth to score it against.

A pack is a directory holding `pack.yaml` (or `pack.json`). It names the
captures to replay and the attack scenarios inside them, in terms no engine
owns: addresses, time windows and MITRE ATT&CK techniques. Nothing in a pack
refers to a NetWatch threat type or a Suricata signature, so every engine is
scored against the same answer key.

The format is documented in docs/bench/pack-format.md.
"""

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re

SCHEMA = 'netwatch-bench/pack/v0'

DEFAULT_INTERNAL_NETWORKS = (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '127.0.0.0/8', '169.254.0.0/16',
)

_TECHNIQUE = re.compile(r'^T\d{4}(\.\d{3})?$')
_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')


class PackError(ValueError):
    """The pack is malformed. The message names the offending field."""


def parse_time(value, where):
    """ISO 8601 (naive means UTC) or epoch seconds -> epoch seconds."""
    if isinstance(value, bool):
        raise PackError('%s: expected a time, got %r' % (where, value))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dt.datetime):          # YAML parses bare timestamps
        stamp = value
    elif isinstance(value, str):
        try:
            stamp = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            raise PackError('%s: not an ISO 8601 time: %r' % (where, value))
    else:
        raise PackError('%s: expected a time, got %r' % (where, value))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    return stamp.timestamp()


def technique_matches(found, expected):
    """True if technique `found` is `expected` or one of its sub-techniques.

    An alert tagged T1499.002 satisfies a scenario expecting T1499; an alert
    tagged T1071.004 does not satisfy a scenario expecting T1071.001.
    """
    return found == expected or found.startswith(expected + '.')


def techniques_match(found, expected):
    return any(technique_matches(f, e) for f in found for e in expected)


class Scenario:
    """One labelled attack: who attacked whom, when, and what it is."""

    def __init__(self, raw, where):
        self.raw = raw
        self.id = _require_id(raw, where)
        where = '%s %s' % (where, self.id)
        self.label = str(raw.get('label') or self.id)
        self.techniques = _techniques(raw, where)
        self.attackers = _addresses(raw.get('attackers', []), where + '.attackers')
        self.victims = _addresses(raw.get('victims', []), where + '.victims')
        if not self.victims:
            raise PackError('%s: at least one victim is required' % where)
        self.pivot = raw.get('pivot')
        if self.pivot is not None:
            self.pivot = _addresses([self.pivot], where + '.pivot')[0]
        if not self.attackers and not self.pivot:
            raise PackError('%s: needs attackers, a pivot, or both' % where)
        self.per_victim = bool(raw.get('per_victim', False))
        windows = raw.get('windows')
        if not windows:
            raise PackError('%s: at least one window is required' % where)
        self.windows = []
        for i, window in enumerate(windows):
            if not isinstance(window, (list, tuple)) or len(window) != 2:
                raise PackError('%s.windows[%d]: expected [start, end]'
                                % (where, i))
            lo = parse_time(window[0], '%s.windows[%d][0]' % (where, i))
            hi = parse_time(window[1], '%s.windows[%d][1]' % (where, i))
            if hi <= lo:
                raise PackError('%s.windows[%d]: end is not after start'
                                % (where, i))
            self.windows.append((lo, hi))
        self.windows.sort()
        onset = raw.get('onset')
        self.onset = (parse_time(onset, where + '.onset') if onset is not None
                      else self.windows[0][0])
        self.notes = raw.get('notes')

    def in_window(self, ts):
        return any(lo <= ts <= hi for lo, hi in self.windows)

    def units(self):
        """Scoring units: one per victim for per-victim scenarios, else one."""
        return list(self.victims) if self.per_victim else [None]


class Capture:
    """One capture: one monitored host's sensor, possibly split over files."""

    def __init__(self, raw, where, pack_dir):
        self.id = _require_id(raw, where)
        where = '%s %s' % (where, self.id)
        files = raw.get('files')
        if not files:
            raise PackError('%s: at least one file is required' % where)
        self.files = []
        for i, entry in enumerate(files):
            if isinstance(entry, str):
                entry = {'path': entry}
            if not isinstance(entry, dict):
                raise PackError('%s.files[%d]: expected a mapping' % (where, i))
            if bool(entry.get('path')) == bool(entry.get('data_path')):
                raise PackError('%s.files[%d]: give exactly one of path '
                                '(relative to the pack) or data_path '
                                '(relative to --data)' % (where, i))
            self.files.append({
                'path': entry.get('path'),
                'data_path': entry.get('data_path'),
                'sha256': entry.get('sha256'),
            })
        self.hosts = raw.get('hosts', 1)
        if not isinstance(self.hosts, int) or self.hosts < 1:
            raise PackError('%s.hosts: must be a positive integer' % where)
        self.pack_dir = pack_dir

    def resolve(self, data_dir=None):
        """Absolute paths of this capture's files, in replay order."""
        paths = []
        for entry in self.files:
            if entry['path']:
                paths.append(os.path.normpath(
                    os.path.join(self.pack_dir, entry['path'])))
            else:
                if not data_dir:
                    raise PackError(
                        'capture %s reads %s from the dataset directory; '
                        'pass --data (see the pack README for how to fetch it)'
                        % (self.id, entry['data_path']))
                paths.append(os.path.join(data_dir, entry['data_path']))
        return paths


class Pack:

    def __init__(self, raw, path):
        if not isinstance(raw, dict):
            raise PackError('%s: top level must be a mapping' % path)
        if raw.get('schema') != SCHEMA:
            raise PackError('%s: schema must be %r, got %r'
                            % (path, SCHEMA, raw.get('schema')))
        self.path = path
        self.dir = os.path.dirname(path)
        self.raw = raw
        self.id = _require_id(raw, 'pack')
        self.title = raw.get('title') or self.id
        self.source = raw.get('source') or {}
        self.limitations = list(raw.get('limitations') or [])
        networks = raw.get('internal_networks') or DEFAULT_INTERNAL_NETWORKS
        try:
            self.internal_networks = [ipaddress.ip_network(n) for n in networks]
        except ValueError as exc:
            raise PackError('internal_networks: %s' % exc)

        self.captures = [Capture(c, 'capture', self.dir)
                         for c in raw.get('captures') or []]
        if not self.captures:
            raise PackError('%s: at least one capture is required' % path)
        self.scenarios = [Scenario(s, 'scenario')
                          for s in raw.get('scenarios') or []]
        self.annotations = [Scenario(s, 'annotation')
                            for s in raw.get('annotations') or []]
        for kind, items in (('capture', self.captures),
                            ('scenario', self.scenarios + self.annotations)):
            seen = set()
            for item in items:
                if item.id in seen:
                    raise PackError('duplicate %s id %r' % (kind, item.id))
                seen.add(item.id)

    def is_internal(self, ip):
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in net for net in self.internal_networks)

    def capture(self, capture_id):
        for c in self.captures:
            if c.id == capture_id:
                return c
        raise KeyError(capture_id)

    def sha256(self):
        with open(self.path, 'rb') as fh:
            return hashlib.sha256(fh.read()).hexdigest()


def load(path):
    """Load a pack from a directory or a pack.yaml / pack.json file."""
    if os.path.isdir(path):
        for name in ('pack.yaml', 'pack.yml', 'pack.json'):
            candidate = os.path.join(path, name)
            if os.path.exists(candidate):
                path = candidate
                break
        else:
            raise PackError('%s: no pack.yaml or pack.json inside' % path)
    path = os.path.abspath(path)
    with open(path, encoding='utf-8') as fh:
        text = fh.read()
    if path.endswith('.json'):
        raw = json.loads(text)
    else:
        try:
            import yaml
        except ImportError:
            raise PackError('reading %s needs PyYAML (pip install pyyaml), '
                            'or convert the pack to pack.json' % path)
        raw = yaml.safe_load(text)
    return Pack(raw, path)


def _require_id(raw, where):
    if not isinstance(raw, dict):
        raise PackError('%s: expected a mapping' % where)
    value = raw.get('id')
    if not isinstance(value, str) or not _ID.match(value):
        raise PackError('%s: id must be a short identifier, got %r'
                        % (where, value))
    return value


def _techniques(raw, where):
    values = raw.get('techniques')
    if not values:
        raise PackError('%s: list the ATT&CK techniques this scenario '
                        'exhibits (e.g. [T1110])' % where)
    for value in values:
        if not isinstance(value, str) or not _TECHNIQUE.match(value):
            raise PackError('%s: %r is not an ATT&CK technique id'
                            % (where, value))
    return tuple(values)


def _addresses(values, where):
    out = []
    for value in values:
        try:
            out.append(str(ipaddress.ip_address(value)))
        except ValueError:
            raise PackError('%s: %r is not an IP address' % (where, value))
    return out
