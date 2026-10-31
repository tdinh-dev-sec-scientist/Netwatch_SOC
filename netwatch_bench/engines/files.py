"""Adapters for alerts that already exist: no replay, just import."""

import os

from ..findings import read_jsonl
from .base import Engine, EngineError, file_sha256
from .suricata import read_eve


def _single_capture(pack, path):
    if len(pack.captures) != 1:
        raise EngineError(
            '%s: the pack has %d captures; name the capture each file '
            'belongs to as CAPTURE=PATH' % (path, len(pack.captures)))
    return pack.captures[0].id


def _parse(specs, pack, require_capture=True):
    """['eve.json'] or ['cap_a=a.json', 'cap_b=b.json'] -> [(capture, path)].

    Without CAPTURE= the file belongs to the pack's only capture, unless
    `require_capture` is False and the records name their own.
    """
    out = []
    for spec in specs:
        capture, sep, path = spec.partition('=')
        if not sep:
            capture, path = None, spec
        if not os.path.exists(path):
            raise EngineError('%s does not exist' % path)
        out.append((capture, path))
    if not require_capture and len(pack.captures) != 1:
        return out
    return [(c or _single_capture(pack, p), p) for c, p in out]


class _FileEngine(Engine):
    replays = False

    def __init__(self, input=None, engine_name=None, **_ignored):
        if not input:
            raise EngineError('--input is required for the %s engine'
                              % self.name)
        self.specs = input
        self.engine_name = engine_name

    def describe(self):
        return {'name': self.engine_name or self.name, 'imported_from': [
            {'path': s.partition('=')[2] or s,
             'sha256': file_sha256(s.partition('=')[2] or s)}
            for s in self.specs]}


class EveFileEngine(_FileEngine):
    """Suricata EVE output you already have."""
    name = 'eve'

    def findings(self, pack):
        for capture, path in _parse(self.specs, pack):
            yield from read_eve(path, capture)


class FindingsFileEngine(_FileEngine):
    """Any engine's alerts, already in the normalized JSON-lines format."""
    name = 'findings'

    def findings(self, pack):
        for capture, path in _parse(self.specs, pack, require_capture=False):
            for f in read_jsonl(path, default_capture=capture):
                if self.engine_name and f['engine'] == 'unknown':
                    f['engine'] = self.engine_name
                yield f
