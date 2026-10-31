"""NetWatch's own detection pipeline, as one engine among others."""

import os
import subprocess

from .base import Engine, EngineError, file_sha256

# Floods are grouped by victim: their source addresses are often spoofed.
_VICTIM_KEYED = frozenset({'syn_flood', 'udp_flood', 'amplification'})
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def to_finding(record, capture_id):
    """A replay.py finding record as a normalized finding."""
    return {
        'ts': record['ts'], 'capture': capture_id, 'engine': 'netwatch',
        'rule': record['threat_type'], 'name': record['threat_type'],
        'severity': record['severity'], 'techniques': record['techniques'],
        'src_ip': record['src_ip'], 'dst_ip': record['dst_ip'],
        'src_port': record['src_port'], 'dst_port': record['dst_port'],
        'protocol': record['protocol'],
        'group_by': ('victim' if record['threat_type'] in _VICTIM_KEYED
                     else 'pair'),
        'confidence': record.get('confidence'),
        'reason': record.get('reason'),
    }


def _git_commit():
    try:
        out = subprocess.run(['git', '-C', _REPO, 'rev-parse', 'HEAD'],
                             capture_output=True, text=True, timeout=5)
        dirty = subprocess.run(['git', '-C', _REPO, 'status', '--porcelain',
                                '--untracked-files=no'],
                               capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() + ('-dirty' if dirty.stdout.strip() else '')


class NetWatchEngine(Engine):
    name = 'netwatch'

    def __init__(self, config=None, **_ignored):
        self.config_path = config
        if config and not os.path.exists(config):
            raise EngineError('NetWatch config %s does not exist' % config)

    def describe(self):
        return {
            'name': self.name,
            'version': _git_commit(),
            'config': self.config_path or 'shipped defaults',
            'config_sha256': (file_sha256(self.config_path)
                              if self.config_path else None),
        }

    def run(self, capture, paths, workdir):
        import config as config_module
        import replay
        cfg = config_module.load(self.config_path)
        out = []
        replay.replay(paths, cfg,
                      on_finding=lambda r: out.append(to_finding(r, capture.id)))
        return out
