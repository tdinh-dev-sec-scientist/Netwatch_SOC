"""
The run manifest: everything needed to reproduce a scorecard, and to tell
whether two scorecards can be compared at all.
"""

import datetime as dt
import platform
import sys

from . import __version__


def build(pack, engine_info, captures, finding_filter, argv, started,
          hashed=True):
    return {
        'schema': 'netwatch-bench/manifest/v0',
        'tool': {'name': 'netwatch-bench', 'version': __version__},
        'command': ['netwatch-bench'] + list(argv),
        'started_utc': started.isoformat(),
        'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'pack': {'id': pack.id, 'path': pack.path, 'sha256': pack.sha256(),
                 'source': pack.source},
        'engine': engine_info,
        'filter': finding_filter.describe() or None,
        'inputs_hashed': hashed,
        'captures': [{'id': c['id'], 'files': c['files']} for c in captures],
        'environment': {
            'python': sys.version.split()[0],
            'platform': platform.platform(),
            'machine': platform.machine(),
        },
    }
