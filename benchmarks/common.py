"""
Shared benchmark plumbing: environment capture, statistics, result writing.

Every benchmark records the machine and settings it ran under alongside its
numbers. A throughput figure without the CPU count, the batch size and the
``synchronous_commit`` setting behind it is not reproducible, and a number
that cannot be reproduced should not end up on a résumé.
"""

import argparse
import datetime as dt
import json
import os
import platform
import statistics
import subprocess
import sys

from sqlalchemy import text

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'results')


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    k = (len(ordered) - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def summarize(values, unit='ms'):
    if not values:
        return {'samples': 0}
    return {
        'samples': len(values),
        'mean_%s' % unit: round(statistics.fmean(values), 4),
        'p50_%s' % unit: round(percentile(values, 50), 4),
        'p95_%s' % unit: round(percentile(values, 95), 4),
        'p99_%s' % unit: round(percentile(values, 99), 4),
        'min_%s' % unit: round(min(values), 4),
        'max_%s' % unit: round(max(values), 4),
        'stdev_%s' % unit: round(statistics.stdev(values), 4)
        if len(values) > 1 else 0.0,
    }


def cpu_count():
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def git_revision():
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:      # noqa: BLE001 - a tarball has no git metadata
        return None


def environment(engine=None):
    """Everything needed to judge whether a rerun is comparable."""
    info = {
        'generated_at': dt.datetime.now(dt.UTC).isoformat(),
        'git_revision': git_revision(),
        'python': sys.version.split()[0],
        'platform': platform.platform(),
        'processor': platform.processor() or platform.machine(),
        'cpu_count': cpu_count(),
        'numpy': _numpy_version(),
    }
    try:
        import psutil
        info['total_memory_mb'] = round(
            psutil.virtual_memory().total / 1024 / 1024)
    except Exception:      # noqa: BLE001 - psutil is optional
        pass
    if engine is not None:
        with engine.connect() as conn:
            info['postgres_version'] = conn.execute(
                text('SHOW server_version')).scalar()
            for setting in ('synchronous_commit', 'shared_buffers',
                            'work_mem', 'max_wal_size', 'wal_level',
                            'effective_cache_size'):
                info['pg_' + setting] = conn.execute(
                    text('SHOW %s' % setting)).scalar()
    return info


def _numpy_version():
    try:
        import numpy
        return numpy.__version__
    except ImportError:
        return None


def write_results(name, payload, path=None):
    """Write machine-readable JSON next to the human-readable stdout."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = path or os.path.join(RESULTS_DIR, '%s.json' % name)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, indent=2, default=str)
        fh.write('\n')
    return path


def rule(title='', width=78):
    if title:
        return '── %s %s' % (title, '─' * max(0, width - len(title) - 4))
    return '─' * width


def add_common_args(parser):
    parser.add_argument('--database-url', default=None,
                        help='overrides NETWATCH_DATABASE_URL')
    parser.add_argument('--json', default=None,
                        help='write results here instead of benchmarks/results')
    parser.add_argument('--keep-data', action='store_true',
                        help='leave the benchmark data in the database')
    return parser


def base_parser(description):
    return add_common_args(argparse.ArgumentParser(description=description))
