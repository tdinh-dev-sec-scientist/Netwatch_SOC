"""
Alert-noise measurement: the untuned posture vs the tuned one.

    python -m tools.noise_experiment
    python -m tools.noise_experiment --json noise_results.json --persist

Replays the *same* PCAP corpus twice — once under config.PROFILES['untuned'],
once under the shipped defaults — and reports the difference in alert volume.
Both runs execute identical code down identical paths; the only thing that
changes is the configuration, and config.profile_diff() prints every value
that differs.

    noise_reduction = (alerts_before - alerts_after) / alerts_before * 100

What "noise" means here matters, so three views are reported rather than one:

  total       every alert on every capture
  benign      alerts raised on the pure-benign baseline. These are false
              positives by construction — an analyst's actual noise.
  attack      alerts raised on captures that do contain an attack. Reducing
              these is deduplication, not error correction: the detection is
              still there, it just is not repeated once per packet.

A reduction in volume is only worth anything if the detections survive it, so
the report also carries the true-positive count under each profile and fails
loudly if tuning lost one.
"""

import argparse
import json
import os
import platform
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as config_module                        # noqa: E402
import pcap_io                                        # noqa: E402
from DB_Manager import DatabaseManager                 # noqa: E402
from tests import replay                               # noqa: E402
from tools import make_pcaps                           # noqa: E402


def measure(profile, root=None, verbose=True):
    """Replay the corpus under one profile and return its alert accounting."""
    if verbose:
        print('replaying corpus under profile=%s ...' % profile)
    summary, rows = replay.run(profile=profile, root=root, verbose=False)

    by_class = {'attack': 0, 'evasion': 0, 'benign': 0}
    by_type = {}
    for row in rows:
        by_class[row['class']] += row['alerts_total']
        for threat, count in row['alerts_by_type'].items():
            by_type[threat] = by_type.get(threat, 0) + count

    return {
        'profile': profile,
        'alerts_total': summary['alerts_total'],
        'alerts_on_benign': by_class['benign'],
        'alerts_on_attack': by_class['attack'] + by_class['evasion'],
        'benign_packets': summary['benign_packets'],
        'packets': summary['packets'],
        'true_positives': summary['combined']['true_positives'],
        'false_negatives': summary['combined']['false_negatives'],
        'false_positives': summary['combined']['false_positives'],
        'true_positive_rate_pct':
            summary['combined']['true_positive_rate_pct'],
        'threat_types_detected': summary['threat_types_detected'],
        'alerts_by_type': dict(sorted(by_type.items())),
        'captures': summary['captures'],
    }


def _reduction(before, after):
    return round((before - after) / before * 100, 2) if before else 0.0


def contributors(before, after, top=5):
    """Which rules account for the reduction, and how much of it each is.

    A single headline percentage says nothing about whether the improvement is
    broad or the work of one pathological rule. This says which.
    """
    removed_total = max(before['alerts_total'] - after['alerts_total'], 0)
    rows = []
    for threat in set(before['alerts_by_type']) | set(after['alerts_by_type']):
        was = before['alerts_by_type'].get(threat, 0)
        now = after['alerts_by_type'].get(threat, 0)
        removed = was - now
        if removed <= 0:
            continue
        rows.append({
            'threat_type': threat,
            'alerts_before': was,
            'alerts_after': now,
            'alerts_removed': removed,
            'share_of_reduction_pct': round(
                removed / removed_total * 100, 2) if removed_total else 0.0,
        })
    rows.sort(key=lambda r: -r['alerts_removed'])
    return rows[:top]


def compare(before, after):
    """Reduction figures, plus whether detection survived the tuning."""
    kept = set(after['threat_types_detected'])
    lost = sorted(set(before['threat_types_detected']) - kept)
    return {
        'alerts_before': before['alerts_total'],
        'alerts_after': after['alerts_total'],
        'total_reduction_pct': _reduction(before['alerts_total'],
                                          after['alerts_total']),
        'benign_alerts_before': before['alerts_on_benign'],
        'benign_alerts_after': after['alerts_on_benign'],
        'benign_reduction_pct': _reduction(before['alerts_on_benign'],
                                           after['alerts_on_benign']),
        'attack_alerts_before': before['alerts_on_attack'],
        'attack_alerts_after': after['alerts_on_attack'],
        'attack_reduction_pct': _reduction(before['alerts_on_attack'],
                                           after['alerts_on_attack']),
        'false_positives_per_10k_benign_packets_before': round(
            before['alerts_on_benign'] / max(before['benign_packets'], 1)
            * 10_000, 3),
        'false_positives_per_10k_benign_packets_after': round(
            after['alerts_on_benign'] / max(after['benign_packets'], 1)
            * 10_000, 3),
        'true_positives_before': before['true_positives'],
        'true_positives_after': after['true_positives'],
        'true_positive_rate_before_pct': before['true_positive_rate_pct'],
        'true_positive_rate_after_pct': after['true_positive_rate_pct'],
        'threat_types_lost_to_tuning': lost,
        'detection_preserved': not lost,
        'formula': 'reduction = (before - after) / before * 100',
    }


def print_report(before, after, delta, diff_rows):
    print('')
    print('Alert-noise reduction — untuned vs tuned, same corpus')
    print('  corpus                     %d captures, %d packets'
          % (after['captures'], after['packets']))
    print('  configuration differences  %d values across %d sections'
          % (len(diff_rows), len({row[0] for row in diff_rows})))
    print('')
    print('  %-26s %12s %12s %10s' % ('', 'untuned', 'tuned', 'reduction'))
    print('  %-26s %12d %12d %9.2f%%'
          % ('alerts, all captures', delta['alerts_before'],
             delta['alerts_after'], delta['total_reduction_pct']))
    print('  %-26s %12d %12d %9.2f%%'
          % ('alerts on benign traffic', delta['benign_alerts_before'],
             delta['benign_alerts_after'], delta['benign_reduction_pct']))
    print('  %-26s %12d %12d %9.2f%%'
          % ('alerts on attack traffic', delta['attack_alerts_before'],
             delta['attack_alerts_after'], delta['attack_reduction_pct']))
    print('  %-26s %12.3f %12.3f'
          % ('false positives / 10k pkts',
             delta['false_positives_per_10k_benign_packets_before'],
             delta['false_positives_per_10k_benign_packets_after']))
    print('')
    print('  %-26s %12d %12d'
          % ('true positives', delta['true_positives_before'],
             delta['true_positives_after']))
    print('  %-26s %11.2f%% %11.2f%%'
          % ('true-positive rate', delta['true_positive_rate_before_pct'],
             delta['true_positive_rate_after_pct']))
    if delta['detection_preserved']:
        print('  detection preserved: no threat type detected under the '
              'untuned profile is lost')
    else:
        print('  WARNING: tuning lost detection of %s'
              % ', '.join(delta['threat_types_lost_to_tuning']))

    print('')
    print('  Loudest detectors under each profile (alerts):')
    types = sorted(set(before['alerts_by_type']) | set(after['alerts_by_type']),
                   key=lambda t: -before['alerts_by_type'].get(t, 0))
    print('    %-22s %10s %10s' % ('threat type', 'untuned', 'tuned'))
    for threat in types[:12]:
        print('    %-22s %10d %10d'
              % (threat, before['alerts_by_type'].get(threat, 0),
                 after['alerts_by_type'].get(threat, 0)))

    print('')
    print('  Where the reduction comes from:')
    for row in contributors(before, after):
        print('    %-22s %6d removed  %6.2f%% of the total reduction'
              % (row['threat_type'], row['alerts_removed'],
                 row['share_of_reduction_pct']))


def print_diff(diff_rows):
    print('')
    print('  Configuration differences (untuned -> tuned):')
    print('    %-20s %-28s %14s %14s'
          % ('section', 'key', 'untuned', 'tuned'))
    for section, key, untuned_value, tuned_value in diff_rows:
        print('    %-20s %-28s %14s %14s'
              % (section, key, untuned_value, tuned_value))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    parser.add_argument('--json', dest='json_path')
    parser.add_argument('--persist', action='store_true',
                        help='record the result in validation_runs')
    parser.add_argument('--show-diff', action='store_true',
                        help='print every configuration value that differs')
    args = parser.parse_args(argv)

    replay.ensure_corpus()
    before = measure('untuned')
    after = measure('tuned')
    delta = compare(before, after)
    diff_rows = config_module.profile_diff('untuned')

    print_report(before, after, delta, diff_rows)
    if args.show_diff:
        print_diff(diff_rows)

    document = {
        'generated_at': time.time(),
        'environment': {
            'python': platform.python_version(),
            'scapy': pcap_io.scapy_version(),
            'platform': '%s %s' % (platform.system(), platform.machine()),
        },
        'untuned': before,
        'tuned': after,
        'delta': delta,
        'contributors': contributors(before, after, top=len(
            set(before['alerts_by_type']) | set(after['alerts_by_type']))),
        'config_diff': [
            {'section': s, 'key': k, 'untuned': u, 'tuned': t}
            for s, k, u, t in diff_rows
        ],
    }
    if args.json_path:
        with open(args.json_path, 'w', encoding='utf-8') as fh:
            json.dump(document, fh, indent=2, sort_keys=True, default=str)
            fh.write('\n')
        print('\nwrote %s' % args.json_path)

    if args.persist:
        db = DatabaseManager()
        try:
            run_id = db.record_validation_run({
                'kind': 'tuning', 'profile': 'untuned->tuned',
                'corpus': 'pcaps/manifest.json',
                'pcap_count': after['captures'], 'packets': after['packets'],
                'true_positives': after['true_positives'],
                'false_positives': after['false_positives'],
                'false_negatives': after['false_negatives'],
                'tpr_pct': after['true_positive_rate_pct'],
                'alerts_total': after['alerts_total'], 'detail': document,
            })
            print('recorded validation_runs id=%s' % run_id)
        finally:
            db.close()

    # Losing a detection to tuning is a failure, however quiet it made things.
    return 0 if delta['detection_preserved'] else 1


if __name__ == '__main__':
    sys.exit(main())
