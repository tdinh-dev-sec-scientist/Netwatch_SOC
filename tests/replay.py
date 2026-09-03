"""
PCAP replay validation — the measured detection-quality harness.

    python -m tests.replay                      # replay the whole corpus
    python -m tests.replay --json results.json  # machine-readable output
    python -m tests.replay --profile untuned    # score a different config
    python -m tests.replay --only port_scan     # one capture

Every capture in pcaps/manifest.json is replayed through the *real* pipeline —
Scapy PcapReader -> ProtocolAnalyzer -> ThreatDetector -> DatabaseManager — and
the alerts it produces are scored against the manifest's ground truth.

Scoring, per capture, at the level of a threat *type*:

  TP  an expected threat type was raised on a capture that contains it
  FN  an expected threat type was not raised
  FP  a threat type was raised that the capture is not ground-truthed for
      (on a benign capture, every distinct threat type raised is one FP)

Counting distinct types rather than raw alerts is deliberate. Raw alert counts
would let one noisy detector on one capture swamp the score, and a detector
that fires four times on a real four-minute port scan is not four detections —
it is one, seen repeatedly. Alert volume is reported separately, and it is the
number the noise-reduction experiment works on.

    precision = TP / (TP + FP)
    recall    = TP / (TP + FN)
    TPR       = recall, i.e. of the expected detections, the fraction observed

Each replay uses a fresh detector, a fresh analyzer and a fresh database, so
no state leaks between captures.
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
from PacketSimulator import PacketSimulator            # noqa: E402
from ProtocolAnalyzer import ProtocolAnalyzer          # noqa: E402
from ThreatDetector import ThreatDetector              # noqa: E402
from tools import make_pcaps                           # noqa: E402


def ensure_corpus(root=make_pcaps.PCAP_DIR, rebuild=False):
    """Generate the corpus if it is missing. Returns the manifest."""
    manifest_path = os.path.join(root, 'manifest.json')
    have_files = os.path.exists(manifest_path) and not make_pcaps.check(root) \
        if os.path.exists(manifest_path) else False
    if rebuild or not have_files:
        manifest = make_pcaps.generate(root)
        os.makedirs(root, exist_ok=True)
        with open(manifest_path, 'w', encoding='utf-8') as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
            fh.write('\n')
        return manifest
    return make_pcaps.load_manifest(manifest_path)


def replay_capture(entry, cfg, db=None, rebase_to=None):
    """Replay one capture and return what the engine found.

    `rebase_to` shifts the capture's timestamps so they land in the recent
    past. Detection windows are relative, so this changes nothing about what
    fires; it only keeps the API's time-windowed queries able to see the rows.
    """
    analyzer = ProtocolAnalyzer()
    engine = ThreatDetector(cfg=cfg)
    owns_db = db is None
    if owns_db:
        # Persistence is part of the pipeline under test, so it runs — into a
        # throwaway in-memory-speed SQLite file the caller never sees.
        db = DatabaseManager(os.path.join(
            os.environ.get('NETWATCH_REPLAY_TMP', '/tmp'),
            'netwatch-replay-%d.db' % os.getpid()))
    sim = PacketSimulator(db, engine, analyzer)

    offset = 0.0
    packets = 0
    alerts = []
    started = time.perf_counter()
    for ts, frame in pcap_io.iter_pcap(entry['path']):
        if rebase_to is not None and offset == 0.0:
            offset = rebase_to - ts
        for finding in sim.process(frame, ts + offset):
            alerts.append(finding)
        sim.maybe_flush()
        packets += 1
    sim.flush()
    elapsed = time.perf_counter() - started

    if owns_db:
        db.close()
        try:
            os.unlink(db.db_path)
        except OSError:
            pass

    return {
        'packets_read': packets,
        'packets_parsed': sim.packets_processed,
        'parse_errors': analyzer.parse_errors,
        'elapsed_s': elapsed,
        'alerts': alerts,
    }


def score_capture(entry, result):
    """Compare observed threat types against the capture's ground truth."""
    expected = set(entry['expected_threats'])
    observed = {f.threat_type for f in result['alerts']}

    detected = sorted(expected & observed)
    missed = sorted(expected - observed)
    unexpected = sorted(observed - expected)

    by_type = {}
    for finding in result['alerts']:
        by_type[finding.threat_type] = by_type.get(finding.threat_type, 0) + 1

    return {
        'file': entry['file'],
        'class': entry['class'],
        'scenario': entry['scenario'],
        'sha256': entry['sha256'],
        'packets': result['packets_read'],
        'packets_parsed': result['packets_parsed'],
        'parse_errors': result['parse_errors'],
        'elapsed_s': round(result['elapsed_s'], 4),
        'expected_threats': sorted(expected),
        'observed_threats': sorted(observed),
        'true_positives': detected,
        'false_negatives': missed,
        'false_positives': unexpected,
        'tp': len(detected),
        'fn': len(missed),
        'fp': len(unexpected),
        'alerts_total': len(result['alerts']),
        'alerts_by_type': dict(sorted(by_type.items())),
        'severities': _severity_mix(result['alerts']),
        'techniques': sorted({t for f in result['alerts']
                              for t in f.techniques}),
        'passed': not missed and not unexpected,
    }


def _severity_mix(alerts):
    mix = {}
    for finding in alerts:
        mix[finding.severity] = mix.get(finding.severity, 0) + 1
    return dict(sorted(mix.items()))


def _rates(rows):
    """TP/FP/FN and the derived rates over a subset of captures."""
    tp = sum(r['tp'] for r in rows)
    fp = sum(r['fp'] for r in rows)
    fn = sum(r['fn'] for r in rows)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) \
        if (precision + recall) else 0.0
    return {
        'captures': len(rows),
        'packets': sum(r['packets'] for r in rows),
        'expected_detections': tp + fn,
        'true_positives': tp,
        'false_positives': fp,
        'false_negatives': fn,
        'true_positive_rate_pct': round(recall * 100, 2),
        'precision_pct': round(precision * 100, 2),
        'recall_pct': round(recall * 100, 2),
        'f1_pct': round(f1 * 100, 2),
        'alerts_total': sum(r['alerts_total'] for r in rows),
    }


def aggregate(rows, profile, corpus_id):
    """Roll per-capture scores into the reported detection metrics.

    The headline figures are the canonical attack corpus scored against the
    benign baseline — attacks as they are normally shaped, and the traffic
    they have to be told apart from. The evasion corpus is scored separately
    and reported alongside rather than folded in, because a miss there is a
    statement about where the thresholds sit, not about whether the detector
    works. `combined` is both, for anyone who wants the single number.
    """
    attack_rows = [r for r in rows if r['class'] == 'attack']
    evasion_rows = [r for r in rows if r['class'] == 'evasion']
    benign_rows = [r for r in rows if r['class'] == 'benign']

    primary = _rates(attack_rows + benign_rows)
    summary = dict(primary)
    summary.update({
        'profile': profile,
        'corpus': corpus_id,
        'captures': len(rows),
        'attack_captures': len(attack_rows),
        'evasion_captures': len(evasion_rows),
        'benign_captures': len(benign_rows),
        'packets': sum(r['packets'] for r in rows),
        'parse_errors': sum(r['parse_errors'] for r in rows),
        'alerts_total': sum(r['alerts_total'] for r in rows),
        'alerts_on_attack_captures': sum(r['alerts_total']
                                         for r in attack_rows),
        'alerts_on_evasion_captures': sum(r['alerts_total']
                                          for r in evasion_rows),
        'alerts_on_benign_captures': sum(r['alerts_total']
                                         for r in benign_rows),
        'benign_packets': sum(r['packets'] for r in benign_rows),
        'threat_types_detected': sorted(
            {t for r in rows for t in r['true_positives']}),
        'techniques_observed': sorted({t for r in rows
                                       for t in r['techniques']}),
        'captures_passed': sum(1 for r in rows if r['passed']),
        'primary': primary,
        'evasion': _rates(evasion_rows),
        'combined': _rates(rows),
        'evasions_detected': sorted(
            {r['scenario'] for r in evasion_rows if not r['false_negatives']}),
        'evasions_missed': sorted(
            {r['scenario'] for r in evasion_rows if r['false_negatives']}),
        'formulas': {
            'true_positive_rate': 'TP / (TP + FN)',
            'precision': 'TP / (TP + FP)',
            'unit': 'one (capture, threat_type) pair',
            'primary_scope': 'canonical attack captures + benign baseline',
            'evasion_scope': 'threshold-boundary captures only',
        },
    })
    return summary


def run(profile='tuned', only=None, rebuild=False, root=None,
        rebase=True, verbose=True):
    """Replay the corpus and return (summary, per-capture rows)."""
    root = root or make_pcaps.PCAP_DIR
    manifest = ensure_corpus(root, rebuild=rebuild)
    cfg = config_module.load(profile=profile)

    entries = make_pcaps.captures(manifest, root=root)
    if only:
        wanted = set(only)
        entries = [e for e in entries
                   if e['scenario'] in wanted
                   or os.path.basename(e['file']) in wanted]
        if not entries:
            raise SystemExit('no capture matches %s' % ', '.join(sorted(only)))

    rebase_to = (time.time() - 3600) if rebase else None
    rows = []
    for entry in entries:
        result = replay_capture(entry, cfg, rebase_to=rebase_to)
        row = score_capture(entry, result)
        rows.append(row)
        if verbose:
            _print_row(row)

    corpus_id = 'manifest:%s' % _manifest_digest(manifest)
    summary = aggregate(rows, profile, corpus_id)
    summary['environment'] = {
        'python': platform.python_version(),
        'scapy': pcap_io.scapy_version(),
        'platform': '%s %s' % (platform.system(), platform.machine()),
    }
    return summary, rows


def _manifest_digest(manifest):
    import hashlib
    blob = json.dumps(manifest['captures'], sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _print_row(row):
    status = 'PASS' if row['passed'] else 'FAIL'
    detail = []
    if row['false_negatives']:
        detail.append('missed=%s' % ','.join(row['false_negatives']))
    if row['false_positives']:
        detail.append('unexpected=%s' % ','.join(row['false_positives']))
    print('%-4s %-34s %6d pkts  %3d alerts  %s'
          % (status, row['file'], row['packets'], row['alerts_total'],
             ' '.join(detail)))


def print_summary(summary):
    primary, evasion, combined = (summary['primary'], summary['evasion'],
                                  summary['combined'])
    print('')
    print('PCAP replay — profile=%s' % summary['profile'])
    print('  corpus                %s' % summary['corpus'])
    print('  captures              %d (%d attack, %d evasion, %d benign)'
          % (summary['captures'], summary['attack_captures'],
             summary['evasion_captures'], summary['benign_captures']))
    print('  packets replayed      %d' % summary['packets'])
    print('  parse errors          %d' % summary['parse_errors'])
    print('')
    print('  PRIMARY  canonical attacks + benign baseline'
          '  (%d captures, %d packets)'
          % (primary['captures'], primary['packets']))
    print('    expected detections %d' % primary['expected_detections'])
    print('    TP / FP / FN        %d / %d / %d'
          % (primary['true_positives'], primary['false_positives'],
             primary['false_negatives']))
    print('    true-positive rate  %.2f%%   (TP / (TP + FN))'
          % primary['true_positive_rate_pct'])
    print('    precision           %.2f%%   (TP / (TP + FP))'
          % primary['precision_pct'])
    print('    alerts on benign    %d over %d benign packets'
          % (summary['alerts_on_benign_captures'],
             summary['benign_packets']))
    print('')
    print('  EVASION  threshold-boundary variants  (%d captures)'
          % evasion['captures'])
    print('    expected detections %d' % evasion['expected_detections'])
    print('    detected            %d  (%s)'
          % (evasion['true_positives'],
             ', '.join(summary['evasions_detected']) or 'none'))
    print('    missed              %d  (%s)'
          % (evasion['false_negatives'],
             ', '.join(summary['evasions_missed']) or 'none'))
    print('    detection rate      %.2f%%'
          % evasion['true_positive_rate_pct'])
    print('')
    print('  COMBINED              TPR %.2f%%  precision %.2f%%'
          % (combined['true_positive_rate_pct'], combined['precision_pct']))
    print('  threat types detected %d' % len(summary['threat_types_detected']))
    print('  ATT&CK techniques     %d' % len(summary['techniques_observed']))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    parser.add_argument('--profile', default='tuned',
                        choices=sorted(config_module.PROFILES),
                        help='detection profile to score (default: tuned)')
    parser.add_argument('--only', nargs='+',
                        help='replay only these scenarios or filenames')
    parser.add_argument('--rebuild', action='store_true',
                        help='regenerate the PCAP corpus first')
    parser.add_argument('--json', dest='json_path',
                        help='write the full result document here')
    parser.add_argument('--persist', action='store_true',
                        help='record the summary in validation_runs')
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args(argv)

    summary, rows = run(profile=args.profile, only=args.only,
                        rebuild=args.rebuild, verbose=not args.quiet)
    print_summary(summary)

    document = {'summary': summary, 'captures': rows,
                'generated_at': time.time()}
    if args.json_path:
        with open(args.json_path, 'w', encoding='utf-8') as fh:
            json.dump(document, fh, indent=2, sort_keys=True, default=str)
            fh.write('\n')
        print('\nwrote %s' % args.json_path)

    if args.persist:
        db = DatabaseManager()
        try:
            run_id = db.record_validation_run({
                'kind': 'replay', 'profile': summary['profile'],
                'corpus': summary['corpus'],
                'pcap_count': summary['captures'],
                'packets': summary['packets'],
                'scenarios': summary['attack_captures'],
                'true_positives': summary['true_positives'],
                'false_positives': summary['false_positives'],
                'false_negatives': summary['false_negatives'],
                'precision_pct': summary['precision_pct'],
                'recall_pct': summary['recall_pct'],
                'tpr_pct': summary['true_positive_rate_pct'],
                'alerts_total': summary['alerts_total'],
                'detail': summary,
            })
            print('recorded validation_runs id=%s' % run_id)
        finally:
            db.close()

    # Non-zero exit when anything was missed, so the harness can gate CI.
    return 0 if summary['false_negatives'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
