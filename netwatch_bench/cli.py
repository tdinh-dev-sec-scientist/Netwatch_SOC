"""
netwatch-bench: score network detections against labelled traffic.

    netwatch-bench validate packs/cicids2018-demo
    netwatch-bench run --pack packs/cicids2018-demo --engine netwatch --out runs/nw
    netwatch-bench run --pack packs/cicids2018-demo --engine suricata \\
        --suricata-docker jasonish/suricata:7.0 --out runs/suricata
    netwatch-bench score --pack packs/cicids2018-demo --from runs/suricata \\
        --min-severity MEDIUM --out runs/suricata-sev12
    netwatch-bench compare runs/nw runs/suricata
"""

import argparse
import json
import os
import sys

from . import __version__, report
from .engines import ENGINES, EngineError
from .findings import Filter, FindingError
from .pack import PackError, load

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _filter_args(p):
    g = p.add_argument_group('finding filter (recorded in the scorecard)')
    g.add_argument('--min-severity', metavar='LEVEL',
                   help='drop findings below INFO|LOW|MEDIUM|HIGH|CRITICAL')
    g.add_argument('--exclude-name-prefix', action='append', default=[],
                   metavar='PREFIX', help='drop findings whose name starts '
                   'with PREFIX (e.g. "SURICATA " for engine anomaly events)')
    g.add_argument('--exclude-rule', action='append', default=[],
                   metavar='RULE', help='drop findings from one rule id')


def _common(p):
    p.add_argument('--pack', required=True, help='pack directory or file')
    p.add_argument('--data', help='dataset directory, for packs whose '
                   'captures live outside the repository')
    p.add_argument('--out', help='write findings.jsonl, scorecard.json and '
                   'report.md here')
    p.add_argument('--skip-hash', action='store_true',
                   help='do not hash capture files (faster on large '
                   'datasets; recorded in the manifest)')
    p.add_argument('--json', action='store_true',
                   help='print the scorecard as JSON instead of a summary')


def parser():
    ap = argparse.ArgumentParser(
        prog='netwatch-bench',
        description='Score network detections against labelled traffic.')
    ap.add_argument('--version', action='version',
                    version='netwatch-bench ' + __version__)
    sub = ap.add_subparsers(dest='command', required=True)

    v = sub.add_parser('validate', help='check a pack and its files')
    v.add_argument('pack')
    v.add_argument('--data')

    r = sub.add_parser('run', help='replay a pack through an engine and '
                       'score it')
    _common(r)
    r.add_argument('--engine', required=True, choices=sorted(ENGINES))
    r.add_argument('--jobs', type=int, default=1,
                   help='captures replayed in parallel')
    e = r.add_argument_group('engine options')
    e.add_argument('--config', help='netwatch: JSON threshold overrides')
    e.add_argument('--suricata-bin', help='suricata: local binary')
    e.add_argument('--suricata-docker', metavar='IMAGE',
                   help='suricata: run in this Docker image')
    e.add_argument('--rules', help='suricata: rules file (default with '
                   'Docker: the image\'s bundled ET Open)')
    e.add_argument('--suricata-config', help='suricata: suricata.yaml')
    e.add_argument('--input', action='append', metavar='[CAPTURE=]PATH',
                   help='eve/findings: alert file to import (repeatable)')
    e.add_argument('--engine-name', help='findings: name to report the '
                   'engine as (e.g. zeek, snort, vendor-x)')
    _filter_args(r)

    s = sub.add_parser('score', help='re-score a previous run, e.g. with a '
                       'filter')
    _common(s)
    s.add_argument('--from', dest='run_dir', required=True,
                   help='a run directory written by `run --out`')
    _filter_args(s)

    c = sub.add_parser('compare', help='compare two runs on the same pack')
    c.add_argument('a', help='run directory or scorecard.json')
    c.add_argument('b', help='run directory or scorecard.json')
    c.add_argument('--out', help='write the comparison Markdown here')
    return ap


def _load_card(path):
    if os.path.isdir(path):
        path = os.path.join(path, 'scorecard.json')
    with open(path, encoding='utf-8') as fh:
        return json.load(fh)


def _print_card(card, as_json, out_dir):
    if as_json:
        print(json.dumps(card, indent=1, sort_keys=True))
        return
    sys.stdout.write(report.terminal(card, colour=sys.stdout.isatty()))
    if out_dir:
        print('\n  Report: %s' % os.path.join(out_dir, 'report.md'))


def _validate(args):
    from .captures import describe
    pack = load(args.pack)
    print('%s: %d captures, %d scenarios (%d scoring units), %d annotations'
          % (pack.id, len(pack.captures), len(pack.scenarios),
             sum(len(s.units()) for s in pack.scenarios),
             len(pack.annotations)))
    problems = skipped = 0
    for capture in pack.captures:
        try:
            paths = capture.resolve(args.data)
        except PackError:
            skipped += 1
            print('  skip %s: in the dataset directory (pass --data to check '
                  'its files)' % capture.id)
            continue
        try:
            facts = describe(capture, paths, hash_files=False)
            print('  ok   %s: %s packets, %.2f host-hours'
                  % (capture.id, format(facts['packets'], ','),
                     facts['host_hours']))
        except (OSError, ValueError) as exc:
            problems += 1
            print('  FAIL %s: %s' % (capture.id, exc))
    if skipped:
        print('Schema valid; %d captures not checked.' % skipped)
    return 1 if problems else 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    args = parser().parse_args(argv)
    # NetWatch's own modules live at the repository root.
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    from . import runner
    try:
        if args.command == 'validate':
            return _validate(args)
        if args.command == 'compare':
            result = report.compare(_load_card(args.a), _load_card(args.b))
            text = report.compare_markdown(result)
            if args.out:
                with open(args.out, 'w', encoding='utf-8') as fh:
                    fh.write(text)
            print(text)
            return 0
        pack = load(args.pack)
        finding_filter = Filter(args.min_severity, args.exclude_name_prefix,
                                args.exclude_rule)
        if args.command == 'score':
            out = args.out or args.run_dir
            card = runner.rescore(pack, args.run_dir, finding_filter, argv,
                                  out, args.data, not args.skip_hash)
            _print_card(card, args.json, out)
            return 0
        engine = ENGINES[args.engine](**vars(args))
        card = runner.run(pack, engine, finding_filter, argv, args.out,
                          args.data, args.jobs, not args.skip_hash,
                          progress=None if args.json else runner.stderr)
        _print_card(card, args.json, args.out)
        return 0
    except (PackError, EngineError, FindingError, FileNotFoundError,
            ValueError) as exc:
        print('netwatch-bench: error: %s' % exc, file=sys.stderr)
        return 2
