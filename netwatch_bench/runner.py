"""Run an engine over a pack and write findings, scorecard and report."""

import datetime as dt
import json
import os
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor

from . import captures as captures_module
from . import manifest, report, scoring
from .findings import normalize, read_jsonl, write_jsonl


def _replay_one(job):
    engine, capture, paths = job
    with tempfile.TemporaryDirectory(prefix='nwbench-') as workdir:
        return [normalize(f, capture.id) for f in
                engine.run(capture, paths, workdir)]


def collect(engine, pack, data_dir=None, jobs=1, progress=None):
    """All normalized findings an engine raises on a pack."""
    if not engine.replays:
        return [normalize(f) for f in engine.findings(pack)]
    work = []
    for capture in pack.captures:
        paths = capture.resolve(data_dir)
        missing = [p for p in paths if not os.path.exists(p)]
        if missing:
            raise FileNotFoundError(
                'capture %s: %s is missing (see the pack README for how to '
                'fetch the dataset)' % (capture.id, missing[0]))
        work.append((engine, capture, paths))
    # Largest first, so a long capture does not start last.
    work.sort(key=lambda j: -sum(os.path.getsize(p) for p in j[2]))
    findings = []
    if jobs > 1 and len(work) > 1:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            for (_e, capture, _p), found in zip(work, pool.map(_replay_one,
                                                               work)):
                findings.extend(found)
                if progress:
                    progress('%s: %d alerts' % (capture.id, len(found)))
    else:
        for job in work:
            found = _replay_one(job)
            findings.extend(found)
            if progress:
                progress('%s: %d alerts' % (job[1].id, len(found)))
    return findings


def describe_captures(pack, data_dir=None, hash_files=True):
    return [captures_module.describe(c, c.resolve(data_dir), hash_files)
            for c in pack.captures]


def scorecard(pack, findings, capture_facts, engine_info, finding_filter,
              argv, started, hashed):
    kept = [f for f in findings if finding_filter(f)]
    card = scoring.score(pack, kept, capture_facts)
    card['limitations'] = pack.limitations
    card['manifest'] = manifest.build(pack, engine_info, capture_facts,
                                      finding_filter, argv, started, hashed)
    for f in kept:
        f.pop('_tp', None)
    return card


def write_outputs(out_dir, card, findings=None):
    os.makedirs(out_dir, exist_ok=True)
    if findings is not None:
        write_jsonl(sorted(findings, key=lambda f: (f['capture'], f['ts'])),
                    os.path.join(out_dir, 'findings.jsonl'))
    with open(os.path.join(out_dir, 'scorecard.json'), 'w',
              encoding='utf-8') as fh:
        json.dump(card, fh, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, 'report.md'), 'w', encoding='utf-8') as fh:
        fh.write(report.markdown(card))


def run(pack, engine, finding_filter, argv, out_dir=None, data_dir=None,
        jobs=1, hash_files=True, progress=None):
    started = dt.datetime.now(dt.timezone.utc)
    engine_info = engine.describe()
    facts = describe_captures(pack, data_dir, hash_files)
    findings = collect(engine, pack, data_dir, jobs, progress)
    card = scorecard(pack, findings, facts, engine_info, finding_filter, argv,
                     started, hash_files)
    if out_dir:
        write_outputs(out_dir, card, findings)
    return card


def rescore(pack, run_dir, finding_filter, argv, out_dir, data_dir=None,
            hash_files=True):
    """Score a previous run's findings again, e.g. with a filter."""
    started = dt.datetime.now(dt.timezone.utc)
    with open(os.path.join(run_dir, 'scorecard.json'), encoding='utf-8') as fh:
        previous = json.load(fh)
    findings = list(read_jsonl(os.path.join(run_dir, 'findings.jsonl')))
    facts = describe_captures(pack, data_dir, hash_files)
    card = scorecard(pack, findings, facts, previous['manifest']['engine'],
                     finding_filter, argv, started, hash_files)
    write_outputs(out_dir, card, findings if out_dir != run_dir else None)
    return card


def stderr(message):
    print(message, file=sys.stderr, flush=True)
