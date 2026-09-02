#!/usr/bin/env python
"""
Sustained-load soak test.

Runs the pipeline at a fixed offered rate for a fixed duration and answers one
question: does it hold up, or does it quietly lose packets and grow?

    python -m benchmarks.soak_test --minutes 10 --rate 4000
    python -m benchmarks.soak_test --minutes 30 --rate 4000 --drop-on-overflow

The claim "zero dropped frames" is only allowed to appear anywhere if this
test reports it, so the accounting is explicit and checked rather than
assumed. Every frame the capture stage pulls off its source lands in exactly
one bucket:

    frames_captured == packets_persisted
                     + packets_dropped
                     + packets_parse_failed
                     + packets_write_failed

The test fails (non-zero exit) if that identity does not hold, if the run
drops or fails a packet under the default backpressure policy, or if resident
memory grows beyond the configured ceiling. Growth is the interesting failure:
a pipeline with an unbounded queue passes a throughput benchmark and dies in a
soak, which is exactly what the bounded queues exist to prevent.

``--drop-on-overflow`` runs the same load with the DROP policy instead of
BLOCK. That run is *expected* to drop packets when the offered rate exceeds
what the pipeline can sustain, and it is how the loss accounting itself is
verified: the drops must be counted, attributable to a named queue, and must
still balance the identity.
"""

import sys
import time

from benchmarks.common import base_parser, environment, rule, write_results
from netwatch import config as config_module
from netwatch.analysis.rules import RulesEngine
from netwatch.capture.source import SyntheticSource
from netwatch.db import schema as schema_mod
from netwatch.db import session as session_mod
from netwatch.db.repository import Repository
from netwatch.db.writer import BatchWriter
from netwatch.pipeline import Pipeline, PipelineConfig
from netwatch.pipeline.queues import OverflowPolicy


def sample_loop(pipeline, interval_s, deadline, samples):
    """Record queue depth, RSS and cumulative counts on a fixed cadence."""
    next_sample = time.time()
    while time.time() < deadline and not pipeline.wait(timeout=0.0):
        now = time.time()
        if now >= next_sample:
            snap = pipeline.snapshot()
            samples.append({
                'at': round(now - pipeline.started_at, 2),
                'captured': snap['accounting']['frames_captured'],
                'persisted': snap['accounting']['packets_persisted'],
                'dropped': snap['accounting']['packets_dropped'],
                'in_flight': snap['accounting']['in_flight'],
                'queue_depths': {q['name']: q['depth']
                                 for q in snap['queues']},
                'rss_mb': snap['resources'].get('peak_rss_mb', 0.0),
                'cpu_percent': snap['resources'].get('mean_cpu_percent', 0.0),
            })
            next_sample = now + interval_s
        time.sleep(min(0.25, interval_s))


def main(argv=None):
    parser = base_parser('NetWatch sustained-load soak test')
    parser.add_argument('--minutes', type=float, default=10.0)
    parser.add_argument('--rate', type=float, default=4000.0,
                        help='offered packets/sec; 0 means unthrottled')
    parser.add_argument('--batch-size', type=int, default=2000)
    parser.add_argument('--persist-workers', type=int, default=2)
    parser.add_argument('--chunk-size', type=int, default=256)
    parser.add_argument('--queue-size', type=int, default=16,
                        help='queue capacity in chunks')
    parser.add_argument('--sample-interval-s', type=float, default=5.0)
    parser.add_argument('--max-rss-mb', type=float, default=1024.0,
                        help='fail the run if resident memory exceeds this')
    parser.add_argument('--drop-on-overflow', action='store_true')
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--reset', action='store_true')
    args = parser.parse_args(argv)

    engine = session_mod.get_engine(args.database_url)
    if args.reset:
        schema_mod.drop_all(engine)
    schema_mod.create_all(engine)
    schema_mod.seed_reference_data(engine)
    protocol_ids, threat_ids = schema_mod.lookup_maps(engine)
    repository = Repository(engine)
    before_rows = repository.health()['tables']

    duration_s = args.minutes * 60.0
    policy = (OverflowPolicy.DROP if args.drop_on_overflow
              else OverflowPolicy.BLOCK)

    print('NetWatch soak test')
    env = environment(engine)
    print('  duration : %.1f minutes' % args.minutes)
    print('  offered  : %s packets/sec'
          % ('unthrottled' if not args.rate else '%.0f' % args.rate))
    print('  policy   : %s  (batch=%d, persist workers=%d, chunk=%d)'
          % (policy, args.batch_size, args.persist_workers, args.chunk_size))
    print('  postgres : %s (synchronous_commit=%s)\n'
          % (env['postgres_version'], env['pg_synchronous_commit']))

    source = SyntheticSource(seed=args.seed, rate_pps=args.rate or None,
                             duration_s=duration_s, scenario_every_s=20.0)
    pipeline = Pipeline(
        source, RulesEngine(cfg=config_module.load()),
        lambda: BatchWriter(engine, protocol_ids, threat_ids),
        config=PipelineConfig(
            persist_workers=args.persist_workers, batch_size=args.batch_size,
            chunk_size=args.chunk_size, capture_queue=args.queue_size,
            rules_queue=args.queue_size,
            persist_queue=int(args.queue_size * 1.5) or 1,
            overflow_policy=policy))

    samples = []
    started = time.perf_counter()
    pipeline.start()
    sample_loop(pipeline, args.sample_interval_s,
                time.time() + duration_s + 120, samples)
    pipeline.wait(timeout=300)
    elapsed = time.perf_counter() - started
    report = pipeline.report()

    acct = report['accounting']
    latency = report['latency_end_to_end_ms']
    resources = report['resources']
    rss_series = [s['rss_mb'] for s in samples if s['rss_mb']]
    peak_depths = {}
    for sample in samples:
        for name, depth in sample['queue_depths'].items():
            peak_depths[name] = max(peak_depths.get(name, 0), depth)

    print(rule('Result'))
    print('  Packets generated:   %d' % acct['frames_captured'])
    print('  Packets processed:   %d' % acct['packets_persisted'])
    print('  Packets dropped:     %d' % acct['packets_dropped'])
    print('  Packets failed:      %d'
          % (acct['packets_parse_failed'] + acct['packets_write_failed']))
    print('    parse failures:    %d' % acct['packets_parse_failed'])
    print('    write failures:    %d' % acct['packets_write_failed'])
    print('  Alerts persisted:    %d' % acct['alerts_persisted'])
    print('  Duration:            %.1f s' % elapsed)
    print('  Throughput:          %.1f packets/sec'
          % (acct['packets_persisted'] / elapsed))
    print('  P50 latency:         %.2f ms' % latency['p50_ms'])
    print('  P95 latency:         %.2f ms' % latency['p95_ms'])
    print('  P99 latency:         %.2f ms' % latency['p99_ms'])
    print('  Max latency:         %.2f ms' % latency['max_ms'])
    if resources.get('available'):
        print('  Peak memory:         %.1f MB' % resources['peak_rss_mb'])
        print('  Mean CPU:            %.1f%% of %d cores'
              % (resources['mean_cpu_percent'], resources['cpu_count']))
    print('  RSS first -> last:   %.1f -> %.1f MB over %d samples'
          % (rss_series[0] if rss_series else 0.0,
             rss_series[-1] if rss_series else 0.0, len(samples)))

    print('\n' + rule('Loss accounting'))
    identity = ('%d captured == %d persisted + %d dropped + %d parse_failed '
                '+ %d write_failed'
                % (acct['frames_captured'], acct['packets_persisted'],
                   acct['packets_dropped'], acct['packets_parse_failed'],
                   acct['packets_write_failed']))
    print('  %s' % identity)
    print('  identity holds: %s' % report['accounting_balanced'])
    print('  unaccounted:    %d' % acct['in_flight'])

    print('\n' + rule('Queues (peak depth observed during the run)'))
    for q in report['queues']:
        print('  %-16s capacity %4d chunks   peak %4d   dropped %6d   '
              'blocked %.2fs'
              % (q['name'], q['capacity'], peak_depths.get(q['name'],
                                                           q['high_water']),
                 q['dropped'], q['blocked_s']))

    failures = []
    if not report['accounting_balanced']:
        failures.append('packet accounting does not balance')
    if not args.drop_on_overflow and acct['packets_dropped']:
        failures.append('%d packets dropped under the BLOCK policy'
                        % acct['packets_dropped'])
    if acct['packets_write_failed']:
        failures.append('%d packets failed to persist'
                        % acct['packets_write_failed'])
    if resources.get('peak_rss_mb', 0) > args.max_rss_mb:
        failures.append('peak RSS %.1f MB exceeded the %.1f MB ceiling'
                        % (resources['peak_rss_mb'], args.max_rss_mb))

    print('\n' + rule('Verdict'))
    if failures:
        for failure in failures:
            print('  FAIL: %s' % failure)
    else:
        print('  PASS: %d packets in, %d out, %d dropped, %d failed'
              % (acct['frames_captured'], acct['packets_persisted'],
                 acct['packets_dropped'],
                 acct['packets_parse_failed'] + acct['packets_write_failed']))

    after_rows = repository.health()['tables']
    try:
        repository.record_pipeline_run({
            'source': 'soak', 'window_s': elapsed,
            'packets_received': acct['frames_captured'],
            'packets_parsed': acct['packets_parsed'],
            'packets_persisted': acct['packets_persisted'],
            'packets_dropped': acct['packets_dropped'],
            'packets_failed': acct['packets_parse_failed']
            + acct['packets_write_failed'],
            'alerts_generated': acct['alerts_persisted'],
            'packets_per_s': round(acct['packets_persisted'] / elapsed, 1),
            'latency_p50_ms': latency['p50_ms'],
            'latency_p95_ms': latency['p95_ms'],
            'latency_p99_ms': latency['p99_ms'],
            'peak_rss_mb': resources.get('peak_rss_mb', 0.0),
            'cpu_percent': resources.get('mean_cpu_percent', 0.0),
        })
    except Exception as exc:      # noqa: BLE001 - telemetry, not the test
        print('  (could not record the run: %s)' % exc)

    payload = {
        'benchmark': 'soak',
        'environment': env,
        'settings': vars(args),
        'elapsed_s': round(elapsed, 3),
        'throughput_pps': round(acct['packets_persisted'] / elapsed, 1),
        'accounting': acct,
        'accounting_balanced': report['accounting_balanced'],
        'zero_dropped_frames': acct['packets_dropped'] == 0,
        'latency_end_to_end_ms': latency,
        'resources': resources,
        'queues': report['queues'],
        'stages': report['stages'],
        'samples': samples,
        'rows_before': before_rows,
        'rows_after': after_rows,
        'failures': failures,
    }
    path = write_results('soak_test', payload, args.json)
    print('\n  results written to %s' % path)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
