#!/usr/bin/env python
"""
End-to-end pipeline throughput benchmark.

Measures the whole pipeline and nothing less: frames go in at the capture
stage and the clock stops when the persistence stage has committed the last
one to PostgreSQL. Parsing, rule evaluation and persistence are all inside
the measured region — there is no mode that skips a stage, because a number
produced that way would not describe the system anyone would run.

    python -m benchmarks.pipeline_benchmark
    python -m benchmarks.pipeline_benchmark --packets 100000 --repeats 3
    python -m benchmarks.pipeline_benchmark --sweep     # worker/batch matrix

What is reported, all measured rather than derived from a target:

    packets offered / processed / dropped / failed
    wall-clock duration and packets per second
    end-to-end latency p50 / p95 / p99 (capture stamp to post-commit)
    per-stage service time and queue-wait time
    queue depth high-water marks and utilisation
    peak RSS and mean CPU

The workload is seeded, so ``--seed`` reproduces byte-identical traffic, and
it contains every attack scenario the generator can build so the rules stage
is doing real work rather than short-circuiting on uniformly benign traffic.
"""

import sys
import time

from benchmarks.common import (
    base_parser,
    environment,
    rule,
    summarize,
    write_results,
)
from netwatch import config as config_module
from netwatch.analysis.rules import RulesEngine
from netwatch.capture.source import ListSource, fixed_workload
from netwatch.db import schema as schema_mod
from netwatch.db import session as session_mod
from netwatch.db.repository import Repository
from netwatch.db.writer import BatchWriter
from netwatch.pipeline import Pipeline, PipelineConfig


def run_once(engine, frames, cfg, pipeline_config, protocol_ids, threat_ids):
    """One measured pass of the full pipeline. Returns the pipeline report."""
    source = ListSource(frames, stamp_now=True)
    rules = RulesEngine(cfg=cfg)
    pipeline = Pipeline(
        source, rules,
        lambda: BatchWriter(engine, protocol_ids, threat_ids),
        config=pipeline_config)
    started = time.perf_counter()
    report = pipeline.run_to_completion(timeout=1800)
    report['wall_clock_s'] = round(time.perf_counter() - started, 4)
    acct = report['accounting']
    report['packets_per_s'] = round(
        acct['packets_persisted'] / report['wall_clock_s'], 1)
    return report


def _print_run(index, total, report):
    acct = report['accounting']
    print('  run %d/%d: %8.1f pkt/s  (%d offered, %d persisted, %d dropped, '
          '%d failed, %.2fs)'
          % (index, total, report['packets_per_s'], acct['frames_captured'],
             acct['packets_persisted'], acct['packets_dropped'],
             acct['packets_parse_failed'] + acct['packets_write_failed'],
             report['wall_clock_s']))


def _stage_table(report):
    lines = ['  %-9s %8s %8s %9s %9s %9s'
             % ('stage', 'in', 'out', 'busy_s', 'wait_s', 'p95_ms')]
    for stage in report['stages']:
        lines.append('  %-9s %8d %8d %9.2f %9.2f %9.3f'
                     % (stage['stage'], stage['items_in'], stage['items_out'],
                        stage['busy_s'], stage['queue_wait_s'],
                        stage['service_ms']['p95_ms']))
    return '\n'.join(lines)


def _queue_table(report):
    lines = ['  %-16s %9s %9s %8s %9s %9s'
             % ('queue', 'capacity', 'high', 'util%', 'dropped', 'blocked_s')]
    for q in report['queues']:
        lines.append('  %-16s %9d %9d %7.1f%% %9d %9.2f'
                     % (q['name'], q['capacity'], q['high_water'],
                        q['high_water_utilization'] * 100, q['dropped'],
                        q['blocked_s']))
    return '\n'.join(lines)


def main(argv=None):
    parser = base_parser('NetWatch end-to-end pipeline benchmark')
    parser.add_argument('--packets', type=int, default=50000,
                        help='benign background frames per run; every attack '
                             'scenario is layered on top')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--seed', type=int, default=1337)
    parser.add_argument('--batch-size', type=int, default=1000)
    parser.add_argument('--chunk-size', type=int, default=256,
                        help='packets per inter-stage queue item')
    parser.add_argument('--parse-workers', type=int, default=1)
    parser.add_argument('--rules-workers', type=int, default=1)
    parser.add_argument('--persist-workers', type=int, default=3)
    parser.add_argument('--queue-size', type=int, default=16,
                        help='queue capacity in chunks')
    parser.add_argument('--sweep', action='store_true',
                        help='sweep persist workers x batch size instead of '
                             'repeating one configuration')
    parser.add_argument('--reset', action='store_true', default=True)
    parser.add_argument('--no-reset', dest='reset', action='store_false')
    args = parser.parse_args(argv)

    engine = session_mod.get_engine(args.database_url)
    if args.reset:
        schema_mod.drop_all(engine)
    schema_mod.create_all(engine)
    schema_mod.seed_reference_data(engine)
    protocol_ids, threat_ids = schema_mod.lookup_maps(engine)
    cfg = config_module.load()

    print('NetWatch pipeline benchmark')
    env = environment(engine)
    print('  postgres  : %s (synchronous_commit=%s)'
          % (env['postgres_version'], env['pg_synchronous_commit']))
    print('  cpus      : %d' % env['cpu_count'])
    print('  workload  : %d background frames + every attack scenario, '
          'seed %d' % (args.packets, args.seed))

    frames = fixed_workload(args.packets, seed=args.seed,
                            start_ts=time.time() - 3600)
    print('  frames    : %d\n' % len(frames))

    def config_for(persist_workers, batch_size):
        return PipelineConfig(
            parse_workers=args.parse_workers,
            rules_workers=args.rules_workers,
            persist_workers=persist_workers,
            batch_size=batch_size,
            chunk_size=args.chunk_size,
            capture_queue=args.queue_size,
            rules_queue=args.queue_size,
            persist_queue=int(args.queue_size * 1.5) or 1)

    runs = []
    if args.sweep:
        combos = [(w, b) for w in (1, 2, 3, 4)
                  for b in (500, 1000, 2000, 4000)]
        print('  sweeping %d configurations\n' % len(combos))
        for workers, batch in combos:
            report = run_once(engine, frames, cfg, config_for(workers, batch),
                              protocol_ids, threat_ids)
            report['persist_workers'] = workers
            report['batch_size'] = batch
            runs.append(report)
            print('  persist=%d batch=%-5d -> %8.1f pkt/s   '
                  'e2e p95 %8.1f ms   peak RSS %6.1f MB'
                  % (workers, batch, report['packets_per_s'],
                     report['latency_end_to_end_ms']['p95_ms'],
                     report['resources'].get('peak_rss_mb', 0.0)))
    else:
        config = config_for(args.persist_workers, args.batch_size)
        for i in range(1, args.repeats + 1):
            report = run_once(engine, frames, cfg, config, protocol_ids,
                              threat_ids)
            report['persist_workers'] = args.persist_workers
            report['batch_size'] = args.batch_size
            runs.append(report)
            _print_run(i, args.repeats, report)

    rates = [r['packets_per_s'] for r in runs]
    best = max(runs, key=lambda r: r['packets_per_s'])
    total_dropped = sum(r['accounting']['packets_dropped'] for r in runs)
    total_failed = sum(r['accounting']['packets_parse_failed']
                       + r['accounting']['packets_write_failed'] for r in runs)
    balanced = all(r['accounting_balanced'] for r in runs)

    print('\n' + rule('Throughput'))
    stats = summarize(rates, unit='pps')
    print('  mean   %9.1f pkt/s   median %9.1f pkt/s'
          % (stats['mean_pps'], stats['p50_pps']))
    print('  range  %9.1f - %.1f pkt/s   stdev %.1f'
          % (stats['min_pps'], stats['max_pps'], stats['stdev_pps']))

    print('\n' + rule('Packet accounting (all runs)'))
    print('  offered %d | persisted %d | dropped %d | failed %d | '
          'identity holds: %s'
          % (sum(r['accounting']['frames_captured'] for r in runs),
             sum(r['accounting']['packets_persisted'] for r in runs),
             total_dropped, total_failed, balanced))

    print('\n' + rule('Best run: %d persist workers, batch %d'
                      % (best['persist_workers'], best['batch_size'])))
    latency = best['latency_end_to_end_ms']
    print('  end-to-end latency  p50 %8.2f ms  p95 %8.2f ms  p99 %8.2f ms  '
          'max %8.2f ms'
          % (latency['p50_ms'], latency['p95_ms'], latency['p99_ms'],
             latency['max_ms']))
    resources = best['resources']
    if resources.get('available'):
        print('  peak RSS %.1f MB   mean CPU %.1f%% of %d cores'
              % (resources['peak_rss_mb'], resources['mean_cpu_percent'],
                 resources['cpu_count']))
    print(_stage_table(best))
    print(_queue_table(best))

    payload = {
        'benchmark': 'pipeline_throughput',
        'environment': env,
        'settings': vars(args),
        'frames_per_run': len(frames),
        'throughput_pps': stats,
        'accounting_balanced': balanced,
        'total_dropped': total_dropped,
        'total_failed': total_failed,
        'best_run': best,
        'runs': runs,
    }
    path = write_results('pipeline_benchmark', payload, args.json)
    print('\n  results written to %s' % path)

    repository = Repository(engine)
    health = repository.health()
    print('  database now holds: %s' % ', '.join(
        '%s=%d' % (k, v) for k, v in sorted(health['tables'].items()) if v))
    return 0 if balanced else 1


if __name__ == '__main__':
    sys.exit(main())
