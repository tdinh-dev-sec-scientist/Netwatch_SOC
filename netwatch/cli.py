"""
Command-line entry points.

    python -m netwatch.cli engine     run the pipeline, no HTTP server
    python -m netwatch.cli api        run the REST API (development server)
    python -m netwatch.cli initdb     create the schema and seed reference data
    python -m netwatch.cli seed       seed reference data only

`seed` is separate from `initdb` because the two have different owners.
Alembic owns the *shape* of the database and is versioned with migrations.
Reference data — the protocol catalog, the detector catalog, the ATT&CK
catalog — is derived from the code that is deployed, so it is refreshed on
every deploy rather than frozen into a migration. A deployment therefore runs
`alembic upgrade head` and then `netwatch.cli seed`.

The `engine` command is the writer half of the split topology: one process
owns ingest while any number of stateless API processes serve reads from the
same PostgreSQL database. It terminates cleanly on SIGTERM/SIGINT — the
capture stage stops, every queued packet is processed, the persistence stage
commits its open batch, and only then does the process exit. `docker stop`
therefore drains rather than discards.
"""

import argparse
import json
import logging
import os
import signal
import sys
import time

from netwatch import config as config_module
from netwatch.analysis.rules import RulesEngine
from netwatch.capture.source import SyntheticSource
from netwatch.db import schema as schema_mod
from netwatch.db import session as session_mod
from netwatch.db.repository import Repository
from netwatch.db.writer import BatchWriter
from netwatch.pipeline import Pipeline, PipelineConfig
from netwatch.pipeline.queues import OverflowPolicy

log = logging.getLogger('netwatch.cli')


def _setup_logging():
    logging.basicConfig(
        level=os.environ.get('NETWATCH_LOGLEVEL', 'INFO').upper(),
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        stream=sys.stdout)


def _env_float(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise SystemExit('%s must be numeric, got %r' % (name, raw)) from None


def _env_int(name, default):
    return int(_env_float(name, default))


def cmd_initdb(args):
    engine = session_mod.wait_for_database(args.database_url,
                                           timeout_s=args.wait_s)
    if args.drop:
        schema_mod.drop_all(engine)
    schema_mod.create_all(engine)
    schema_mod.seed_reference_data(engine)
    health = Repository(engine).health()
    print('schema ready: %d tables, %d indexes on %s'
          % (health['table_count'], health['index_count'],
             health['server_version']))
    return 0


def cmd_seed(args):
    """Refresh the reference tables from the deployed code. Idempotent."""
    engine = session_mod.wait_for_database(args.database_url,
                                           timeout_s=args.wait_s)
    schema_mod.seed_reference_data(engine)
    protocol_ids, threat_ids = schema_mod.lookup_maps(engine)
    print('seeded: %d protocols, %d threat types, %d ATT&CK techniques'
          % (len(protocol_ids), len(threat_ids),
             Repository(engine).health()['tables']['mitre_techniques']))
    return 0


def cmd_engine(args):
    engine = session_mod.wait_for_database(args.database_url,
                                           timeout_s=args.wait_s)
    if args.create_schema:
        schema_mod.create_all(engine)
        schema_mod.seed_reference_data(engine)
    protocol_ids, threat_ids = schema_mod.lookup_maps(engine)

    cfg = config_module.load()
    rules = RulesEngine(cfg=cfg)
    source = SyntheticSource(seed=args.seed, rate_pps=args.rate_pps,
                             duration_s=args.duration_s)
    pipeline = Pipeline(
        source, rules, lambda: BatchWriter(engine, protocol_ids, threat_ids),
        config=PipelineConfig(
            parse_workers=args.parse_workers,
            persist_workers=args.persist_workers,
            batch_size=args.batch_size,
            capture_queue=args.queue_size,
            rules_queue=args.queue_size,
            persist_queue=args.queue_size * 2,
            overflow_policy=(OverflowPolicy.DROP if args.drop_on_overflow
                             else OverflowPolicy.BLOCK)))

    def shutdown(signum, _frame):
        log.info('signal %s received; draining pipeline',
                 signal.Signals(signum).name)
        pipeline.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log.info('engine starting: detectors=%d rate=%s batch=%d persist=%d',
             len(rules.detectors), args.rate_pps, args.batch_size,
             args.persist_workers)
    pipeline.start()

    repository = Repository(engine)
    last_report = time.time()
    while not pipeline.wait(timeout=1.0):
        if time.time() - last_report >= args.report_interval_s:
            _record_window(repository, pipeline)
            last_report = time.time()
    report = pipeline.report()
    _record_window(repository, pipeline, source='engine')
    acct = report['accounting']
    log.info('engine stopped: captured=%d persisted=%d dropped=%d '
             'parse_failed=%d write_failed=%d balanced=%s',
             acct['frames_captured'], acct['packets_persisted'],
             acct['packets_dropped'], acct['packets_parse_failed'],
             acct['packets_write_failed'], report['accounting_balanced'])
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, default=str)
    return 0 if report['accounting_balanced'] else 1


def _record_window(repository, pipeline, source='engine'):
    snap = pipeline.snapshot()
    acct, latency = snap['accounting'], snap['latency_end_to_end_ms']
    try:
        repository.record_pipeline_run({
            'source': source,
            'window_s': snap['elapsed_s'],
            'packets_received': acct['frames_captured'],
            'packets_parsed': acct['packets_parsed'],
            'packets_persisted': acct['packets_persisted'],
            'packets_dropped': acct['packets_dropped'],
            'packets_failed': acct['packets_write_failed']
            + acct['packets_parse_failed'],
            'alerts_generated': acct['alerts_persisted'],
            'packets_per_s': snap['throughput']['persisted_per_s'],
            'latency_p50_ms': latency['p50_ms'],
            'latency_p95_ms': latency['p95_ms'],
            'latency_p99_ms': latency['p99_ms'],
            'peak_rss_mb': snap['resources'].get('peak_rss_mb', 0.0),
            'cpu_percent': snap['resources'].get('mean_cpu_percent', 0.0),
            'stage_json': json.dumps({'queues': snap['queues'],
                                      'stages': snap['stages']}, default=str),
        })
    except Exception:      # noqa: BLE001 - telemetry must not kill the engine
        log.exception('failed to record pipeline window')


def cmd_api(args):
    from netwatch.api import create_app
    app = create_app(create_schema=args.create_schema,
                     run_pipeline=args.run_pipeline,
                     database_url=args.database_url)
    app.run(host=args.host, port=args.port, threaded=True,
            use_reloader=False, debug=args.debug)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog='netwatch')
    parser.add_argument('--database-url', default=None,
                        help='overrides NETWATCH_DATABASE_URL')
    parser.add_argument('--wait-s', type=float, default=60.0,
                        help='how long to wait for the database to accept '
                             'connections before giving up')
    sub = parser.add_subparsers(dest='command', required=True)

    initdb = sub.add_parser('initdb', help='create schema and seed lookups')
    initdb.add_argument('--drop', action='store_true',
                        help='drop everything first (destructive)')
    initdb.set_defaults(func=cmd_initdb)

    seed = sub.add_parser('seed', help='seed reference data only')
    seed.set_defaults(func=cmd_seed)

    eng = sub.add_parser('engine', help='run the pipeline without HTTP')
    eng.add_argument('--rate-pps', type=float,
                     default=_env_float('NETWATCH_RATE_PPS', 200.0),
                     help='offered packets/sec; 0 means as fast as possible')
    eng.add_argument('--duration-s', type=float,
                     default=_env_float('NETWATCH_DURATION', 0) or None)
    eng.add_argument('--seed', type=int, default=None)
    eng.add_argument('--batch-size', type=int,
                     default=_env_int('NETWATCH_BATCH_SIZE', 500))
    eng.add_argument('--parse-workers', type=int,
                     default=_env_int('NETWATCH_PARSE_WORKERS', 1))
    eng.add_argument('--persist-workers', type=int,
                     default=_env_int('NETWATCH_PERSIST_WORKERS', 2))
    eng.add_argument('--queue-size', type=int,
                     default=_env_int('NETWATCH_QUEUE_SIZE', 4000))
    eng.add_argument('--drop-on-overflow', action='store_true',
                     help='drop instead of applying backpressure when a '
                          'queue is full (counted, never silent)')
    eng.add_argument('--report-interval-s', type=float, default=60.0)
    eng.add_argument('--create-schema', action='store_true')
    eng.add_argument('--json', default=None, help='write the final report')
    eng.set_defaults(func=cmd_engine)

    api = sub.add_parser('api', help='run the REST API (development server)')
    api.add_argument('--host', default=os.environ.get('NETWATCH_HOST',
                                                      '127.0.0.1'))
    api.add_argument('--port', type=int,
                     default=_env_int('NETWATCH_PORT', 5001))
    api.add_argument('--debug', action='store_true')
    api.add_argument('--create-schema', action='store_true')
    api.add_argument('--run-pipeline', action='store_true')
    api.set_defaults(func=cmd_api)
    return parser


def main(argv=None):
    _setup_logging()
    args = build_parser().parse_args(argv)
    if getattr(args, 'rate_pps', None) == 0:
        args.rate_pps = None
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
