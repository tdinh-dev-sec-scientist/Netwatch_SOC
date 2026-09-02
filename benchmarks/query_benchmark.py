#!/usr/bin/env python
"""
Database scale and query-latency benchmark.

Populates PostgreSQL with a realistic dataset, then times every query the REST
API issues, twice:

    BEFORE   only the primary keys, unique constraints and the foreign-key
             indexes PostgreSQL requires — i.e. the schema with no query
             tuning at all
    AFTER    the composite indexes declared in ``netwatch.db.models``

Same data, same queries, same process, same order; the only thing that changes
between the two passes is ``CREATE INDEX``. Both passes ANALYZE first so the
planner is working from fresh statistics in each configuration, and the plan
for every query is captured with EXPLAIN so an improvement can be attributed
to an index scan replacing a sequential scan rather than to a warm cache.

    python -m benchmarks.query_benchmark
    python -m benchmarks.query_benchmark --alerts 500000 --packets 1000000
    python -m benchmarks.query_benchmark --repeats 50

Every number reported here is measured. Nothing is scaled, extrapolated or
chosen in advance.
"""

import sys
import time

from sqlalchemy import text

from benchmarks.common import (
    base_parser,
    environment,
    rule,
    summarize,
    write_results,
)
from netwatch import mitre
from netwatch.db import schema as schema_mod
from netwatch.db import seed as seed_mod
from netwatch.db import session as session_mod
from netwatch.db.repository import Repository

#: The queries the composite indexes were designed for: filtered and/or
#: sorted list endpoints, where an index turns "scan every alert and sort"
#: into "walk an index and stop at LIMIT". These are what the BEFORE/AFTER
#: headline is measured over, and they are named here rather than chosen
#: after seeing the results.
#:
#: The other queries in the suite are whole-table aggregates — coverage
#: matrices, catalog rollups, distributions. No composite index makes a
#: GROUP BY over every row cheaper, and including them in the headline would
#: measure something the indexes were never meant to change.
INDEX_TARGETED = (
    'alerts_by_severity', 'alerts_by_threat_type', 'alerts_by_source_host',
    'alerts_unacknowledged', 'alerts_severity_and_time', 'alert_detail',
    'threat_summary', 'host_detail', 'packets_by_source',
    'packets_by_protocol', 'flows_by_source',
)

#: The queries behind the REST API, in the shape the API issues them.
#: `ctx` carries ids discovered from the loaded data so every query hits rows
#: that exist — a query that matches nothing measures nothing.
QUERIES = [
    ('alerts_recent', lambda r, c: r.get_alerts(limit=50)),
    ('alerts_by_severity', lambda r, c: r.get_alerts(limit=50,
                                                     severity='CRITICAL')),
    ('alerts_by_threat_type', lambda r, c: r.get_alerts(
        limit=50, threat_type=c['threat_type'])),
    ('alerts_by_source_host', lambda r, c: r.get_alerts(limit=50,
                                                        src_ip=c['host_ip'])),
    ('alerts_unacknowledged', lambda r, c: r.get_alerts(limit=50,
                                                        acknowledged=False)),
    ('alerts_severity_and_time', lambda r, c: r.get_alerts(
        limit=50, severity='HIGH', since=time.time() - 86400)),
    ('alerts_deep_page', lambda r, c: r.get_alerts(limit=50, offset=5000)),
    ('alert_detail', lambda r, c: r.get_alert(c['alert_id'])),
    ('alert_stats_by_type', lambda r, c: r.get_alert_stats_by_type(hours=24)),
    ('threat_summary', lambda r, c: r.get_threat_summary(hours=24)),
    ('severity_breakdown', lambda r, c: r.get_severity_breakdown(hours=24)),
    ('alert_timeline', lambda r, c: r.get_alert_timeline(hours=24)),
    ('overview', lambda r, c: r.get_overview()),
    ('mitre_techniques', lambda r, c: r.get_mitre_techniques(hours=24)),
    ('mitre_technique_detail', lambda r, c: r.get_mitre_technique('T1046')),
    ('mitre_coverage', lambda r, c: r.get_mitre_coverage()),
    ('top_hosts', lambda r, c: r.get_hosts(limit=25, order='threat_score')),
    ('host_detail', lambda r, c: r.get_host(c['host_ip'])),
    ('geo_distribution', lambda r, c: r.get_geo_distribution()),
    ('flows_recent', lambda r, c: r.get_flows(limit=50)),
    ('flows_by_source', lambda r, c: r.get_flows(limit=50,
                                                 src_ip=c['host_ip'])),
    ('packets_recent', lambda r, c: r.get_packets(limit=100)),
    ('packets_by_protocol', lambda r, c: r.get_packets(limit=100,
                                                       protocol='DNS')),
    ('packets_by_source', lambda r, c: r.get_packets(limit=100,
                                                     src_ip=c['host_ip'])),
    ('protocol_distribution', lambda r, c: r.get_protocol_distribution()),
    ('throughput_60m', lambda r, c: r.get_throughput(60)),
    ('protocol_catalog', lambda r, c: r.get_protocol_catalog()),
    ('threat_type_catalog', lambda r, c: r.get_threat_types()),
]

#: Raw SQL mirrors of the queries whose plan is worth showing. Keyed by the
#: benchmark name above so the report can pair a latency with a plan.
EXPLAIN_SQL = {
    'alerts_by_severity': """
        SELECT a.id FROM alerts a WHERE a.severity = 'CRITICAL'
        ORDER BY a.ts DESC LIMIT 50""",
    'alerts_by_source_host': """
        SELECT a.id FROM alerts a
        WHERE a.src_host_id = (SELECT id FROM hosts ORDER BY id LIMIT 1)
        ORDER BY a.ts DESC LIMIT 50""",
    'alerts_unacknowledged': """
        SELECT a.id FROM alerts a WHERE NOT a.acknowledged
        ORDER BY a.ts DESC LIMIT 50""",
    'threat_summary': """
        SELECT a.src_host_id, a.threat_type_id, COUNT(*)
        FROM alerts a WHERE a.ts > now() - interval '24 hours'
        GROUP BY a.src_host_id, a.threat_type_id LIMIT 50""",
    'packets_by_source': """
        SELECT p.id FROM packets p
        WHERE p.src_host_id = (SELECT id FROM hosts ORDER BY id LIMIT 1)
        ORDER BY p.ts DESC LIMIT 100""",
}


def measure(repository, ctx, repeats, warmup=3):
    """Time every query `repeats` times. Returns per-query and pooled stats."""
    for _name, fn in QUERIES:            # warm the shared buffer cache
        for _ in range(warmup):
            fn(repository, ctx)

    per_query, pooled, targeted = {}, [], []
    for name, fn in QUERIES:
        samples = []
        for _ in range(repeats):
            started = time.perf_counter()
            fn(repository, ctx)
            samples.append((time.perf_counter() - started) * 1000.0)
        per_query[name] = summarize(samples)
        pooled.extend(samples)
        if name in INDEX_TARGETED:
            targeted.extend(samples)
    return per_query, summarize(pooled), summarize(targeted)


def capture_plans(engine):
    plans = {}
    with engine.connect() as conn:
        for name, sql in EXPLAIN_SQL.items():
            rows = conn.execute(text('EXPLAIN (ANALYZE, BUFFERS) ' + sql)).all()
            plans[name] = [r[0] for r in rows]
    return plans


def _plan_kind(plan_lines):
    """One-word summary of what the planner chose, for the report table."""
    joined = ' '.join(plan_lines)
    if 'Index Only Scan' in joined:
        return 'index-only scan'
    if 'Index Scan' in joined:
        return 'index scan'
    if 'Bitmap Heap Scan' in joined:
        return 'bitmap scan'
    if 'Parallel Seq Scan' in joined:
        return 'parallel seq scan'
    if 'Seq Scan' in joined:
        return 'seq scan'
    return 'other'


def main(argv=None):
    parser = base_parser('NetWatch database query benchmark')
    parser.add_argument('--alerts', type=int, default=400_000,
                        help='alert rows to load (the event table)')
    parser.add_argument('--packets', type=int, default=600_000)
    parser.add_argument('--hosts', type=int, default=2000)
    parser.add_argument('--repeats', type=int, default=25)
    parser.add_argument('--seed', type=int, default=4242)
    parser.add_argument('--skip-load', action='store_true',
                        help='benchmark whatever is already in the database')
    args = parser.parse_args(argv)

    engine = session_mod.get_engine(args.database_url)
    schema_mod.create_all(engine)
    schema_mod.seed_reference_data(engine)
    repository = Repository(engine)

    print('NetWatch database query benchmark')
    env = environment(engine)
    print('  postgres : %s   shared_buffers=%s work_mem=%s'
          % (env['postgres_version'], env['pg_shared_buffers'],
             env['pg_work_mem']))

    protocol_ids, threat_ids = schema_mod.lookup_maps(engine)
    if not args.skip_load:
        print('\n  loading dataset ...')
        started = time.perf_counter()
        host_ids = seed_mod.ensure_hosts(engine, args.hosts, seed=args.seed)
        loaded = seed_mod.load_alerts(
            engine, args.alerts, host_ids, threat_ids, protocol_ids,
            seed=args.seed,
            techniques=[t.id for t in mitre.all_techniques()])
        loaded.update(seed_mod.load_packets(engine, args.packets, host_ids,
                                            protocol_ids, seed=args.seed))
        print('  loaded %s in %.1fs'
              % (', '.join('%s=%d' % kv for kv in sorted(loaded.items())),
                 time.perf_counter() - started))

    health = repository.health()
    rows = health['tables']
    print('\n  dataset: %s' % ', '.join(
        '%s=%d' % (k, v) for k, v in sorted(rows.items()) if v))
    print('  database size: %.1f MB' % (health['db_size_bytes'] / 1e6))

    with engine.connect() as conn:
        ctx = {
            'alert_id': conn.execute(text(
                'SELECT id FROM alerts ORDER BY ts DESC LIMIT 1')).scalar(),
            'host_ip': conn.execute(text(
                'SELECT host(ip) FROM hosts h JOIN alerts a '
                'ON a.src_host_id = h.id GROUP BY h.ip '
                'ORDER BY COUNT(*) DESC LIMIT 1')).scalar(),
            'threat_type': conn.execute(text(
                'SELECT tt.name FROM threat_types tt JOIN alerts a '
                'ON a.threat_type_id = tt.id GROUP BY tt.name '
                'ORDER BY COUNT(*) DESC LIMIT 1')).scalar(),
        }
    print('  probe row: alert %s, busiest host %s, commonest threat %s'
          % (ctx['alert_id'], ctx['host_ip'], ctx['threat_type']))

    # ── BEFORE ───────────────────────────────────────────────────────────────
    dropped = schema_mod.drop_composite_indexes(engine)
    schema_mod.analyze(engine)
    print('\n' + rule('BEFORE: %d composite indexes dropped' % len(dropped)))
    before_plans = capture_plans(engine)
    before_per_query, before_pooled, before_targeted = measure(
        repository, ctx, args.repeats)
    print('  all %d queries   p50 %8.2f ms   p95 %8.2f ms   p99 %8.2f ms'
          % (len(QUERIES), before_pooled['p50_ms'], before_pooled['p95_ms'],
             before_pooled['p99_ms']))
    print('  %d targeted      p50 %8.2f ms   p95 %8.2f ms   p99 %8.2f ms'
          % (len(INDEX_TARGETED), before_targeted['p50_ms'],
             before_targeted['p95_ms'], before_targeted['p99_ms']))

    # ── AFTER ────────────────────────────────────────────────────────────────
    created = schema_mod.create_composite_indexes(engine)
    print('\n' + rule('AFTER: %d composite indexes created' % len(created)))
    after_plans = capture_plans(engine)
    after_per_query, after_pooled, after_targeted = measure(
        repository, ctx, args.repeats)
    print('  all %d queries   p50 %8.2f ms   p95 %8.2f ms   p99 %8.2f ms'
          % (len(QUERIES), after_pooled['p50_ms'], after_pooled['p95_ms'],
             after_pooled['p99_ms']))
    print('  %d targeted      p50 %8.2f ms   p95 %8.2f ms   p99 %8.2f ms'
          % (len(INDEX_TARGETED), after_targeted['p50_ms'],
             after_targeted['p95_ms'], after_targeted['p99_ms']))

    # ── comparison ───────────────────────────────────────────────────────────
    print('\n' + rule('Per query (p95 ms), biggest wins first'))
    print('  %-26s %10s %10s %8s   %s' % ('query', 'before', 'after', 'factor',
                                          'plan before -> after'))
    deltas = []
    for name in before_per_query:
        before = before_per_query[name]['p95_ms']
        after = after_per_query[name]['p95_ms']
        factor = (before / after) if after else 0.0
        deltas.append((before - after, name, before, after, factor))
    for _delta, name, before, after, factor in sorted(deltas, reverse=True):
        plan = ''
        if name in before_plans:
            plan = '%s -> %s' % (_plan_kind(before_plans[name]),
                                 _plan_kind(after_plans[name]))
        print('  %-26s%s %9.2f %10.2f %7.1fx   %s'
              % (name, '*' if name in INDEX_TARGETED else ' ', before, after,
                 factor, plan))
    print('  (* = a query the composite indexes target)')

    targeted_speedup = (before_targeted['p95_ms'] / after_targeted['p95_ms']
                        if after_targeted['p95_ms'] else 0.0)
    pooled_speedup = (before_pooled['p95_ms'] / after_pooled['p95_ms']
                      if after_pooled['p95_ms'] else 0.0)
    print('\n' + rule('Headline'))
    print('  dataset: %s alert rows, %s packet rows, %s technique links'
          % (format(rows['alerts'], ','), format(rows['packets'], ','),
             format(rows['alert_techniques'], ',')))
    print('  p95 over the %d queries the composite indexes target'
          % len(INDEX_TARGETED))
    print('    %.1f ms  ->  %.1f ms   (%.1fx)'
          % (before_targeted['p95_ms'], after_targeted['p95_ms'],
             targeted_speedup))
    print('  p95 over all %d queries, aggregates included' % len(QUERIES))
    print('    %.1f ms  ->  %.1f ms   (%.1fx)'
          % (before_pooled['p95_ms'], after_pooled['p95_ms'], pooled_speedup))
    print('    (whole-table GROUP BY queries dominate this tail and no index'
          ' changes them)')

    payload = {
        'benchmark': 'query_latency',
        'environment': env,
        'settings': vars(args),
        'dataset': rows,
        'db_size_bytes': health['db_size_bytes'],
        'probe_context': ctx,
        'composite_indexes': sorted(schema_mod.composite_index_names()),
        'index_targeted_queries': list(INDEX_TARGETED),
        'before': {'pooled': before_pooled, 'targeted': before_targeted,
                   'per_query': before_per_query, 'plans': before_plans},
        'after': {'pooled': after_pooled, 'targeted': after_targeted,
                  'per_query': after_per_query, 'plans': after_plans},
        'targeted_p95_before_ms': before_targeted['p95_ms'],
        'targeted_p95_after_ms': after_targeted['p95_ms'],
        'targeted_p95_speedup': round(targeted_speedup, 2),
        'pooled_p95_speedup': round(pooled_speedup, 2),
    }
    path = write_results('query_benchmark', payload, args.json)
    print('\n  results written to %s' % path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
