"""
Reproducible performance benchmark for NetWatch SOC.

Measures two things, both end-to-end and both actually observed:

  Throughput     frames -> ProtocolAnalyzer -> ThreatDetector -> SQLite,
                 including parsing, detection and batched persistence.
                 Reported as packets/minute.

  Query latency  the same queries the REST API issues, run against whatever
                 the throughput phase actually wrote. Reported as p50/p95/p99.

Usage:
    python benchmark.py                          # 5 iterations x 20k packets
    python benchmark.py --iterations 3 --packets 50000
    python benchmark.py --json results.json --keep-db

The workload is seeded, so a given --seed reproduces byte-identical traffic.
Iterations accumulate into one database so the query phase runs against a
realistically populated dataset; row counts are reported alongside the
latencies so the numbers can be judged in context.
"""

import argparse
import json
import os
import statistics
import sys
import tempfile
import time

import config as config_module
from DB_Manager import DatabaseManager
from PacketSimulator import PacketSimulator, TrafficGenerator
from ProtocolAnalyzer import ProtocolAnalyzer
from ThreatDetector import ThreatDetector

# Attack scenarios mixed into each workload so detectors do real work rather
# than short-circuiting on uniformly benign traffic.
WORKLOAD_SCENARIOS = [
    'port_scan', 'network_recon', 'brute_force', 'credential_stuffing',
    'c2_beacon', 'dns_tunnel', 'dga_lookups', 'icmp_tunnel',
    'protocol_tunnel', 'lateral_movement', 'syn_flood', 'udp_flood',
    'ntp_amplification', 'http_attack', 'arp_spoof', 'tls_anomaly',
    'icmp_sweep',
]


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    k = (len(ordered) - 1) * pct / 100.0
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def summarize(values):
    return {
        'samples': len(values),
        'mean_ms': round(statistics.fmean(values), 3) if values else 0.0,
        'p50_ms': round(percentile(values, 50), 3),
        'p95_ms': round(percentile(values, 95), 3),
        'p99_ms': round(percentile(values, 99), 3),
        'max_ms': round(max(values), 3) if values else 0.0,
    }


def build_workload(packet_count, seed, start_ts):
    """Benign background plus every attack scenario, interleaved by timestamp."""
    gen = TrafficGenerator(seed)
    frames = gen.background(packet_count, start_ts=start_ts)
    span = (frames[-1][0] - frames[0][0]) if len(frames) > 1 else 60.0
    step = span / (len(WORKLOAD_SCENARIOS) + 1)
    for i, name in enumerate(WORKLOAD_SCENARIOS):
        frames.extend(gen.scenario(name, start_ts=start_ts + step * (i + 1)))
    frames.sort(key=lambda pair: pair[0])
    return frames


def run_throughput(db, frames, iteration):
    """One measured pass of the full pipeline. Returns a metrics dict."""
    engine = ThreatDetector(db, cfg=config_module.load())
    analyzer = ProtocolAnalyzer()
    sim = PacketSimulator(db, engine, analyzer)

    t0 = time.perf_counter()
    for ts, frame in frames:
        sim.process(frame, ts)
        sim.maybe_flush()
    sim.flush()
    elapsed = time.perf_counter() - t0

    processed = sim.packets_processed
    return {
        'iteration': iteration,
        'frames_offered': len(frames),
        'packets_processed': processed,
        'parse_errors': analyzer.parse_errors,
        'alerts_generated': sim.alerts_generated,
        'elapsed_s': round(elapsed, 4),
        'packets_per_s': round(processed / elapsed, 1),
        'packets_per_min': round(processed / elapsed * 60, 1),
        'parse_us_avg': round(sim.parse_ns / max(processed, 1) / 1000.0, 3),
        'detect_us_avg': round(sim.detect_ns / max(processed, 1) / 1000.0, 3),
        'db_write_ms_total': round(sim.db_write_ms, 2),
        'protocols_seen': len(analyzer.stats),
        'distinct_threat_types': sum(
            1 for d in engine.stats()['detectors'] if d['findings_emitted']),
    }


QUERIES = [
    ('health', lambda db, ctx: db.health()),
    ('overview', lambda db, ctx: db.get_overview()),
    ('throughput_60m', lambda db, ctx: db.get_throughput(60)),
    ('protocol_distribution', lambda db, ctx: db.get_protocol_distribution()),
    ('severity_breakdown', lambda db, ctx: db.get_severity_breakdown()),
    ('alert_timeline', lambda db, ctx: db.get_alert_timeline()),
    ('alerts_recent_50', lambda db, ctx: db.get_alerts(limit=50)),
    ('alerts_by_severity', lambda db, ctx: db.get_alerts(
        limit=50, severity='HIGH')),
    ('alerts_paged_offset500', lambda db, ctx: db.get_alerts(
        limit=50, offset=500)),
    ('alert_detail', lambda db, ctx: db.get_alert(ctx['alert_id'])),
    ('alert_stats_by_type', lambda db, ctx: db.get_alert_stats_by_type()),
    ('threat_summary', lambda db, ctx: db.get_threat_summary()),
    ('mitre_techniques', lambda db, ctx: db.get_mitre_techniques()),
    ('mitre_technique_detail', lambda db, ctx: db.get_mitre_technique(
        ctx['technique_id'])),
    ('mitre_coverage', lambda db, ctx: db.get_mitre_coverage()),
    ('top_hosts', lambda db, ctx: db.get_top_hosts(15)),
    ('host_detail', lambda db, ctx: db.get_host(ctx['host_ip'])),
    ('geo_distribution', lambda db, ctx: db.get_geo_distribution()),
    ('connections_recent', lambda db, ctx: db.get_connections(50)),
    ('packets_recent', lambda db, ctx: db.get_packets(100)),
    ('packets_by_protocol', lambda db, ctx: db.get_packets(
        100, protocol='DNS')),
    ('performance_history', lambda db, ctx: db.get_performance(120)),
]


def run_query_latency(db, repeats):
    """Time every API-backing query. Returns (per-query, all-samples)."""
    alert = db.get_alerts(limit=1)['alerts']
    hosts = db.get_top_hosts(1)
    ctx = {
        'alert_id': alert[0]['id'] if alert else 1,
        'technique_id': 'T1046',
        'host_ip': hosts[0]['ip'] if hosts else '10.0.1.10',
    }

    # Warm the page cache so the first query does not skew the distribution.
    for _name, fn in QUERIES:
        fn(db, ctx)

    per_query, everything = {}, []
    for name, fn in QUERIES:
        samples = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            fn(db, ctx)
            samples.append((time.perf_counter() - t0) * 1000.0)
        per_query[name] = summarize(samples)
        everything.extend(samples)
    return per_query, everything


def main(argv=None):
    ap = argparse.ArgumentParser(description='NetWatch SOC benchmark')
    ap.add_argument('--iterations', type=int, default=5)
    ap.add_argument('--packets', type=int, default=20000,
                    help='benign background packets per iteration')
    ap.add_argument('--query-repeats', type=int, default=30)
    ap.add_argument('--seed', type=int, default=1337)
    ap.add_argument('--db', default=None,
                    help='database path (default: a temporary file)')
    ap.add_argument('--json', default=None, help='write results as JSON')
    ap.add_argument('--keep-db', action='store_true')
    args = ap.parse_args(argv)

    db_path = args.db or os.path.join(tempfile.gettempdir(),
                                      'netwatch_bench_%d.db' % os.getpid())
    for suffix in ('', '-wal', '-shm'):
        if os.path.exists(db_path + suffix):
            os.remove(db_path + suffix)

    print('NetWatch SOC benchmark')
    print('  database   : %s' % db_path)
    print('  iterations : %d' % args.iterations)
    print('  packets    : %d background + %d attack scenarios per iteration'
          % (args.packets, len(WORKLOAD_SCENARIOS)))
    print('  seed       : %d\n' % args.seed)

    db = DatabaseManager(db_path)
    runs = []
    base_ts = time.time() - args.iterations * 3600

    for i in range(1, args.iterations + 1):
        # A distinct seed and time offset per iteration keeps the workload
        # varied while remaining fully reproducible from --seed.
        frames = build_workload(args.packets, args.seed + i,
                                base_ts + (i - 1) * 3600)
        result = run_throughput(db, frames, i)
        runs.append(result)
        print('  iteration %d/%d: %8.1f pkt/min  (%d packets in %.2fs, '
              '%d alerts, %d parse errors)'
              % (i, args.iterations, result['packets_per_min'],
                 result['packets_processed'], result['elapsed_s'],
                 result['alerts_generated'], result['parse_errors']))

    throughputs = [r['packets_per_min'] for r in runs]
    health = db.health()

    print('\n  populating query benchmark dataset: '
          '%d packets, %d alerts, %d technique links'
          % (health['tables']['packets'], health['tables']['alerts'],
             health['tables']['alert_techniques']))

    per_query, all_samples = run_query_latency(db, args.query_repeats)

    throughput_summary = {
        'iterations': len(runs),
        'mean_packets_per_min': round(statistics.fmean(throughputs), 1),
        'median_packets_per_min': round(statistics.median(throughputs), 1),
        'min_packets_per_min': round(min(throughputs), 1),
        'max_packets_per_min': round(max(throughputs), 1),
        'stdev_packets_per_min': round(
            statistics.stdev(throughputs), 1) if len(throughputs) > 1 else 0.0,
        'total_packets': sum(r['packets_processed'] for r in runs),
        'total_alerts': sum(r['alerts_generated'] for r in runs),
        'total_parse_errors': sum(r['parse_errors'] for r in runs),
        'mean_parse_us': round(
            statistics.fmean([r['parse_us_avg'] for r in runs]), 3),
        'mean_detect_us': round(
            statistics.fmean([r['detect_us_avg'] for r in runs]), 3),
    }
    query_summary = summarize(all_samples)
    slowest = sorted(per_query.items(), key=lambda kv: -kv[1]['p95_ms'])[:5]

    print('\n── Throughput ' + '─' * 52)
    print('  mean      : %9.1f packets/min' %
          throughput_summary['mean_packets_per_min'])
    print('  median    : %9.1f packets/min' %
          throughput_summary['median_packets_per_min'])
    print('  range     : %9.1f - %.1f packets/min'
          % (throughput_summary['min_packets_per_min'],
             throughput_summary['max_packets_per_min']))
    print('  per packet: %.1f us parse + %.1f us detect'
          % (throughput_summary['mean_parse_us'],
             throughput_summary['mean_detect_us']))
    print('  target 5,000 pkt/min: %s'
          % ('MET' if throughput_summary['mean_packets_per_min'] >= 5000
             else 'NOT MET'))

    print('\n── Query latency (%d queries x %d repeats) '
          % (len(QUERIES), args.query_repeats) + '─' * 20)
    print('  p50 %.3f ms | p95 %.3f ms | p99 %.3f ms | max %.3f ms'
          % (query_summary['p50_ms'], query_summary['p95_ms'],
             query_summary['p99_ms'], query_summary['max_ms']))
    print('  target <50 ms (p95): %s'
          % ('MET' if query_summary['p95_ms'] < 50 else 'NOT MET'))
    print('  slowest queries by p95:')
    for name, stats in slowest:
        print('    %-26s p50 %7.3f ms   p95 %7.3f ms'
              % (name, stats['p50_ms'], stats['p95_ms']))

    db.record_performance({
        'source': 'benchmark',
        'window_s': sum(r['elapsed_s'] for r in runs),
        'packets_processed': throughput_summary['total_packets'],
        'packets_per_min': throughput_summary['mean_packets_per_min'],
        'alerts_generated': throughput_summary['total_alerts'],
        'parse_errors': throughput_summary['total_parse_errors'],
        'parse_us_avg': throughput_summary['mean_parse_us'],
        'detect_us_avg': throughput_summary['mean_detect_us'],
        'db_write_ms': round(sum(r['db_write_ms_total'] for r in runs), 2),
        'query_p50_ms': query_summary['p50_ms'],
        'query_p95_ms': query_summary['p95_ms'],
    })

    results = {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'python': sys.version.split()[0],
        'platform': sys.platform,
        'seed': args.seed,
        'throughput': throughput_summary,
        'throughput_runs': runs,
        'query_latency_overall': query_summary,
        'query_latency_by_query': per_query,
        'dataset': health['tables'],
        'index_count': health['index_count'],
        'targets': {
            'throughput_packets_per_min': 5000,
            'throughput_met':
                throughput_summary['mean_packets_per_min'] >= 5000,
            'query_latency_ms': 50,
            'query_latency_met': query_summary['p95_ms'] < 50,
        },
    }

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump(results, fh, indent=2)
        print('\n  results written to %s' % args.json)

    db.close()
    if not args.keep_db and not args.db:
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(db_path + suffix):
                os.remove(db_path + suffix)

    both_met = results['targets']['throughput_met'] and \
        results['targets']['query_latency_met']
    return 0 if both_met else 1


if __name__ == '__main__':
    sys.exit(main())
