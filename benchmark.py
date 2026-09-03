"""
Reproducible performance benchmark for NetWatch SOC.

Everything here is measured, not modelled. One capture is replayed repeatedly
through the real pipeline under one configuration, and the median across runs
is reported — the median rather than the mean because a single scheduling
hiccup should not move the headline figure.

  Throughput     Two numbers, because they answer different questions:

                   pipeline   parse -> detect -> batched persistence, over
                              frames already in memory. This is the DPI
                              pipeline's own rate.
                   replay     the same work with Scapy reading each frame off
                              disk. This is what an end-to-end PCAP replay
                              actually sustains.

                 Reported as packets/second, with packets/minute alongside.

  Query latency  the same queries the REST API issues, run against whatever
                 the throughput phase actually wrote. Reported as p50/p95/p99.

Usage:
    python benchmark.py                        # 6 runs, first discarded
    python benchmark.py --runs 10 --packets 40000
    python benchmark.py --json results.json --keep-db

The capture is built once from a seeded generator and replayed byte-identically
by every run, so the only thing varying between runs is the machine. The first
run is discarded as warm-up (cold page cache, cold allocator) and the report
says so; --warmup 0 keeps it.
"""

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time

import config as config_module
import db_dialects
import pcap_io
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


def build_capture(path, packet_count, seed, start_ts):
    """Write the benchmark capture once. Every run then replays these bytes."""
    written = pcap_io.write_pcap(
        path, build_workload(packet_count, seed, start_ts))
    return written, pcap_io.pcap_summary(path)


def run_throughput(db, capture_path, run_index, cfg, base_ts,
                   preloaded=None):
    """One measured pass of the full pipeline over the capture.

    Two timings are taken from the same pass structure:

      replay_s    Scapy reads each frame off disk and the pipeline consumes it
      pipeline_s  the same pipeline work over frames already in memory

    Both run the identical parse/detect/persist path; the difference is
    whether the capture is being read during the measurement. Reporting only
    one would either understate what a replay costs or overstate what the DPI
    pipeline costs.
    """
    frames = preloaded if preloaded is not None else None

    # Pass 1 — end-to-end replay, straight off disk.
    engine = ThreatDetector(db, cfg=cfg)
    analyzer = ProtocolAnalyzer()
    sim = PacketSimulator(db, engine, analyzer)
    offset = base_ts
    first_ts = None
    t0 = time.perf_counter()
    for ts, frame in pcap_io.iter_pcap(capture_path):
        if first_ts is None:
            first_ts = ts
        sim.process(frame, ts - first_ts + offset)
        sim.maybe_flush()
    sim.flush()
    replay_s = time.perf_counter() - t0
    replayed = sim.packets_processed

    # Pass 2 — the pipeline alone, over frames already resident.
    if frames is None:
        frames = pcap_io.read_pcap(capture_path)
    base = frames[0][0] if frames else 0.0
    engine2 = ThreatDetector(db, cfg=cfg)
    analyzer2 = ProtocolAnalyzer()
    sim2 = PacketSimulator(db, engine2, analyzer2)
    t1 = time.perf_counter()
    for ts, frame in frames:
        sim2.process(frame, ts - base + offset)
        sim2.maybe_flush()
    sim2.flush()
    pipeline_s = time.perf_counter() - t1
    processed = sim2.packets_processed

    return {
        'run': run_index,
        'frames_in_capture': len(frames),
        'packets_processed': processed,
        'parse_errors': analyzer2.parse_errors,
        'alerts_generated': sim2.alerts_generated,
        'pipeline_elapsed_s': round(pipeline_s, 4),
        'pipeline_packets_per_s': round(processed / pipeline_s, 1),
        'pipeline_packets_per_min': round(processed / pipeline_s * 60, 1),
        'replay_elapsed_s': round(replay_s, 4),
        'replay_packets_per_s': round(replayed / replay_s, 1),
        'replay_packets_per_min': round(replayed / replay_s * 60, 1),
        'parse_us_avg': round(sim2.parse_ns / max(processed, 1) / 1000.0, 3),
        'detect_us_avg': round(sim2.detect_ns / max(processed, 1) / 1000.0, 3),
        'db_write_ms_total': round(sim2.db_write_ms + sim.db_write_ms, 2),
        'protocols_seen': len(analyzer2.stats),
        'distinct_threat_types': sum(
            1 for d in engine2.stats()['detectors'] if d['findings_emitted']),
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


def series(runs, key):
    return [r[key] for r in runs]


def describe(values):
    """Median-first summary. The median is the reported figure."""
    return {
        'runs': len(values),
        'median': round(statistics.median(values), 1) if values else 0.0,
        'mean': round(statistics.fmean(values), 1) if values else 0.0,
        'min': round(min(values), 1) if values else 0.0,
        'max': round(max(values), 1) if values else 0.0,
        'stdev': round(statistics.stdev(values), 1) if len(values) > 1
        else 0.0,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description='NetWatch SOC benchmark')
    ap.add_argument('--runs', type=int, default=6,
                    help='measured runs over the capture (default: 6)')
    ap.add_argument('--warmup', type=int, default=1,
                    help='leading runs to discard as warm-up (default: 1)')
    ap.add_argument('--packets', type=int, default=20000,
                    help='benign background packets in the capture')
    ap.add_argument('--query-repeats', type=int, default=30)
    ap.add_argument('--seed', type=int, default=1337)
    ap.add_argument('--pcap', default=None,
                    help='replay this capture instead of building one')
    ap.add_argument('--db', default=None,
                    help='database path or postgresql:// URL '
                         '(default: a temporary SQLite file)')
    ap.add_argument('--json', default=None, help='write results as JSON')
    ap.add_argument('--keep-db', action='store_true')
    ap.add_argument('--min-packets-per-s', type=float, default=1000.0,
                    help='fail if the median pipeline rate falls below this')
    args = ap.parse_args(argv)

    if args.runs <= args.warmup:
        ap.error('--runs must exceed --warmup, or nothing is measured')

    tmp_dir = tempfile.gettempdir()
    db_path = args.db or os.path.join(tmp_dir,
                                      'netwatch_bench_%d.db' % os.getpid())
    if not db_dialects._is_url(db_path):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(db_path + suffix):
                os.remove(db_path + suffix)

    base_ts = time.time() - 3600
    owns_capture = args.pcap is None
    capture_path = args.pcap or os.path.join(
        tmp_dir, 'netwatch_bench_%d.pcap' % os.getpid())
    if owns_capture:
        build_capture(capture_path, args.packets, args.seed, base_ts)
    capture = pcap_io.pcap_summary(capture_path)

    db = DatabaseManager(db_path)
    cfg = config_module.load()

    print('NetWatch SOC benchmark')
    print('  backend    : %s (%s)' % (db.backend, db.db_path))
    print('  capture    : %s' % capture_path)
    print('               %d packets, %.1fs span, sha256 %s'
          % (capture['packets'], capture['duration_s'],
             capture['sha256'][:16]))
    print('  runs       : %d measured, %d discarded as warm-up'
          % (args.runs - args.warmup, args.warmup))
    print('  profile    : tuned (config defaults, identical for every run)')
    print('  scapy      : %s\n' % pcap_io.scapy_version())

    # Read once so every run consumes identical in-memory frames; the replay
    # pass still reads from disk on each run.
    preloaded = pcap_io.read_pcap(capture_path)

    runs = []
    for i in range(1, args.runs + 1):
        result = run_throughput(db, capture_path, i, cfg, base_ts,
                                preloaded=preloaded)
        result['warmup'] = i <= args.warmup
        runs.append(result)
        print('  run %2d/%d %s: pipeline %9.1f pkt/s   replay %9.1f pkt/s   '
              '(%d packets, %d alerts, %d parse errors)'
              % (i, args.runs, 'W' if result['warmup'] else ' ',
                 result['pipeline_packets_per_s'],
                 result['replay_packets_per_s'],
                 result['packets_processed'], result['alerts_generated'],
                 result['parse_errors']))

    measured = [r for r in runs if not r['warmup']]
    pipeline = describe(series(measured, 'pipeline_packets_per_s'))
    replay_rate = describe(series(measured, 'replay_packets_per_s'))
    health = db.health()

    print('\n  query benchmark dataset: %d packets, %d alerts, %d links'
          % (health['tables']['packets'], health['tables']['alerts'],
             health['tables']['alert_techniques']))

    per_query, all_samples = run_query_latency(db, args.query_repeats)
    query_summary = summarize(all_samples)
    slowest = sorted(per_query.items(), key=lambda kv: -kv[1]['p95_ms'])[:5]

    throughput_summary = {
        'measured_runs': len(measured),
        'warmup_runs': args.warmup,
        'capture_packets': capture['packets'],
        'capture_sha256': capture['sha256'],
        'pipeline_packets_per_s': pipeline,
        'replay_packets_per_s': replay_rate,
        'median_pipeline_packets_per_min': round(pipeline['median'] * 60, 1),
        'median_replay_packets_per_min': round(replay_rate['median'] * 60, 1),
        'per_run_pipeline_packets_per_s': series(measured,
                                                 'pipeline_packets_per_s'),
        'per_run_replay_packets_per_s': series(measured,
                                               'replay_packets_per_s'),
        'total_packets': sum(r['packets_processed'] for r in measured),
        'total_alerts': sum(r['alerts_generated'] for r in measured),
        'total_parse_errors': sum(r['parse_errors'] for r in measured),
        'mean_parse_us': round(
            statistics.fmean(series(measured, 'parse_us_avg')), 3),
        'mean_detect_us': round(
            statistics.fmean(series(measured, 'detect_us_avg')), 3),
        'protocols_seen': max(series(measured, 'protocols_seen')),
    }

    print('\n-- Throughput ' + '-' * 52)
    print('  measured over %d runs (%d warm-up run(s) discarded)'
          % (len(measured), args.warmup))
    print('  pipeline (parse + detect + persist, frames in memory)')
    print('    per run : %s pkt/s'
          % ', '.join('%.0f' % v
                      for v in throughput_summary[
                          'per_run_pipeline_packets_per_s']))
    print('    MEDIAN  : %9.1f packets/sec   (%.0f packets/min)'
          % (pipeline['median'],
             throughput_summary['median_pipeline_packets_per_min']))
    print('    range   : %9.1f - %.1f pkt/s   stdev %.1f'
          % (pipeline['min'], pipeline['max'], pipeline['stdev']))
    print('  replay (as above, reading each frame from the PCAP)')
    print('    per run : %s pkt/s'
          % ', '.join('%.0f' % v
                      for v in throughput_summary[
                          'per_run_replay_packets_per_s']))
    print('    MEDIAN  : %9.1f packets/sec   (%.0f packets/min)'
          % (replay_rate['median'],
             throughput_summary['median_replay_packets_per_min']))
    print('  per packet: %.1f us parse + %.1f us detect'
          % (throughput_summary['mean_parse_us'],
             throughput_summary['mean_detect_us']))
    print('  protocols identified in the capture: %d'
          % throughput_summary['protocols_seen'])
    print('  floor %.0f pkt/s: %s'
          % (args.min_packets_per_s,
             'MET' if pipeline['median'] >= args.min_packets_per_s
             else 'NOT MET'))

    print('\n-- Query latency (%d queries x %d repeats) '
          % (len(QUERIES), args.query_repeats) + '-' * 20)
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
        'window_s': sum(r['pipeline_elapsed_s'] for r in measured),
        'packets_processed': throughput_summary['total_packets'],
        'packets_per_min':
            throughput_summary['median_pipeline_packets_per_min'],
        'alerts_generated': throughput_summary['total_alerts'],
        'parse_errors': throughput_summary['total_parse_errors'],
        'parse_us_avg': throughput_summary['mean_parse_us'],
        'detect_us_avg': throughput_summary['mean_detect_us'],
        'db_write_ms': round(
            sum(r['db_write_ms_total'] for r in measured), 2),
        'query_p50_ms': query_summary['p50_ms'],
        'query_p95_ms': query_summary['p95_ms'],
    })

    results = {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'python': sys.version.split()[0],
        'platform': '%s %s' % (platform.system(), platform.machine()),
        'processor': platform.processor() or 'unknown',
        'cpu_count': os.cpu_count(),
        'scapy': pcap_io.scapy_version(),
        'backend': db.backend,
        'seed': args.seed,
        'capture': capture,
        'methodology': {
            'runs': args.runs,
            'warmup_runs_discarded': args.warmup,
            'reported_statistic': 'median across measured runs',
            'configuration': 'config.DEFAULTS, identical for every run',
            'pipeline_scope': 'parse + detect + batched persistence',
            'replay_scope': 'pipeline plus Scapy PCAP read',
        },
        'throughput': throughput_summary,
        'throughput_runs': runs,
        'query_latency_overall': query_summary,
        'query_latency_by_query': per_query,
        'dataset': health['tables'],
        'index_count': health['index_count'],
        'targets': {
            'min_packets_per_s': args.min_packets_per_s,
            'throughput_met': pipeline['median'] >= args.min_packets_per_s,
            'query_latency_ms': 50,
            'query_latency_met': query_summary['p95_ms'] < 50,
        },
    }

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump(results, fh, indent=2)
        print('\n  results written to %s' % args.json)

    db.close()
    if not args.keep_db and not args.db and not db_dialects._is_url(db_path):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(db_path + suffix):
                os.remove(db_path + suffix)
    if owns_capture and not args.keep_db and os.path.exists(capture_path):
        os.remove(capture_path)

    both_met = results['targets']['throughput_met'] and \
        results['targets']['query_latency_met']
    return 0 if both_met else 1


if __name__ == '__main__':
    sys.exit(main())
